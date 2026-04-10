#!/usr/bin/env bash
set -euo pipefail

# Transfer IOTA using an SLH-DSA-SHA2-128f abstract account.
# The 17,088-byte signature is split at the FORS/HT boundary into two args
# (3,712 + 13,376 bytes) to stay within the 16K auth-call-arg size limit.

# === Configuration ===
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_DIR="$SCRIPT_DIR/keys/128f"
GAS_BUDGET="3000000000"
CLI="$SCRIPT_DIR/cli/target/release/fips205-cli"
SECRET_KEY="$KEY_DIR/secret_key.bin"
PUBLIC_KEY="$KEY_DIR/public_key.bin"
ADDRESS_FILE="$KEY_DIR/address"

if [ ! -f "$ADDRESS_FILE" ]; then
    echo "ERROR: No 128f account found. Run ./create_account.sh 128f first."
    exit 1
fi
ABSTRACT_ACCOUNT=$(cat "$ADDRESS_FILE")

# === Parse arguments ===
if [ $# -lt 2 ]; then
    echo "Usage: $0 <recipient_address> <amount>"
    echo "  recipient_address: 0x... IOTA address"
    echo "  amount: amount of IOTA (in NANOS) to transfer"
    exit 1
fi

RECIPIENT="$1"
AMOUNT="$2"

# === Validate prerequisites ===
if [ ! -f "$CLI" ]; then
    echo "ERROR: fips205-cli not found. Run: cd cli && cargo build --release"
    exit 1
fi

# === Register and switch to the abstract account ===
echo "Adding abstract account to IOTA client..."
iota client add-account "$ABSTRACT_ACCOUNT" 2>/dev/null || true

echo "Switching to abstract account..."
iota client switch --address "$ABSTRACT_ACCOUNT"

# === Build unsigned transaction ===
echo ""
echo "Creating unsigned transaction..."
UNSIGNED_TX_BYTES=$(iota client pay-iota \
    --recipients "$RECIPIENT" \
    --amounts "$AMOUNT" \
    --gas-budget "$GAS_BUDGET" \
    --serialize-unsigned-transaction)
echo "Unsigned TX: ${UNSIGNED_TX_BYTES:0:64}..."

# === Extract TX digest ===
TX_DIGEST_HEX=$(iota keytool tx-digest "$UNSIGNED_TX_BYTES" --json | jq -r '.digestHex')
echo "TX Digest Hex: $TX_DIGEST_HEX"

# === Sign the TX digest ===
# CLI outputs two lines for 128f: sig_r_fors (line 1) and sig_ht (line 2)
echo ""
echo "Signing with SLH-DSA-SHA2-128f..."
SIGN_OUTPUT=$("$CLI" sign \
    --digest "$TX_DIGEST_HEX" \
    --secret-key "$SECRET_KEY" \
    --address "$ABSTRACT_ACCOUNT" \
    --param 128f)
SIG_R_FORS_HEX=$(echo "$SIGN_OUTPUT" | sed -n '1p')
SIG_HT_HEX=$(echo "$SIGN_OUTPUT" | sed -n '2p')
echo "sig_r_fors: $((${#SIG_R_FORS_HEX} / 2)) bytes, sig_ht: $((${#SIG_HT_HEX} / 2)) bytes"

# === Verify locally (sanity check) ===
echo ""
echo "Verifying signature locally..."
"$CLI" verify \
    --digest "$TX_DIGEST_HEX" \
    --signature "${SIG_R_FORS_HEX}${SIG_HT_HEX}" \
    --public-key "$PUBLIC_KEY" \
    --address "$ABSTRACT_ACCOUNT" \
    --param 128f

# === Attach auth args to the existing unsigned TX and execute ===
echo ""
echo "Executing transaction..."
iota client serialized-tx "$UNSIGNED_TX_BYTES" \
    --auth-call-args "0x$SIG_R_FORS_HEX" "0x$SIG_HT_HEX"
