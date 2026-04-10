#!/usr/bin/env bash
set -euo pipefail

# === Configuration ===
PARAM="${1:-128s}"  # "128s" or "128f", default: 128s
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/.env"
CLI="$SCRIPT_DIR/cli/target/release/fips205-cli"
KEY_DIR="$SCRIPT_DIR/keys/$PARAM"

# Validate parameter set
if [ "$PARAM" != "128s" ] && [ "$PARAM" != "128f" ]; then
    echo "Usage: $0 [128s|128f]"
    echo "  Default: 128s"
    exit 1
fi

# Switch to the funding address
echo "Switching to funding address..."
iota client switch --address "$FUNDING_ADDRESS"

# Build CLI if not already built
if [ ! -f "$CLI" ]; then
    echo "Building fips205-cli..."
    (cd "$SCRIPT_DIR/cli" && cargo build --release)
fi

# Generate keypair
echo "Generating SLH-DSA-SHA2-${PARAM} keypair..."
mkdir -p "$KEY_DIR"
KEYGEN_OUTPUT=$("$CLI" keygen --param "$PARAM" --output "$KEY_DIR")
echo "$KEYGEN_OUTPUT"

# Extract public key hex from CLI output
PK_HEX=$(echo "$KEYGEN_OUTPUT" | grep "Public key (hex):" | sed 's/.*Public key (hex): //')

if [ -z "${PK_HEX:-}" ]; then
    echo "ERROR: Failed to extract public key hex from keygen output"
    exit 1
fi

echo ""
echo "Creating FIPS 205 abstract account on IOTA..."
echo "  Package:  $PACKAGE_ID"
echo "  Metadata: $METADATA_ID"
echo "  Param:    $PARAM"
echo ""

CREATE_OUTPUT=$(iota client call \
    --package "$PACKAGE_ID" \
    --module fips205_authenticator \
    --function "create_slh_dsa_sha2_${PARAM}" \
    --args "0x$PK_HEX" "$METADATA_ID" \
    --gas-budget 50000000 \
    --json)
echo "$CREATE_OUTPUT" | jq .

# Extract the created account address (the Fips205Account object)
ACCOUNT_ADDRESS=$(echo "$CREATE_OUTPUT" | jq -r '[.objectChanges[] | select(.objectType | test("fips205_authenticator::Fips205Account")) | select(.owner.Shared)] | first | .objectId')

if [ -z "$ACCOUNT_ADDRESS" ] || [ "$ACCOUNT_ADDRESS" = "null" ]; then
    echo "ERROR: Failed to extract account address from create output"
    exit 1
fi

echo ""
echo "Abstract account created: $ACCOUNT_ADDRESS"

# Save the account address alongside the keys
echo "$ACCOUNT_ADDRESS" > "$KEY_DIR/address"
echo "Saved account address to $KEY_DIR/address"

# Switch to the new account and request faucet funds
echo ""
echo "Registering and switching to abstract account..."
iota client add-account "$ACCOUNT_ADDRESS" 2>/dev/null || true
iota client switch --address "$ACCOUNT_ADDRESS"

echo "Requesting faucet funds..."
iota client faucet

echo ""
echo "Done! Account $ACCOUNT_ADDRESS is ready."
