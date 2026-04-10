#!/usr/bin/env bash
set -euo pipefail

# === Configuration ===
FUNDING_ADDRESS="0x4993f3eee84c4fc748b54c217de9ac0b28d65e7802c2f4b2bcc33570fbf798ba"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

# === Switch to funding address ===
echo "Switching to funding address..."
iota client switch --address "$FUNDING_ADDRESS"

# === Build ===
echo ""
echo "Building Move package..."
iota move build

# === Publish ===
echo ""
echo "Publishing package..."
PUBLISH_OUTPUT=$(iota client publish --json --gas-budget 5000000000)

# === Extract IDs from publish output ===
PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | jq -r '.objectChanges[] | select(.type == "published") | .packageId')
METADATA_ID=$(echo "$PUBLISH_OUTPUT" | jq -r '.objectChanges[] | select(.type == "created" and .objectType == "0x2::package_metadata::PackageMetadataV1") | .objectId')

if [ -z "$PACKAGE_ID" ] || [ "$PACKAGE_ID" = "null" ]; then
    echo "ERROR: Failed to extract package ID from publish output"
    echo "$PUBLISH_OUTPUT" | jq .
    exit 1
fi

if [ -z "$METADATA_ID" ] || [ "$METADATA_ID" = "null" ]; then
    echo "ERROR: Failed to extract metadata ID from publish output"
    echo "$PUBLISH_OUTPUT" | jq .
    exit 1
fi

# === Write .env file ===
cat > "$ENV_FILE" <<EOF
FUNDING_ADDRESS="$FUNDING_ADDRESS"
PACKAGE_ID="$PACKAGE_ID"
METADATA_ID="$METADATA_ID"
EOF

echo ""
echo "Deployed successfully!"
echo "  Package ID:  $PACKAGE_ID"
echo "  Metadata ID: $METADATA_ID"
echo "  Written to:  $ENV_FILE"
