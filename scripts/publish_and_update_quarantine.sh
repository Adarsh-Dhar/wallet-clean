#!/usr/bin/env bash
set -euo pipefail

# Builds and publishes the Move package in /move, extracts the new package id,
# updates .env QUARANTINE_PACKAGE_ID and SPAM_PACKAGE_ID (if present), and
# prints the new id. Does NOT restart the server by default.

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR/move"

echo "Building Move package..."
sui move build

echo "Publishing Move package (this will use your active Sui wallet)..."
OUT=$(sui client publish --gas-budget 1000000 2>&1) || { echo "Publish failed:"; echo "$OUT"; exit 1; }

echo "$OUT"

# Try to extract the first 0x hex token that looks like a package id
PACKAGE_ID=$(printf "%s" "$OUT" | grep -Eo "0x[a-f0-9]+" | head -n1 || true)

if [ -z "$PACKAGE_ID" ]; then
  echo "Could not parse package id from publish output. Please paste the package id manually and press Enter:";
  read -r PACKAGE_ID
fi

echo "Detected package id: $PACKAGE_ID"

ENV_FILE="$ROOT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo ".env file not found at $ENV_FILE. Aborting update." >&2
  exit 1
fi

# Update QUARANTINE_PACKAGE_ID and SPAM_PACKAGE_ID if present
perl -0777 -pe "s/^QUARANTINE_PACKAGE_ID=.*$/QUARANTINE_PACKAGE_ID=$PACKAGE_ID/m" -i "$ENV_FILE"
perl -0777 -pe "s/^SPAM_PACKAGE_ID=.*$/SPAM_PACKAGE_ID=$PACKAGE_ID/m" -i "$ENV_FILE" || true

# If SPAM_PACKAGE_ID wasn't present, append it
if ! grep -q "^SPAM_PACKAGE_ID=" "$ENV_FILE"; then
  echo "SPAM_PACKAGE_ID=$PACKAGE_ID" >> "$ENV_FILE"
fi

echo ".env updated with PACKAGE_ID=$PACKAGE_ID"

echo "Done. To apply the change restart the server with: ./run.sh"

echo "If you want this script to restart the server automatically, re-run with: ./scripts/publish_and_update_quarantine.sh --restart"
