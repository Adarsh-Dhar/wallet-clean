#!/bin/bash
# deploy-move.sh
# Run this once to deploy the quarantine_vault contract and extract the IDs you need.
# Prerequisites: `sui` CLI installed and funded on devnet.
#
# Usage:
#   bash deploy-move.sh
#
# After it finishes, copy the three export lines into your Replit Secrets.

set -e

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  DeepClean — Move Contract Deployment      ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# ── Step 1: Switch to devnet ──────────────────────────────────────────────────
echo "→ Switching to devnet…"
sui client switch --env devnet

# ── Step 2: Check active address ─────────────────────────────────────────────
DEPLOYER=$(sui client active-address)
echo "  Deployer address: $DEPLOYER"

# ── Step 3: Request faucet funds if balance is low ───────────────────────────
echo "→ Requesting devnet faucet funds…"
sui client faucet || echo "  (Faucet may have already funded you — continuing)"

sleep 3

# ── Step 4: Build and publish ─────────────────────────────────────────────────
echo "→ Publishing move/ package to devnet…"
# Try normal publish; if it fails because Move.toml has no 'devnet' environment,
# fall back to `sui client test-publish` which allows temporary publishes to devnet.
PUBLISH_OUTPUT=""
if PUBLISH_OUTPUT=$(sui client publish move/ --gas-budget 100000000 --json 2>&1); then
  echo "(publish succeeded)"
else
  echo "(publish failed — attempting test-publish for devnet)..."
  if PUBLISH_OUTPUT=$(sui client test-publish move/ --gas-budget 100000000 --json 2>&1); then
    echo "(test-publish succeeded)"
  else
    echo "(both publish and test-publish failed)"
    echo "$PUBLISH_OUTPUT" > /tmp/deepclean_publish_output.json
    echo "See /tmp/deepclean_publish_output.json for details. Exiting." >&2
    exit 1
  fi
fi

echo "$PUBLISH_OUTPUT" > /tmp/deepclean_publish_output.json

# ── Step 5: Extract Package ID ───────────────────────────────────────────────
PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for change in data.get('objectChanges', []):
    if change.get('type') == 'published':
        print(change['packageId'])
        break
" 2>/dev/null || echo "")

if [ -z "$PACKAGE_ID" ]; then
  echo ""
  echo "⚠️  Could not auto-extract package ID."
  echo "   Open /tmp/deepclean_publish_output.json and find the 'packageId' field manually."
  echo "   Look for an objectChange with type='published'."
  exit 1
fi

echo "  Package ID: $PACKAGE_ID"

# ── Step 6: Extract AdminCap object ID ───────────────────────────────────────
ADMIN_CAP_ID=$(echo "$PUBLISH_OUTPUT" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for change in data.get('objectChanges', []):
    obj_type = change.get('objectType', '')
    if 'quarantine_vault::AdminCap' in obj_type:
        print(change['objectId'])
        break
" 2>/dev/null || echo "")

if [ -z "$ADMIN_CAP_ID" ]; then
  echo ""
  echo "⚠️  Could not auto-extract AdminCap ID."
  echo "   In /tmp/deepclean_publish_output.json, find objectChanges where"
  echo "   objectType contains 'quarantine_vault::AdminCap' and copy its objectId."
  exit 1
fi

echo "  AdminCap ID: $ADMIN_CAP_ID"

# ── Step 7: Export the agent private key ─────────────────────────────────────
echo "→ Exporting active keypair (this is your AGENT_PRIVATE_KEY)…"
AGENT_PRIVATE_KEY=$(sui keytool export \
  --key-identity "$DEPLOYER" \
  --json 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('exportedPrivkey',''))" \
  2>/dev/null || echo "")

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  Copy these 3 values into Replit Secrets   ║"
echo "╚════════════════════════════════════════════╝"
echo ""
echo "  QUARANTINE_PACKAGE_ID   = $PACKAGE_ID"
echo "  QUARANTINE_ADMIN_CAP_ID = $ADMIN_CAP_ID"
echo "  AGENT_PRIVATE_KEY       = ${AGENT_PRIVATE_KEY:-<run: sui keytool export --key-identity $DEPLOYER>}"
echo "  SUI_NETWORK             = devnet"
echo ""
echo "✅  Done. After setting secrets, restart the API server."
echo "   On-chain quarantine will activate automatically."
echo ""
echo "   Verify on Suiscan:"
echo "   https://suiscan.xyz/devnet/object/$PACKAGE_ID"