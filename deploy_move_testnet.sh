#!/bin/bash
# deploy-move-testnet.sh
# Deploy quarantine_vault contract to testnet and extract AdminCap ID

set -e

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║  DeepClean — Move Contract Deployment      ║"
echo "║  Target: TESTNET                           ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# ── Step 1: Switch to testnet ─────────────────────────────────────────────────
echo "→ Switching to testnet…"
sui client switch --env testnet

# ── Step 2: Check active address ──────────────────────────────────────────────
DEPLOYER=$(sui client active-address)
echo "  Deployer address: $DEPLOYER"

# ── Step 3: Get current object balance for debugging ─────────────────────────
echo "→ Checking wallet balance…"
BALANCE=$(sui client gas 2>/dev/null | grep -oP '(?<=value: )\d+' | head -1 || echo "unknown")
echo "  Current balance: $BALANCE MIST"

# ── Step 4: Publish to testnet ────────────────────────────────────────────────
echo "→ Publishing move/ package to testnet…"
PUBLISH_OUTPUT=$(sui client publish move/ --gas-budget 300000000 --json)

echo "$PUBLISH_OUTPUT" > /tmp/deepclean_publish_testnet.json

# ── Step 5: Extract Package ID ────────────────────────────────────────────────
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
  echo "   Full output saved to /tmp/deepclean_publish_testnet.json"
  cat /tmp/deepclean_publish_testnet.json
  exit 1
fi

echo "  Package ID: $PACKAGE_ID"

# ── Step 6: Extract AdminCap object ID ────────────────────────────────────────
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
  echo "   Full output saved to /tmp/deepclean_publish_testnet.json"
  cat /tmp/deepclean_publish_testnet.json
  exit 1
fi

echo "  AdminCap ID: $ADMIN_CAP_ID"

# ── Step 7: Extract Upgrade Capability ────────────────────────────────────────
UPGRADE_CAP=$(echo "$PUBLISH_OUTPUT" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for change in data.get('objectChanges', []):
    obj_type = change.get('objectType', '')
    if 'UpgradeCap' in obj_type:
        print(change['objectId'])
        break
" 2>/dev/null || echo "")

echo "  Upgrade Cap: $UPGRADE_CAP"

# ── Step 8: Export the agent private key ──────────────────────────────────────
echo "→ Exporting active keypair…"
AGENT_PRIVATE_KEY=$(sui keytool export \
  --key-identity "$DEPLOYER" \
  --json 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('exportedPrivkey',''))" \
  2>/dev/null || echo "")

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║           Update your .env file with these values              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "QUARANTINE_PACKAGE_ID=$PACKAGE_ID"
echo "QUARANTINE_ADMIN_CAP_ID=$ADMIN_CAP_ID"
echo "AGENT_PRIVATE_KEY=$AGENT_PRIVATE_KEY"
echo "SUI_NETWORK=testnet"
echo "REAL_ONCHAIN=true"
echo ""
echo "✅  Done. Update your .env and restart the API server."
echo ""
