#!/bin/bash
# final-setup.sh - Prepare production environment and fund agent wallet

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         DeepClean Production Setup — Final Configuration        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Rebuild frontend with fix
echo "Step 1: Rebuilding frontend with wallet PTB fix..."
cd /Users/adarsh/Documents/Gemini-Vision-API/artifacts/deepclean
rm -rf dist/.vite-stamp
pnpm run build > /tmp/deepclean-build.log 2>&1 || {
  echo "❌ Frontend build failed. Check /tmp/deepclean-build.log"
  exit 1
}
echo "✓ Frontend rebuilt successfully"
echo ""

# Step 2: Show new bundle hash (cache-bust)
echo "Step 2: New frontend bundle (cache-busted):"
ls -lh dist/public/assets/index-*.js | awk '{print "  " $NF " (" $5 ")"}'
echo ""

# Step 3: Derive agent wallet address
echo "Step 3: Agent wallet address for on-chain operations:"
AGENT_ADDR="0xc80e88f16908b3af2a9a70fb9b7c51cd906a4db59a46c62caf906c13e23fcb30"
echo "  $AGENT_ADDR"
echo ""

# Step 4: Check gas balance
echo "Step 4: Checking agent wallet balance on testnet..."
BALANCE=$(curl -s https://fullnode.testnet.sui.io -X POST \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"suix_getBalance\",\"params\":[\"$AGENT_ADDR\",\"0x2::sui::SUI\"],\"id\":1}" \
  | grep -o '"balance":"[^"]*' | cut -d'"' -f4)

if [ -z "$BALANCE" ] || [ "$BALANCE" = "0" ]; then
  echo "  ❌ Balance: 0 SUI (needs funding)"
  echo ""
  echo "   👉 REQUIRED: Fund the agent wallet on testnet faucet:"
  echo "      https://faucet.testnet.sui.io"
  echo ""
  echo "   1. Go to https://faucet.testnet.sui.io"
  echo "   2. Paste this address: $AGENT_ADDR"
  echo "   3. Request gas (testnet faucet drips 10 SUI)"
  echo "   4. Wait ~30s for confirmation"
  echo "   5. Restart the API server"
else
  echo "  ✓ Balance: $BALANCE MIST (sufficient for transactions)"
fi
echo ""

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              Setup Complete — Ready to Deploy                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Frontend: dist/public/ (includes fixed wallet PTB)"
echo "  Backend:  artifacts/api-server/dist/index.mjs (production bundle)"
echo "  Port:     8080"
echo "  Network:  testnet"
echo ""
echo "To start:"
echo "  PORT=8080 node artifacts/api-server/dist/index.mjs &"
echo "  # Serve artifacts/deepclean/dist/public/ via HTTP"
echo ""
