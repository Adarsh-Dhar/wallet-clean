#!/usr/bin/env bash
# =============================================================================
#  setup-demo.sh
#
#  One-time setup to prepare for running the demo
#  Installs dependencies and makes scripts executable
#
# =============================================================================

set -euo pipefail

echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║        DeepClean Demo — Setup                        ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""

# Check if we're in the right directory
if [[ ! -f "package.json" ]]; then
  echo "  ✗  package.json not found"
  echo "     Run this script from the project root"
  exit 1
fi

# Make scripts executable
echo "  Setting up scripts..."
chmod +x demo.sh 2>/dev/null || echo "  · demo.sh already set up"
chmod +x inject_junk.sh 2>/dev/null || echo "  · inject_junk.sh already set up"
chmod +x clean-wallet.mjs 2>/dev/null || true
chmod +x test-clean.mjs 2>/dev/null || true

# Install dependencies
echo ""
echo "  Installing dependencies (pnpm)..."
pnpm install

echo ""
echo "  ✓  Setup complete"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Get your private key (for signing wallet 0x8cb08...):"
echo "     sui keytool export --key-identity 0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e"
echo ""
echo "  2. Run the full demo:"
echo "     ./demo.sh --key <YOUR_PRIVATE_KEY>"
echo ""
echo "     OR (if API runs in NODE_ENV=test):"
echo "     ./demo.sh --skip-auth"
echo ""
echo "  3. The demo will:"
echo "     · Clean the wallet on-chain"
echo "     · Verify objects are gone"
echo "     · Check database state"
echo ""
