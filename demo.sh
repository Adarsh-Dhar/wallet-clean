#!/usr/bin/env bash
# =============================================================================
#  demo.sh
#
#  End-to-end demo: clean the wallet and verify it's clean
#
#  USAGE
#    chmod +x demo.sh
#    ./demo.sh [--address ADDR] [--key KEY] [--api URL] [--skip-auth]
#
#  DEFAULTS
#    --address  0xdf91e28e5ce7bddfa06f7f924db73003501d1d65192c489bb84056e1a7d628a5
#    --api      http://localhost:8080
#    --key      (required unless --skip-auth)
#
#  EXAMPLE (with private key)
#    ./demo.sh --key suiprivkey1...
#
#  EXAMPLE (test mode — requires NODE_ENV=test on API server)
#    ./demo.sh --skip-auth
#
# =============================================================================

set -euo pipefail

# ── Parse args ───────────────────────────────────────────────────────────────

ADDRESS="0xdf91e28e5ce7bddfa06f7f924db73003501d1d65192c489bb84056e1a7d628a5"
API="http://localhost:8080"
KEY=""
SKIP_AUTH=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --address)
      ADDRESS="$2"
      shift 2
      ;;
    --key)
      KEY="$2"
      shift 2
      ;;
    --api)
      API="$2"
      shift 2
      ;;
    --skip-auth)
      SKIP_AUTH=true
      shift
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

if [[ -z "$KEY" && "$SKIP_AUTH" != "true" ]]; then
  echo ""
  echo "  ✗  --key is required (or pass --skip-auth for NODE_ENV=test mode)"
  echo ""
  echo "  Get your key:"
  echo "    sui keytool export --key-identity 0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e"
  echo ""
  exit 1
fi

# ── Title ──────────────────────────────────────────────────────────────────────

clear
echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║        DeepClean — Full Demo Workflow                ║"
echo "  ║     Clean Wallet + Verify + Generate Report         ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Address : $ADDRESS"
echo "  API     : $API"
echo ""

# ── Check if Node is available ─────────────────────────────────────────────────

if ! command -v node &>/dev/null; then
  echo "  ✗  Node.js not found"
  exit 1
fi

# ── Check if clean-wallet.mjs and test-clean.mjs exist ──────────────────────────

if [[ ! -f "clean-wallet.mjs" ]]; then
  echo "  ✗  clean-wallet.mjs not found in current directory"
  exit 1
fi

if [[ ! -f "test-clean.mjs" ]]; then
  echo "  ✗  test-clean.mjs not found in current directory"
  exit 1
fi

# ── Stage 1: Clean the wallet ──────────────────────────────────────────────────

echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║  STAGE 1 — Clean Wallet                               ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo ""

CLEAN_ARGS=(
  --address "$ADDRESS"
  --api "$API"
)

if [[ -n "$KEY" ]]; then
  CLEAN_ARGS+=(--key "$KEY")
fi

if [[ "$SKIP_AUTH" == "true" ]]; then
  CLEAN_ARGS+=(--skip-auth)
fi

if ! node clean-wallet.mjs "${CLEAN_ARGS[@]}"; then
  echo ""
  echo "  ✗  Clean failed"
  exit 1
fi

# ── Stage 2: Verify the wallet is clean ────────────────────────────────────────

echo ""
echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║  STAGE 2 — Verify Clean                               ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo ""

if ! node test-clean.mjs \
  --address "$ADDRESS" \
  --api "$API" \
  --network testnet; then
  echo ""
  echo "  ⚠  Verification had failures"
  echo "     (This may be expected if the seeding step wasn't run)"
  exit 1
fi

# ── Done ───────────────────────────────────────────────────────────────────────

echo ""
echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║  ✓  DEMO COMPLETE                                     ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo ""
echo "  The wallet has been:"
echo "    1. Cleaned   — all spam objects burned on-chain"
echo "    2. Verified  — checked on-chain and in database"
echo ""
echo "  Next:"
echo "    • Open DeepClean in browser"
echo "    • Connect wallet: $ADDRESS"
echo "    • Confirm all threats are marked as burned"
echo ""
