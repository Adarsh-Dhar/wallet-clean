#!/usr/bin/env bash
# =============================================================================
#  inject-junk.sh
#  Injects real on-chain spam objects into your demo wallet using the
#  already-deployed DeepClean spam contracts on Sui testnet.
#
#  USAGE
#    chmod +x inject-junk.sh
#    ./inject-junk.sh <TARGET_WALLET_ADDRESS>
#
#  REQUIREMENTS
#    - sui CLI installed and on PATH  (https://docs.sui.io/guides/developer/getting-started/sui-install)
#    - sui CLI configured for testnet (sui client switch --env testnet)
#    - The active address in `sui client active-address` must own the AdminCap
#      for the spam package OR you call the public mint functions (no cap needed)
#    - Testnet SUI for gas  → https://faucet.testnet.sui.io
#
#  WHAT IT DOES
#    Mints one of each spam object type directly into TARGET_WALLET_ADDRESS:
#      1. malicious_airdrop::AirdropToken   — fake "5000 SUI Airdrop" NFT
#      2. fake_foundation_nft::FounderPass  — fake "Sui Foundation VIP" pass
#      3. honeypot_defi::HoneypotToken      — fake "10x APY" DeFi token
#      4. rug_token::MemeCoin               — fake "100x Meme Coin" via airdrop_to
  #      5. pool::Position                    — fake "Cetus LP Position"
#
#  All 5 land in the target wallet as real objects with real object IDs.
#  The app's Scan will then detect and classify each one.
# =============================================================================

set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────────

PACKAGE_ID="0xe933d9d3e69b29d0183ffbcecaacf7ec8dbc3832f99815760f0d34913c2c1ca4"
NETWORK="testnet"

# ── Argument ─────────────────────────────────────────────────────────────────

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
  echo ""
  echo "  Usage: $0 <TARGET_WALLET_ADDRESS>"
  echo ""
  echo "  Example:"
  echo "    $0 0xabc123..."
  echo ""
  exit 1
fi

# Basic sanity check — Sui addresses are 0x + 64 hex chars
if ! echo "$TARGET" | grep -qE '^0x[0-9a-fA-F]{64}$'; then
  echo "  ✗ Address looks wrong: $TARGET"
  echo "    Expected format: 0x followed by 64 hex characters"
  exit 1
fi

# ── Pre-flight ────────────────────────────────────────────────────────────────

echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║           DeepClean — Junk Injector                  ║"
echo "  ║           Sui Testnet Spam Seeder                    ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Package : $PACKAGE_ID"
echo "  Network : $NETWORK"
echo "  Target  : $TARGET"
echo ""

# Check sui CLI
if ! command -v sui &>/dev/null; then
  echo "  ✗ sui CLI not found. Install from:"
  echo "    https://docs.sui.io/guides/developer/getting-started/sui-install"
  exit 1
fi

# Check active env
ACTIVE_ENV=$(sui client active-env 2>/dev/null || echo "unknown")
if [[ "$ACTIVE_ENV" != "$NETWORK" ]]; then
  echo "  ⚠  Active sui env is '$ACTIVE_ENV', expected '$NETWORK'"
  echo "     Switching to testnet..."
  sui client switch --env "$NETWORK"
fi

ACTIVE_ADDR=$(sui client active-address 2>/dev/null || echo "")
if [[ -z "$ACTIVE_ADDR" ]]; then
  echo "  ✗ No active address. Run: sui client new-address ed25519"
  exit 1
fi

echo "  Signing with : $ACTIVE_ADDR"
echo ""

# ── Helper ───────────────────────────────────────────────────────────────────

run_call() {
  local label="$1"
  local module="$2"
  local func="$3"
  shift 3
  local extra_args=("$@")

  echo -n "  [1/1] Minting $label ... "

  local output
  if output=$(sui client call \
    --package "$PACKAGE_ID" \
    --module  "$module" \
    --function "$func" \
    ${extra_args[@]+"${extra_args[@]}"} \
    --gas-budget 10000000 \
    --json 2>&1); then

    # Extract digest from JSON output
    local digest
    digest=$(echo "$output" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('digest') or d.get('effects',{}).get('transactionDigest','?'))
except:
    print('?')
" 2>/dev/null || echo "?")

    echo "✓  digest: $digest"
    echo "     https://suiscan.xyz/testnet/tx/$digest"
  else
    echo "✗  FAILED"
    echo ""
    echo "     $output" | head -20
    echo ""
    # Don't abort — try the rest
  fi
  echo ""
}

# ── Inject each spam type ────────────────────────────────────────────────────

echo "  Injecting 5 spam objects into $TARGET"
echo "  ─────────────────────────────────────────────────────"
echo ""

# 1. malicious_airdrop — mint() transfers to ctx.sender(), so we call from target
#    BUT we can't sign as the target. Instead we use `airdrop_to` pattern if available,
#    or call mint() and then transfer. Since mint() sends to ctx.sender (the signer),
#    we need a different approach for 3 of these modules.
#
#    Strategy:
#    - rug_token has `airdrop_to(recipient, ctx)` — direct send to target ✓
#    - The others have `mint(ctx)` which sends to ctx.sender (= our signing wallet)
#      so we mint to ourselves then immediately transfer to target.

echo "  ── Object 1: malicious_airdrop::AirdropToken ──────────"
run_call "AirdropToken" "malicious_airdrop" "mint"
# This mints to active address; we'll transfer after all mints

echo "  ── Object 2: fake_foundation_nft::FounderPass ─────────"
run_call "FounderPass" "fake_foundation_nft" "mint"

echo "  ── Object 3: honeypot_defi::HoneypotToken ─────────────"
run_call "HoneypotToken" "honeypot_defi" "stake_and_receive"

echo "  ── Object 4: rug_token::MemeCoin (direct airdrop) ─────"
# airdrop_to takes recipient address as arg — lands directly in TARGET
run_call "MemeCoin" "rug_token" "airdrop_to" \
  --args "$TARGET"

echo "  ── Object 5: pool::Position ───────────────────"
run_call "Position" "pool" "mint"

# ── Transfer minted objects to target ────────────────────────────────────────

echo ""
echo "  ─────────────────────────────────────────────────────"
echo "  Transferring minted objects to target wallet..."
echo ""

# Get all objects minted to the signing address that match our package
OWNED_JSON=$(sui client objects --json 2>/dev/null || echo "[]")

OBJECT_IDS=$(echo "$OWNED_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
pkg = '$PACKAGE_ID'
ids = []
for item in data:
    try:
        obj_type = (
            item.get('type','') or
            item.get('data',{}).get('type','') or
            ''
        )
        obj_id = (
            item.get('objectId','') or
            item.get('data',{}).get('objectId','')
        )
        if pkg in obj_type and obj_id:
            ids.append(obj_id)
    except:
        pass
print('\n'.join(ids))
" 2>/dev/null || echo "")

if [[ -z "$OBJECT_IDS" ]]; then
  echo "  ⚠  Could not auto-detect minted object IDs."
  echo "     Run manually:"
  echo "     sui client objects --json | grep -i '$PACKAGE_ID'"
  echo ""
  echo "     Then transfer each one:"
  echo "     sui client transfer --object-id <ID> --to $TARGET --gas-budget 5000000"
  echo ""
else
  while IFS= read -r OBJ_ID; do
    [[ -z "$OBJ_ID" ]] && continue
    echo -n "  Transferring $OBJ_ID → $TARGET ... "
    if sui client transfer \
        --object-id "$OBJ_ID" \
        --to "$TARGET" \
        --gas-budget 5000000 \
        --json &>/dev/null; then
      echo "✓"
    else
      echo "✗ (may already be in target wallet or already transferred)"
    fi
  done <<< "$OBJECT_IDS"
fi

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "  ═════════════════════════════════════════════════════"
echo "  ✓  Injection complete"
echo ""
echo "  Next steps:"
echo "    1. Open DeepClean in your browser"
echo "    2. Connect $TARGET"
echo "    3. Click  'Seed spam'  (or hit the Populate API)"
echo "    4. Watch threats appear — all 5 objects should be"
echo "       classified MALICIOUS with high risk scores"
echo "    5. Click  'Clean'  — approve the wallet popup"
echo "    6. Objects are gone. 'Wallet Clean' screen appears."
echo ""
echo "  Verify on-chain:"
echo "  https://suiscan.xyz/testnet/account/$TARGET"
echo "  ═════════════════════════════════════════════════════"
echo ""