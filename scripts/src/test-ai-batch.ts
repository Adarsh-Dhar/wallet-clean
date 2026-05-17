/**
 * Tests that analyzeThreatBatch correctly differentiates malicious from legit objects.
 * Run with: npx ts-node scripts/src/test-ai-batch.ts
 */
import { analyzeThreatBatch } from "../../artifacts/api-server/src/lib/gemini";

const TEST_OBJECTS = [
  // --- Should be MALICIOUS ---
  {
    objectId: "0xdead0001",
    objectType: "0xdead000100::scam_airdrop::FreeToken",
    senderAddress: "0xbadactor",
    displayName: "FREE 5000 SUI — Exclusive Airdrop",
    displayUrl: "https://free-sui-tokens.xyz/airdrop/claim",
  },
  {
    objectId: "0xdead0002",
    objectType: "0xdead000200::phishing_kit::WalletDrainer",
    senderAddress: "0xbadactor",
    displayName: "Official Sui Wallet Connect",
    displayUrl: "https://su\u0456.io/connect", // Cyrillic homoglyph
  },
  {
    objectId: "0xdead0003",
    objectType: "0xdead000300::honeypot_defi::HoneypotToken",
    senderAddress: "0xbadactor",
    displayName: "SuiGold — 10x APY DeFi Protocol",
    displayUrl: "https://suigold-defi.xyz/stake",
    moveAbi: JSON.stringify({ functions: [{ name: "_drain_all", visibility: "private" }] }),
  },
  // --- Should be SAFE ---
  {
    objectId: "0xlegit0001",
    objectType: "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin",
    senderAddress: "0x00aa",
    displayName: null,
    displayUrl: null,
  },
  {
    objectId: "0xlegit0002",
    objectType: "0x5d4b302506645c37ff133b98c4b50a744f7a58be6b040e4e4d90c5f6b74cbce5::coin::USDC",
    senderAddress: "0x00aa",
    displayName: "USD Coin (USDC)",
    displayUrl: "https://www.circle.com/usdc",
  },
  {
    objectId: "0xlegit0003",
    objectType: "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb::pool::Position",
    senderAddress: "0x00aa",
    displayName: "Cetus LP Position",
    displayUrl: "https://cetus.zone",
  },
];

async function runTest() {
  console.log(`\n🧪 Testing analyzeThreatBatch with ${TEST_OBJECTS.length} objects...\n`);

  const results = await analyzeThreatBatch(TEST_OBJECTS);

  let passed = 0;
  let failed = 0;

  const EXPECTED: Record<string, "MALICIOUS" | "SAFE"> = {
    "0xdead0001": "MALICIOUS",
    "0xdead0002": "MALICIOUS",
    "0xdead0003": "MALICIOUS",
    "0xlegit0001": "SAFE",
    "0xlegit0002": "SAFE",
    "0xlegit0003": "SAFE",
  };

  for (const r of results) {
    const expected = EXPECTED[r.objectId];
    const ok = r.verdict === expected;
    const icon = ok ? "✅" : "❌";
    console.log(
      `${icon} ${r.objectId.padEnd(14)} | expected=${expected?.padEnd(9)} got=${r.verdict.padEnd(9)} | score=${String(r.risk_score).padStart(3)}/100 | ${r.reasoning.slice(0, 60)}...`
    );
    if (ok) passed++; else failed++;
  }

  console.log(`\n─────────────────────────────────────────`);
  console.log(`Result: ${passed}/${TEST_OBJECTS.length} passed, ${failed} failed`);
  if (failed === 0) {
    console.log("✅ All verdicts correct — agent is properly differentiating malicious from legit.\n");
    process.exit(0);
  } else {
    console.log("❌ Some verdicts were wrong — check the model prompt or mock logic.\n");
    process.exit(1);
  }
}

runTest().catch((err) => { console.error(err); process.exit(1); });
