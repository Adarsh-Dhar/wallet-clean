/**
 * T2 — AI Engine Test Suite
 *
 * Tests the /threats/analyze endpoint against 10 fixture objects covering:
 * - Known honeypot ABIs           → expect MALICIOUS, score >= 65
 * - Phishing / spoofed URLs       → expect MALICIOUS, score >= 65
 * - Classic spam airdrops         → expect MALICIOUS, score >= 65
 * - Legitimate safe tokens        → expect SAFE, score <= 30
 * - Edge cases (no metadata)      → validate structure only
 *
 * Run with: pnpm --filter @workspace/scripts run test:ai
 * Override: API_BASE=http://localhost:80/api pnpm --filter @workspace/scripts run test:ai
 *
 * Pass criteria (all must hold):
 *   ✅ Response structure valid (all fields, correct types)
 *   ✅ risk_score 0–100, confidence 0.0–1.0, reason_code 1–5
 *   ✅ Verdict consistent with risk_score band
 *   ✅ Each call completes in < 20 000 ms
 *   ✅ Known-bad fixtures score >= 65 (MALICIOUS)
 *   ✅ Known-good fixtures score <= 30 (SAFE)
 */

import "dotenv/config";

const API_BASE = process.env["API_BASE"] ?? "http://localhost:80/api";
// Each fixture may wait in the server-side Gemini queue (≥5 s/slot) then call Gemini (~6 s)
// Allow plenty of headroom: 10 fixtures × 11 s = 110 s, so 120 s per-fixture is safe
const ANALYSIS_TIMEOUT_MS = 120_000;

interface Fixture {
  name: string;
  input: {
    objectId: string;
    objectType: string;
    senderAddress: string;
    displayName?: string | null;
    displayUrl?: string | null;
    moveAbi?: string | null;
  };
  expectedVerdict?: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
  minRiskScore?: number;
  maxRiskScore?: number;
}

const FIXTURES: Fixture[] = [
  // ── Known-bad: Honeypot with hidden drain ──────────────────────────────────
  {
    name: "Honeypot with _drain_all function in ABI",
    input: {
      objectId: "0xdeadbeef000000000000000000000001",
      objectType: "0xhoneypot::vault::SuiRewards",
      senderAddress: "0xbad0000000000000000000000000000001",
      displayName: "Sui Rewards Vault",
      displayUrl: "https://sui-rewards-official.com/claim",
      moveAbi: JSON.stringify({
        functions: [
          { name: "stake", visibility: "public" },
          { name: "_drain_all", visibility: "private", description: "drains entire vault balance" },
          { name: "get_rewards", visibility: "public" },
        ],
        structs: [{ name: "SuiRewards", abilities: ["key"] }],
      }),
    },
    expectedVerdict: "MALICIOUS",
    minRiskScore: 65,
  },
  // ── Known-bad: Phishing — spoofed official URL ────────────────────────────
  {
    name: "Phishing NFT mimicking Sui Foundation",
    input: {
      objectId: "0xdeadbeef000000000000000000000002",
      objectType: "0xfake::sui_foundation::OfficialNFT",
      senderAddress: "0xbad0000000000000000000000000000002",
      displayName: "Sui Foundation Official NFT",
      displayUrl: "https://sui-f0undation.com/exclusive-nft",
    },
    expectedVerdict: "MALICIOUS",
    minRiskScore: 65,
  },
  // ── Known-bad: Spam airdrop ───────────────────────────────────────────────
  {
    name: "Spam free airdrop token",
    input: {
      objectId: "0xdeadbeef000000000000000000000003",
      objectType: "0xspam::airdrop::FreeToken",
      senderAddress: "0xbad0000000000000000000000000000003",
      displayName: "FREE 10000 SUI — Claim Now!",
      displayUrl: "https://free-sui-tokens.xyz/airdrop/claim",
    },
    expectedVerdict: "MALICIOUS",
    minRiskScore: 65,
  },
  // ── Known-bad: Honeypot — mint_free calling coin::transfer from caller ────
  {
    name: "Honeypot — mint_free drains caller balance",
    input: {
      objectId: "0xdeadbeef000000000000000000000004",
      objectType: "0xhoneypot::token::SuiGold",
      senderAddress: "0xbad0000000000000000000000000000004",
      displayName: "SuiGold — Revolutionary DeFi",
      displayUrl: "https://suigold-defi.finance/app",
      moveAbi: JSON.stringify({
        structs: [{ name: "SuiGold", abilities: ["key", "store"] }],
        functions: [
          { name: "mint_free", visibility: "public", params: ["&mut TreasuryCap<SuiGold>", "Coin<SUI>"] },
          { name: "claim", visibility: "public", params: ["address"] },
        ],
      }),
    },
    expectedVerdict: "MALICIOUS",
    minRiskScore: 65,
  },
  // ── Known-bad: Unicode homoglyph URL ─────────────────────────────────────
  {
    name: "Unicode homoglyph phishing URL (Cyrillic і)",
    input: {
      objectId: "0xdeadbeef000000000000000000000005",
      objectType: "0xscam::wallet::SuiConnector",
      senderAddress: "0xbad0000000000000000000000000000005",
      displayName: "Official Sui Wallet Connect",
      // Note: Cyrillic 'і' (U+0456) instead of Latin 'i' in "Suі"
      displayUrl: "https://su\u0456.io/connect",
    },
    expectedVerdict: "MALICIOUS",
    minRiskScore: 65,
  },
  // ── Known-good: USDC Coin ─────────────────────────────────────────────────
  {
    name: "Legitimate USDC coin transfer",
    input: {
      objectId: "0x5d4b302506645c37ff133b98c4b50a744f7a58be6b040e4e4d90c5f6b74cbce5",
      objectType: "0x5d4b302506645c37ff133b98c4b50a744f7a58be6b040e4e4d90c5f6b74cbce5::coin::USDC",
      senderAddress: "0x000000000000000000000000000000000000000000000000000000000000000a",
      displayName: "USD Coin (USDC)",
      displayUrl: "https://www.circle.com/usdc",
    },
    expectedVerdict: "SAFE",
    maxRiskScore: 30,
  },
  // ── Known-good: Native SUI coin ───────────────────────────────────────────
  {
    name: "Native SUI coin — 0x2::coin::Coin<0x2::sui::SUI>",
    input: {
      objectId: "0x0000000000000000000000000000000002",
      objectType: "0x2::coin::Coin",
      senderAddress: "0xlegit0000000000000000000000000001",
      displayName: null,
      displayUrl: null,
    },
    expectedVerdict: "SAFE",
    maxRiskScore: 30,
  },
  // ── Known-good: NFT from known verified collection ────────────────────────
  {
    name: "Verified NFT from known collection",
    input: {
      objectId: "0xgood0000000000000000000000000002",
      objectType: "0x2::display::Display",
      senderAddress: "0xverified_creator_000000000000001",
      displayName: "CryptoPunk #4729",
      displayUrl: "https://cryptopunks.app/punk/4729",
    },
    expectedVerdict: "SAFE",
    maxRiskScore: 35,
  },
  // ── Edge case: No metadata at all ─────────────────────────────────────────
  {
    name: "Unknown object — zero metadata (structure validation only)",
    input: {
      objectId: "0xunknown0000000000000000000000001",
      objectType: "0xunknown::module::Unknown",
      senderAddress: "0xunknown0000000000000000000000001",
      displayName: null,
      displayUrl: null,
      moveAbi: null,
    },
    // No verdict expectation — just validate schema + latency
  },
  // ── Edge case: Suspicious but not conclusive ──────────────────────────────
  {
    name: "Suspicious NFT with airdrop function",
    input: {
      objectId: "0xsuspicious0000000000000000000001",
      objectType: "0xnew_project::nft::SpecialEdition",
      senderAddress: "0xnew_address000000000000000000001",
      displayName: "Special Edition NFT — Limited Drop",
      displayUrl: "https://special-edition-nft.io/mint",
      moveAbi: JSON.stringify({
        functions: [
          { name: "transfer", visibility: "public" },
          { name: "airdrop_free", visibility: "public", params: ["&mut TreasuryCap"] },
        ],
      }),
    },
    // At least some risk
    minRiskScore: 15,
  },
];

// ─── Runner ───────────────────────────────────────────────────────────────────

interface AnalysisResult {
  riskScore: number;
  verdict: string;
  reasonCode: number;
  confidence: number;
  flags: string[];
  reasoning: string;
  latencyMs?: number;
}

interface TestResult {
  name: string;
  passed: boolean;
  riskScore: number;
  verdict: string;
  confidence: number;
  latencyMs: number;
  failures: string[];
}

async function runFixture(fixture: Fixture): Promise<TestResult> {
  const start = Date.now();
  const failures: string[] = [];

  let r: AnalysisResult;
  try {
    const res = await fetch(`${API_BASE}/threats/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fixture.input),
      signal: AbortSignal.timeout(ANALYSIS_TIMEOUT_MS),
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    r = (await res.json()) as AnalysisResult;
  } catch (err) {
    const latencyMs = Date.now() - start;
    return {
      name: fixture.name,
      passed: false,
      riskScore: -1,
      verdict: "ERROR",
      confidence: -1,
      latencyMs,
      failures: [`Request failed: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  const latencyMs = r.latencyMs ?? (Date.now() - start);

  // Schema checks
  if (typeof r.riskScore !== "number") failures.push("riskScore missing or not a number");
  if (!["SAFE", "SUSPICIOUS", "MALICIOUS"].includes(r.verdict)) failures.push(`verdict "${r.verdict}" invalid`);
  if (typeof r.confidence !== "number") failures.push("confidence missing");
  if (!Array.isArray(r.flags)) failures.push("flags not an array");
  if (typeof r.reasoning !== "string" || !r.reasoning) failures.push("reasoning empty");
  if (typeof r.reasonCode !== "number") failures.push("reasonCode missing");

  // Range checks
  if (r.riskScore < 0 || r.riskScore > 100) failures.push(`riskScore ${r.riskScore} out of 0–100`);
  if (r.confidence < 0 || r.confidence > 1) failures.push(`confidence ${r.confidence} out of 0–1`);
  if (r.reasonCode < 1 || r.reasonCode > 5) failures.push(`reasonCode ${r.reasonCode} out of 1–5`);

  // Score/verdict consistency
  if (r.riskScore <= 30 && r.verdict === "MALICIOUS") failures.push(`MALICIOUS but score=${r.riskScore} (≤30)`);
  if (r.riskScore >= 65 && r.verdict === "SAFE") failures.push(`SAFE but score=${r.riskScore} (≥65)`);

  // Latency SLA: < 20 000 ms
  if (latencyMs > 20_000) failures.push(`Latency ${latencyMs}ms exceeds 20s SLA`);

  // Fixture-specific
  if (fixture.expectedVerdict && r.verdict !== fixture.expectedVerdict) {
    failures.push(`Expected ${fixture.expectedVerdict}, got ${r.verdict} (score=${r.riskScore})`);
  }
  if (fixture.minRiskScore !== undefined && r.riskScore < fixture.minRiskScore) {
    failures.push(`score ${r.riskScore} below min ${fixture.minRiskScore}`);
  }
  if (fixture.maxRiskScore !== undefined && r.riskScore > fixture.maxRiskScore) {
    failures.push(`score ${r.riskScore} above max ${fixture.maxRiskScore}`);
  }

  return {
    name: fixture.name,
    passed: failures.length === 0,
    riskScore: r.riskScore,
    verdict: r.verdict,
    confidence: r.confidence,
    latencyMs,
    failures,
  };
}

async function main() {
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log("║  T2 — DeepClean AI Engine Test Suite         ║");
  console.log("╚══════════════════════════════════════════════╝\n");
  console.log(`  API: ${API_BASE}\n`);
  console.log(`Running ${FIXTURES.length} fixture tests sequentially...\n`);

  const results: TestResult[] = [];

  for (let i = 0; i < FIXTURES.length; i++) {
    const fixture = FIXTURES[i]!;
    process.stdout.write(`  ▶ ${fixture.name}\n      `);
    const r = await runFixture(fixture);
    results.push(r);

    if (r.passed) {
      console.log(`✅  verdict=${r.verdict} score=${r.riskScore} conf=${(r.confidence * 100).toFixed(0)}% latency=${r.latencyMs}ms`);
    } else {
      console.log(`❌  verdict=${r.verdict} score=${r.riskScore} latency=${r.latencyMs}ms`);
      for (const f of r.failures) console.log(`      ↳ ${f}`);
    }
    console.log();
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;
  const latencies = results.map((r) => r.latencyMs).filter((ms) => ms > 0);
  const avgLatency = latencies.length ? Math.round(latencies.reduce((a, b) => a + b) / latencies.length) : 0;
  const maxLatency = latencies.length ? Math.max(...latencies) : 0;

  console.log("─────────────────────────────────────────────────────");
  console.log(`  Passed:      ${passed} / ${results.length}`);
  console.log(`  Avg latency: ${avgLatency}ms`);
  console.log(`  Max latency: ${maxLatency}ms  ${maxLatency > 20_000 ? "⚠️  SLA BREACH" : "✅"}`);
  console.log("─────────────────────────────────────────────────────\n");

  if (failed > 0) {
    console.error(`❌  ${failed} test(s) failed\n`);
    process.exit(1);
  }
  console.log("✅  All AI engine tests passed\n");
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});

export {};
