#!/usr/bin/env tsx

type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";

interface AnalyzeInput {
  objectId: string;
  objectType: string;
  senderAddress: string;
  displayName?: string | null;
  displayUrl?: string | null;
  moveAbi?: string | null;
}

interface AnalyzeResponse {
  riskScore: number;
  verdict: Verdict;
  reasonCode: number;
  confidence: number;
  flags: string[];
  reasoning: string;
  latencyMs?: number;
}

interface Fixture {
  label: string;
  input: AnalyzeInput;
  expectedVerdicts: Verdict[];
  minRiskScore?: number;
  maxRiskScore?: number;
}

const args = process.argv.slice(2);

function getArg(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : undefined;
}

function hasFlag(flag: string): boolean {
  return args.includes(flag);
}

const TARGET_ADDRESS = getArg("--address");
const API_BASE = getArg("--api") ?? "http://localhost:80/api";
const SPAM_ONLY = hasFlag("--spam-only");
const LEGIT_ONLY = hasFlag("--legit-only");

const TIMEOUT_MS = 60_000;

const C = {
  reset: "\x1b[0m",
  cyan: "\x1b[96m",
  green: "\x1b[92m",
  red: "\x1b[91m",
  yellow: "\x1b[93m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
};

function colorVerdict(v: Verdict): string {
  if (v === "SAFE") return `${C.green}${v}${C.reset}`;
  if (v === "SUSPICIOUS") return `${C.yellow}${v}${C.reset}`;
  return `${C.red}${v}${C.reset}`;
}

function usage(): void {
  console.log("Usage:");
  console.log("  pnpm --filter @workspace/scripts run populate --address 0x<your_wallet>");
  console.log("  pnpm --filter @workspace/scripts run populate --address 0x<your_wallet> --spam-only");
  console.log("  pnpm --filter @workspace/scripts run populate --address 0x<your_wallet> --legit-only");
  console.log("Optional:");
  console.log("  --api http://localhost:8000/api");
}

function normalizeAddress(a: string): string {
  return a.startsWith("0x") ? a.toLowerCase() : `0x${a.toLowerCase()}`;
}

const TARGET = TARGET_ADDRESS ? normalizeAddress(TARGET_ADDRESS) : "0x0";

const SPAM_FIXTURES: Fixture[] = [
  {
    label: "Fake SUI airdrop",
    input: {
      objectId: "0xspam0001",
      objectType: "0xdead0001::scam_airdrop::FreeToken",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000001",
      displayName: "FREE 5000 SUI - Exclusive Airdrop",
      displayUrl: "https://free-sui-tokens.xyz/airdrop/claim",
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "Cyrillic homoglyph phishing URL",
    input: {
      objectId: "0xspam0002",
      objectType: "0xdead0002::phishing_kit::WalletDrainer",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000002",
      displayName: "Official Sui Wallet Connect",
      displayUrl: "https://su\u0456.io/connect",
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "Honeypot DeFi with _drain_all ABI",
    input: {
      objectId: "0xspam0003",
      objectType: "0xdead0003::honeypot_defi::HoneypotToken",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000003",
      displayName: "SuiGold - 10x APY DeFi Protocol",
      displayUrl: "https://suigold-defi.xyz/stake",
      moveAbi: JSON.stringify({
        functions: [
          { name: "_drain_all", visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] },
          { name: "stake_free", visibility: "public", params: ["address"] },
        ],
      }),
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "Digit substitution domain",
    input: {
      objectId: "0xspam0004",
      objectType: "0xdead0004::fake_foundation::FounderPass",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000004",
      displayName: "Sui Foundation VIP Founder Pass",
      displayUrl: "https://sui-f0undation.com/exclusive-nft",
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "NFT phishing mint URL",
    input: {
      objectId: "0xspam0005",
      objectType: "0xdead0005::nft_phish::MintPass",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000005",
      displayName: "Sui Foundation Official NFT",
      displayUrl: "https://suifoundation-nft.io/mint",
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "Fake Cetus impersonation",
    input: {
      objectId: "0xspam0006",
      objectType: "0xdead0006::fake_cetus::LPReceipt",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000006",
      displayName: "Cetus Protocol - Claim LP Rewards",
      displayUrl: "https://cetus-protocol.xyz/claim-rewards",
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "Approval phish with sweep_all ABI",
    input: {
      objectId: "0xspam0007",
      objectType: "0xdead0007::approval_phish::ApprovalRequest",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000007",
      displayName: "Sui Wallet Verification Required",
      displayUrl: "https://verify-su\u0456wallet.com/approve",
      moveAbi: JSON.stringify({
        functions: [
          { name: "request_approval", visibility: "public", params: ["address", "u64"] },
          { name: "sweep_all", visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] },
        ],
      }),
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "Dust attack bulk sender",
    input: {
      objectId: "0xspam0008",
      objectType: "0xdead0008::dust_attack::TrackingDust",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000008",
      displayName: "0.000001 SUI Transfer",
      displayUrl: "",
    },
    expectedVerdicts: ["SUSPICIOUS", "MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "Rug token hidden freeze/migrate",
    input: {
      objectId: "0xspam0009",
      objectType: "0xdead0009::rug_token::MemeCoin",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000009",
      displayName: "SuiDoge - 100x Meme Coin",
      displayUrl: "https://suidoge-token.xyz/stake",
      moveAbi: JSON.stringify({
        functions: [
          { name: "buy", visibility: "public", params: ["address", "u64"] },
          { name: "sell", visibility: "public", params: ["address", "u64"] },
          { name: "freeze_all", visibility: "private", params: [] },
          { name: "migrate_funds", visibility: "private", params: ["address"] },
        ],
      }),
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
  {
    label: "Fake governance urgency + digit-sub domain",
    input: {
      objectId: "0xspam0010",
      objectType: "0xdead0010::fake_governance::VoteProposal",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000010",
      displayName: "Sui DAO - Urgent Governance Vote (Expires Soon)",
      displayUrl: "https://sui-gov0rnance.io/vote",
    },
    expectedVerdicts: ["MALICIOUS"],
    minRiskScore: 65,
  },
];

const LEGIT_FIXTURES: Fixture[] = [
  {
    label: "Native SUI coin",
    input: {
      objectId: "0xlegit0001",
      objectType: "0x2::coin::Coin<0x2::sui::SUI>",
      senderAddress: TARGET,
      displayName: "SUI",
      displayUrl: null,
    },
    expectedVerdicts: ["SAFE"],
    maxRiskScore: 30,
  },
  {
    label: "USDC from Circle",
    input: {
      objectId: "0xlegit0002",
      objectType: "0x5d4b302506645c37ff133b98c4b50a744f7a58be6b040e4e4d90c5f6b74cbce5::coin::USDC",
      senderAddress: TARGET,
      displayName: "USD Coin (USDC)",
      displayUrl: "https://www.circle.com/usdc",
    },
    expectedVerdicts: ["SAFE"],
    maxRiskScore: 30,
  },
  {
    label: "Cetus LP position",
    input: {
      objectId: "0xlegit0003",
      objectType: "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb::pool::Position",
      senderAddress: TARGET,
      displayName: "Cetus LP Position",
      displayUrl: "https://cetus.zone",
    },
    expectedVerdicts: ["SAFE"],
    maxRiskScore: 30,
  },
  {
    label: "DeepBook order",
    input: {
      objectId: "0xlegit0004",
      objectType: "0x000000000000000000000000000000000000000000000000000000000000dee9::clob_v2::Order",
      senderAddress: TARGET,
      displayName: "DeepBook Order",
      displayUrl: null,
    },
    expectedVerdicts: ["SAFE"],
    maxRiskScore: 30,
  },
  {
    label: "Sui Kiosk system object",
    input: {
      objectId: "0xlegit0005",
      objectType: "0x2::kiosk::Kiosk",
      senderAddress: TARGET,
      displayName: null,
      displayUrl: null,
      moveAbi: null,
    },
    expectedVerdicts: ["SAFE"],
    maxRiskScore: 30,
  },
];

async function analyze(input: AnalyzeInput): Promise<AnalyzeResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE}/threats/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }
    return (await res.json()) as AnalyzeResponse;
  } finally {
    clearTimeout(timeout);
  }
}

function checkFixture(fixture: Fixture, response: AnalyzeResponse): string[] {
  const failures: string[] = [];
  if (!fixture.expectedVerdicts.includes(response.verdict)) {
    failures.push(`verdict ${response.verdict} != expected ${fixture.expectedVerdicts.join("|")}`);
  }
  if (fixture.minRiskScore !== undefined && response.riskScore < fixture.minRiskScore) {
    failures.push(`score ${response.riskScore} < ${fixture.minRiskScore}`);
  }
  if (fixture.maxRiskScore !== undefined && response.riskScore > fixture.maxRiskScore) {
    failures.push(`score ${response.riskScore} > ${fixture.maxRiskScore}`);
  }
  return failures;
}

function printHeader(): void {
  console.log(`\n${C.bold}${C.cyan}╔══════════════════════════════════════════════════╗${C.reset}`);
  console.log(`${C.bold}${C.cyan}║  DeepClean - Spam vs Legit Population & Test    ║${C.reset}`);
  console.log(`${C.bold}${C.cyan}╚══════════════════════════════════════════════════╝${C.reset}`);
}

async function runGroup(name: string, fixtures: Fixture[]): Promise<{ passed: number; failed: number }> {
  if (fixtures.length === 0) {
    return { passed: 0, failed: 0 };
  }

  console.log(`\n${C.bold}${name}${C.reset}`);

  let passed = 0;
  let failed = 0;

  for (let i = 0; i < fixtures.length; i++) {
    const fixture = fixtures[i]!;
    const prefix = `  [${i + 1}/${fixtures.length}] ${fixture.label}...`;

    try {
      const response = await analyze(fixture.input);
      const failures = checkFixture(fixture, response);
      const status = failures.length === 0
        ? `${C.green}PASS${C.reset}`
        : `${C.red}FAIL${C.reset}`;

      console.log(`  [${i + 1}/${fixtures.length}] ${fixture.label}... ${colorVerdict(response.verdict)} score=${response.riskScore} ${failures.length === 0 ? "✅" : "❌"} ${status}`);

      if (failures.length === 0) {
        passed += 1;
      } else {
        failed += 1;
        console.log(`       reason: ${failures.join("; ")}`);
        console.log(`       reasoning: ${response.reasoning}`);
        console.log(`       flags: ${response.flags.length > 0 ? response.flags.join(", ") : "NONE"}`);
      }
    } catch (e) {
      failed += 1;
      const message = e instanceof Error ? e.message : String(e);
      console.log(`${prefix} ${C.red}ERROR${C.reset} ❌`);
      console.log(`       request failed: ${message}`);
    }
  }

  return { passed, failed };
}

async function main(): Promise<void> {
  if (!TARGET_ADDRESS) {
    console.error(`${C.red}--address is required${C.reset}`);
    usage();
    process.exit(1);
  }
  if (SPAM_ONLY && LEGIT_ONLY) {
    console.error(`${C.red}--spam-only and --legit-only cannot be used together${C.reset}`);
    usage();
    process.exit(1);
  }

  const spamFixtures = LEGIT_ONLY ? [] : SPAM_FIXTURES;
  const legitFixtures = SPAM_ONLY ? [] : LEGIT_FIXTURES;

  printHeader();
  console.log(`\n  Target address: ${C.cyan}${TARGET}${C.reset}`);
  console.log(`  API base      : ${C.dim}${API_BASE}${C.reset}`);
  console.log(`  Mode          : ${C.dim}${SPAM_ONLY ? "spam-only" : LEGIT_ONLY ? "legit-only" : "mixed"}${C.reset}`);

  const spamResult = await runGroup("Spam Cases", spamFixtures);
  const legitResult = await runGroup("Legit Cases", legitFixtures);

  const totalPassed = spamResult.passed + legitResult.passed;
  const totalFailed = spamResult.failed + legitResult.failed;

  if (spamFixtures.length > 0) {
    console.log(`\n  Spam detected correctly   : ${spamResult.passed}/${spamFixtures.length}`);
  }
  if (legitFixtures.length > 0) {
    console.log(`  Legit cleared correctly   : ${legitResult.passed}/${legitFixtures.length}`);
  }
  console.log(`  Total : ${totalPassed} passed, ${totalFailed} failed`);

  if (totalFailed === 0) {
    console.log(`\n${C.green}${C.bold}✅  All objects classified correctly.${C.reset}\n`);
    process.exit(0);
  }

  console.log(`\n${C.red}${C.bold}❌  Classification mismatches detected.${C.reset}\n`);
  process.exit(1);
}

main().catch((e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  console.error(`${C.red}${msg}${C.reset}`);
  process.exit(1);
});
