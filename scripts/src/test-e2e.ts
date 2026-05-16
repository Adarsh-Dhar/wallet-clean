/**
 * T5 — DeepClean End-to-End Pipeline Test
 *
 * Tests the full pipeline against a running local server at localhost:80.
 * This is your demo script — run it the day before submission.
 *
 * Pipeline tested:
 *   1. Health check
 *   2. Add a wallet to monitor
 *   3. Submit a malicious object for analysis
 *   4. Verify threat auto-saved with correct verdict
 *   5. Verify Walrus blob ID present (T4 linkage)
 *   6. Release a quarantined threat
 *   7. Submit another threat and burn it
 *   8. Verify dashboard stats updated
 *   9. Verify risk-breakdown endpoint reflects new threats
 *  10. Remove the test wallet
 *  11. Full pipeline SLA check (< 30 000ms)
 *
 * Run with: pnpm --filter @workspace/scripts run test:e2e
 * Set API_BASE to override: API_BASE=http://localhost:80/api pnpm --filter @workspace/scripts run test:e2e
 */

const API_BASE = process.env["API_BASE"] ?? "http://localhost:80/api";
const TIMEOUT_MS = 30_000;

type TestResult = { name: string; passed: boolean; ms: number; detail?: string };

const results: TestResult[] = [];

async function apiFetch(
  path: string,
  opts: RequestInit = {},
): Promise<{ ok: boolean; status: number; body: unknown }> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(opts.headers as Record<string, string> ?? {}) },
    signal: AbortSignal.timeout(TIMEOUT_MS),
    ...opts,
  });
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { ok: res.ok, status: res.status, body };
}

async function test(
  name: string,
  fn: () => Promise<string | void>,
): Promise<void> {
  const start = Date.now();
  process.stdout.write(`  ▶ ${name}... `);
  try {
    const detail = await fn();
    const ms = Date.now() - start;
    results.push({ name, passed: true, ms, detail: detail ?? undefined });
    console.log(`✅  ${ms}ms${detail ? ` — ${detail}` : ""}`);
  } catch (err) {
    const ms = Date.now() - start;
    const detail = err instanceof Error ? err.message : String(err);
    results.push({ name, passed: false, ms, detail });
    console.log(`❌  ${ms}ms — ${detail}`);
  }
}

function expect<T>(label: string, actual: T, expected: T): void {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function expectTruthy(label: string, value: unknown): void {
  if (!value) throw new Error(`${label} is falsy`);
}

function expectRange(label: string, value: number, min: number, max: number): void {
  if (value < min || value > max) {
    throw new Error(`${label}: ${value} not in range [${min}, ${max}]`);
  }
}

// ─── State shared across tests ────────────────────────────────────────────────
let walletId: number;
let threatId: number;
let burnThreatId: number;
let dashboardBefore: Record<string, number>;

// ─── Test definitions ─────────────────────────────────────────────────────────

async function main() {
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log("║  T5 — DeepClean E2E Pipeline Test           ║");
  console.log("╚══════════════════════════════════════════════╝\n");
  console.log(`  API base: ${API_BASE}\n`);

  const pipelineStart = Date.now();

  // 1. Health check
  await test("Health check returns ok", async () => {
    const { ok, body } = await apiFetch("/healthz");
    if (!ok) throw new Error("Non-200 response");
    const b = body as Record<string, unknown>;
    expect("status", b["status"], "ok");
    return `monitor.started=${(b["monitor"] as Record<string, unknown>)?.["started"]}`;
  });

  // Snapshot dashboard before
  await test("Snapshot dashboard stats before", async () => {
    const { ok, body } = await apiFetch("/stats/dashboard");
    if (!ok) throw new Error("Dashboard request failed");
    dashboardBefore = body as Record<string, number>;
    return `totalThreats=${dashboardBefore["totalThreats"]}`;
  });

  // 2. Add wallet
  await test("Add wallet to monitor", async () => {
    const { ok, status, body } = await apiFetch("/monitor/wallets", {
      method: "POST",
      body: JSON.stringify({
        address: "0xe2e_test_wallet_00000000000000001",
        label: "E2E Test Wallet",
      }),
    });
    if (!ok) throw new Error(`POST /monitor/wallets → ${status}`);
    const b = body as Record<string, unknown>;
    expectTruthy("wallet.id", b["id"]);
    walletId = b["id"] as number;
    return `id=${walletId}`;
  });

  // 3. Analyze malicious object
  await test("Analyze known-malicious object", async () => {
    const { ok, status, body } = await apiFetch("/threats/analyze", {
      method: "POST",
      body: JSON.stringify({
        objectId: "0xe2e_phishing_object_0000000000001",
        objectType: "0xscam::fake_wallet::SuiWalletConnect",
        senderAddress: "0xbad_actor_0000000000000000001",
        displayName: "Sui Wallet Connect — Exclusive Access",
        displayUrl: "https://sui-wallet-0fficial.com/connect",
      }),
    });
    if (!ok) throw new Error(`POST /threats/analyze → ${status}`);
    const b = body as Record<string, unknown>;
    const verdict = b["verdict"] as string;
    const score = b["riskScore"] as number;
    const latencyMs = (b["latencyMs"] as number) ?? 0;
    if (score < 65) throw new Error(`Expected high-risk threat, got riskScore=${score}`);
    if (verdict !== "MALICIOUS") throw new Error(`Expected MALICIOUS, got ${verdict}`);
    if (latencyMs > 20_000) throw new Error(`Analysis latency ${latencyMs}ms exceeds 20s SLA`);
    threatId = b["savedThreatId"] as number;
    if (!threatId) throw new Error("savedThreatId missing — threat was not auto-quarantined");
    return `threatId=${threatId}, score=${score}, latency=${latencyMs}ms`;
  });

  // 4. Fetch threat and verify saved correctly
  await test("Fetch quarantined threat by ID", async () => {
    const { ok, status, body } = await apiFetch(`/threats/${threatId}`);
    if (!ok) throw new Error(`GET /threats/${threatId} → ${status}`);
    const b = body as Record<string, unknown>;
    expect("status", b["status"], "quarantined");
    expect("verdict", b["verdict"], "MALICIOUS");
    expectRange("riskScore", b["riskScore"] as number, 65, 100);
    return `status=${b["status"]}, blobId=${b["walrusBlobId"] ?? "none"}`;
  });

  // 5. Walrus blob ID check (T4 integration)
  await test("Walrus blob ID linked to threat", async () => {
    const { body } = await apiFetch(`/threats/${threatId}`);
    const b = body as Record<string, unknown>;
    const blobId = b["walrusBlobId"] as string | null;
    if (!blobId) {
      // Non-fatal for CI where Walrus testnet may be unreachable — warn
      return "⚠️ No walrus_blob_id (Walrus testnet may be unreachable in this environment)";
    }
    if (blobId.length < 8) throw new Error(`walrusBlobId "${blobId}" looks invalid`);
    return `blobId=${blobId.slice(0, 12)}...`;
  });

  // 6. Release threat
  await test("Release quarantined threat", async () => {
    const { ok, status, body } = await apiFetch(`/threats/${threatId}/release`, { method: "POST" });
    if (!ok) throw new Error(`POST /threats/${threatId}/release → ${status}`);
    const b = body as Record<string, unknown>;
    expect("status after release", b["status"], "released");
    return `status=${b["status"]}`;
  });

  // Cannot release again
  await test("Double-release returns 409 conflict", async () => {
    const { status } = await apiFetch(`/threats/${threatId}/release`, { method: "POST" });
    if (status !== 409) throw new Error(`Expected 409, got ${status}`);
  });

  // 7. Analyze another threat and burn it
  await test("Analyze second threat for burn test", async () => {
    const { ok, status, body } = await apiFetch("/threats/analyze", {
      method: "POST",
      body: JSON.stringify({
        objectId: "0xe2e_honeypot_object_000000000001",
        objectType: "0xhoneypot::drain::SuiYield",
        senderAddress: "0xbad_actor_0000000000000000002",
        displayName: "FREE SUI Yield Farm",
        displayUrl: "https://free-sui-yield.com/stake",
      }),
    });
    if (!ok) throw new Error(`POST /threats/analyze → ${status}`);
    const b = body as Record<string, unknown>;
    burnThreatId = b["savedThreatId"] as number;
    if (!burnThreatId) throw new Error("Second threat not quarantined");
    return `burnThreatId=${burnThreatId}`;
  });

  await test("Burn quarantined threat", async () => {
    const { ok, status, body } = await apiFetch(`/threats/${burnThreatId}/burn`, { method: "POST" });
    if (!ok) throw new Error(`POST /threats/${burnThreatId}/burn → ${status}`);
    const b = body as Record<string, unknown>;
    expect("status after burn", b["status"], "burned");
    return `status=${b["status"]}`;
  });

  // Cannot burn again
  await test("Double-burn returns 409 conflict", async () => {
    const { status } = await apiFetch(`/threats/${burnThreatId}/burn`, { method: "POST" });
    if (status !== 409) throw new Error(`Expected 409, got ${status}`);
  });

  // 8. Dashboard stats updated
  await test("Dashboard stats reflect new threats", async () => {
    const { ok, body } = await apiFetch("/stats/dashboard");
    if (!ok) throw new Error("Dashboard request failed");
    const after = body as Record<string, number>;
    if (after["totalThreats"] <= dashboardBefore["totalThreats"]) {
      throw new Error(`totalThreats did not increase: ${dashboardBefore["totalThreats"]} → ${after["totalThreats"]}`);
    }
    return `totalThreats: ${dashboardBefore["totalThreats"]} → ${after["totalThreats"]}`;
  });

  // 9. Risk breakdown
  await test("Risk breakdown returns data", async () => {
    const { ok, body } = await apiFetch("/stats/risk-breakdown");
    if (!ok) throw new Error("Risk breakdown request failed");
    const items = body as Array<Record<string, unknown>>;
    if (!Array.isArray(items) || items.length === 0) throw new Error("Empty breakdown");
    for (const item of items) {
      if (typeof item["reasonCode"] !== "number") throw new Error("Missing reasonCode");
      if (typeof item["count"] !== "number") throw new Error("Missing count");
      if (typeof item["label"] !== "string") throw new Error("Missing label");
    }
    return `${items.length} reason codes`;
  });

  // 10. Filter threats by status
  await test("Filter threats by status=released returns results", async () => {
    const { ok, body } = await apiFetch("/threats?status=released");
    if (!ok) throw new Error("Filter request failed");
    const items = body as Array<Record<string, unknown>>;
    if (!Array.isArray(items)) throw new Error("Not an array");
    const allReleased = items.every((t) => t["status"] === "released");
    if (!allReleased) throw new Error("Non-released items in filtered response");
    return `${items.length} released threats`;
  });

  // 11. Remove test wallet
  await test("Remove test wallet", async () => {
    const { ok, status } = await apiFetch(`/monitor/wallets/${walletId}`, { method: "DELETE" });
    if (!ok) throw new Error(`DELETE /monitor/wallets/${walletId} → ${status}`);
    return `wallet ${walletId} removed`;
  });

  // ── Summary ────────────────────────────────────────────────────────────────
  const pipelineMs = Date.now() - pipelineStart;
  const passed = results.filter((r) => r.passed).length;
  const failed = results.length - passed;

  console.log(`\n─────────────────────────────────────────────`);
  console.log(`  Results:         ${passed}/${results.length} passed`);
  console.log(`  Total pipeline:  ${pipelineMs}ms`);
  if (pipelineMs > 30_000) {
    console.log(`  ⚠️  Pipeline SLA breached (> 30 000ms)`);
  } else {
    console.log(`  ✅  Pipeline SLA OK (< 30s)`);
  }
  console.log(`─────────────────────────────────────────────\n`);

  if (failed > 0) {
    console.error(`❌  ${failed} test(s) failed\n`);
    process.exit(1);
  }

  console.log(`✅  All E2E tests passed\n`);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});

export {};
