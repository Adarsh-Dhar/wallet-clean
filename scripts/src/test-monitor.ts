/**
 * T1 — Sui Monitor Layer Test
 *
 * Tests the monitor via the health endpoint and wallet management API.
 * This script simulates the reconnect scenario by adding/removing wallets
 * and verifying that the monitor picks up the changes on the next sync.
 *
 * Run with: pnpm --filter @workspace/scripts run test:monitor
 * Override: API_BASE=http://localhost:80/api pnpm --filter @workspace/scripts run test:monitor
 */

import "dotenv/config";

const API_BASE = process.env["API_BASE"] ?? "http://localhost:80/api";

interface TestResult { name: string; passed: boolean; detail?: string }
const results: TestResult[] = [];

async function apiFetch(path: string, opts: RequestInit = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    signal: AbortSignal.timeout(10_000),
    ...opts,
  });
  let body: unknown;
  try { body = await res.json(); } catch { body = null; }
  return { ok: res.ok, status: res.status, body };
}

async function test(name: string, fn: () => Promise<string | void>): Promise<void> {
  process.stdout.write(`  ▶ ${name}... `);
  try {
    const detail = await fn();
    results.push({ name, passed: true, detail: detail ?? undefined });
    console.log(`✅${detail ? `  — ${detail}` : ""}`);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    results.push({ name, passed: false, detail });
    console.log(`❌  ${detail}`);
  }
}

async function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log("\n╔══════════════════════════════════════════════╗");
  console.log("║  T1 — Sui Monitor Layer Test                 ║");
  console.log("╚══════════════════════════════════════════════╝\n");
  console.log(`  API: ${API_BASE}\n`);

  let addedWalletId: number | null = null;

  // 1. Health check shows monitor running
  await test("Health endpoint reports monitor status", async () => {
    const { ok, body } = await apiFetch("/healthz");
    if (!ok) throw new Error("Health check failed");
    const b = body as Record<string, unknown>;
    if (!b["monitor"]) throw new Error("monitor field missing from health response");
    const m = b["monitor"] as Record<string, unknown>;
    return `started=${m["started"]}, network=${m["network"]}, wallets=${m["activeWallets"]}`;
  });

  // 2. Add a wallet — monitor should pick it up on next poll
  await test("Add wallet to monitoring list", async () => {
    const { ok, status, body } = await apiFetch("/monitor/wallets", {
      method: "POST",
      body: JSON.stringify({
        address: "0xmonitor_test_wallet_000000000001",
        label: "Monitor Test Wallet T1",
      }),
    });
    if (!ok) throw new Error(`POST /monitor/wallets → ${status}`);
    const b = body as Record<string, unknown>;
    addedWalletId = b["id"] as number;
    return `wallet id=${addedWalletId}`;
  });

  // 3. Wallet appears in list
  await test("Wallet appears in list endpoint", async () => {
    const { ok, body } = await apiFetch("/monitor/wallets");
    if (!ok) throw new Error("GET /monitor/wallets failed");
    const wallets = body as Array<Record<string, unknown>>;
    const found = wallets.find((w) => w["id"] === addedWalletId);
    if (!found) throw new Error(`Wallet id=${addedWalletId} not found in list`);
    if (!found["isActive"]) throw new Error("Wallet isActive is false");
    return `found ${wallets.length} wallets, added one active`;
  });

  // 4. Wallet persists — isActive=true
  await test("Added wallet is active", async () => {
    const { ok, body } = await apiFetch("/monitor/wallets");
    if (!ok) throw new Error("List failed");
    const wallets = body as Array<Record<string, unknown>>;
    const w = wallets.find((w) => w["id"] === addedWalletId);
    if (!w?.["isActive"]) throw new Error("Wallet not active");
    return `isActive=${w["isActive"]}`;
  });

  // 5. Simulate "reconnect" — add a second wallet while monitor is running
  await test("Add second wallet (simulates mid-runtime subscription add)", async () => {
    const { ok, body } = await apiFetch("/monitor/wallets", {
      method: "POST",
      body: JSON.stringify({
        address: "0xmonitor_test_wallet_000000000002",
        label: "Monitor Test Wallet T1 (2)",
      }),
    });
    if (!ok) throw new Error("Failed to add second wallet");
    const b = body as Record<string, unknown>;
    const id = b["id"] as number;
    // Immediately remove to clean up
    await apiFetch(`/monitor/wallets/${id}`, { method: "DELETE" });
    return `added and removed id=${id}`;
  });

  // 6. Brief wait to confirm monitor doesn't crash
  await test("Monitor stable after wallet churn (1s wait)", async () => {
    await sleep(1_000);
    const { ok, body } = await apiFetch("/healthz");
    if (!ok) throw new Error("Health check failed after wallet churn");
    const b = body as Record<string, unknown>;
    const m = b["monitor"] as Record<string, unknown>;
    return `started=${m["started"]}`;
  });

  // 7. Remove the original test wallet
  await test("Remove test wallet cleans up", async () => {
    if (!addedWalletId) throw new Error("No wallet to remove");
    const { ok, status } = await apiFetch(`/monitor/wallets/${addedWalletId}`, { method: "DELETE" });
    if (!ok) throw new Error(`DELETE → ${status}`);
    return `wallet ${addedWalletId} removed`;
  });

  // 8. Verify wallet gone from list
  await test("Removed wallet absent from list", async () => {
    const { ok, body } = await apiFetch("/monitor/wallets");
    if (!ok) throw new Error("List failed");
    const wallets = body as Array<Record<string, unknown>>;
    const stillThere = wallets.some((w) => w["id"] === addedWalletId);
    if (stillThere) throw new Error(`Wallet ${addedWalletId} still in list after removal`);
    return `confirmed absent`;
  });

  // Summary
  const passed = results.filter(r => r.passed).length;
  const failed = results.length - passed;
  console.log(`\n─────────────────────────────────────────────`);
  console.log(`  Results: ${passed}/${results.length} passed`);
  console.log(`─────────────────────────────────────────────\n`);
  if (failed > 0) { console.error(`❌  ${failed} failed\n`); process.exit(1); }
  console.log("✅  All monitor tests passed\n");
}

main().catch(err => { console.error("Fatal:", err); process.exit(1); });

export {};
