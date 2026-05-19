// artifacts/api-server/src/lib/monitor.ts
import { prisma } from "@workspace/db";
import { analyzeThreat } from "./gemini";
import { storeThreatLog, buildThreatLog } from "./walrus";
import { quarantineOnChain, isOnChainEnabled } from "./onchain";
import { logger } from "./logger";
import { isValidSuiAddress, normalizeSuiAddress } from "@mysten/sui/utils";
import { MIN_RISK_SCORE_FOR_QUARANTINE } from "./constants";

const SUI_NETWORK      = process.env["SUI_NETWORK"]             ?? "testnet";
const POLL_INTERVAL_MS = Number(process.env["MONITOR_POLL_INTERVAL_MS"] ?? 30_000);
const SEEN_OBJECTS_TTL_MS = 10 * 60_000;

const SUI_RPC_URLS: Record<string, string> = {
  mainnet:  "https://fullnode.mainnet.sui.io:443",
  testnet:  "https://fullnode.testnet.sui.io:443",
  devnet:   "https://fullnode.devnet.sui.io:443",
  localnet: "http://127.0.0.1:9000",
};

const RPC_URL = SUI_RPC_URLS[SUI_NETWORK] ?? SUI_RPC_URLS["testnet"]!;

interface MonitorState {
  started:     boolean;
  pollTimer:   ReturnType<typeof setInterval> | null;
  seenObjects: Map<string, number>;
  cursors:     Map<string, string | null>;
}

const state: MonitorState = {
  started:     false,
  pollTimer:   null,
  seenObjects: new Map(),
  cursors:     new Map(),
};

export async function startMonitor(): Promise<void> {
  if (state.started) {
    logger.info("Monitor already running — restarting");
    await stopMonitor();
  }

  state.started = true;
  logger.info({ network: SUI_NETWORK, rpcUrl: RPC_URL, pollInterval: POLL_INTERVAL_MS }, "Sui monitor starting");

  poll().catch((err) => logger.error({ err }, "Initial monitor poll failed"));

  state.pollTimer = setInterval(() => {
    poll().catch((err) => logger.error({ err }, "Monitor poll failed"));
    evictExpiredSeenObjects();
  }, POLL_INTERVAL_MS);
}

export async function stopMonitor(): Promise<void> {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  state.started = false;
  logger.info("Sui monitor stopped");
}

export function getMonitorStatus() {
  return {
    started:          state.started,
    network:          SUI_NETWORK,
    rpcUrl:           RPC_URL,
    pollIntervalMs:   POLL_INTERVAL_MS,
    activeWallets:    state.cursors.size,
    seenObjectsCount: state.seenObjects.size,
  };
}

async function poll(): Promise<void> {
  // Try to fetch active wallets with an exponential backoff retry strategy.
  const wallets = await attemptFindActiveWallets(5, 1000);
  if (!wallets) {
    // All retries failed — return and let the periodic interval try again later.
    return;
  }

  logger.debug({ count: wallets.length }, "Polling wallets");

  await Promise.allSettled(wallets.map((w) => pollWallet(w.address)));
}

async function attemptFindActiveWallets(maxRetries = 5, baseDelayMs = 1000) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const wallets = await prisma.watchedWallet.findMany({ where: { isActive: true } });
      return wallets;
    } catch (err: any) {
      const attemptNum = attempt + 1;
      const isAuthError = err?.name === "PrismaClientInitializationError" || /Authentication failed/i.test(String(err?.message));
      logger.warn({ err, attempt: attemptNum }, `Monitor DB query failed (attempt ${attemptNum}/${maxRetries})`);

      // For auth errors, don't keep retrying immediately — but we still backoff to allow transient fixes.
      const delay = Math.min(baseDelayMs * 2 ** attempt, 30_000);
      await new Promise((res) => setTimeout(res, delay));

      // If last attempt, log an error and return null to let the interval try again later.
      if (attemptNum >= maxRetries) {
        logger.error({ err }, "Monitor DB query failed after retries — will retry on next poll interval");
        return null;
      }
    }
  }
  return null;
}

async function pollWallet(address: string): Promise<void> {
  try {
    const normalizedAddress = normalizeSuiAddress(address);
    if (!isValidSuiAddress(normalizedAddress)) {
      logger.warn({ address }, "Skipping invalid wallet address");
      return;
    }

    const cursor = state.cursors.get(normalizedAddress) ?? null;

    const result = await suiRpc<{
      data: Array<{
        digest: string;
        transaction?: { data?: { transaction?: { inputs?: Array<{ objectId?: string; objectType?: string }>; kind?: string } } };
        effects?: { created?: Array<{ reference?: { objectId?: string }; owner?: { AddressOwner?: string } }> };
      }>;
      nextCursor: string | null;
      hasNextPage: boolean;
    }>("suix_queryTransactionBlocks", [
      { filter: { ToAddress: normalizedAddress }, options: { showInput: true, showEffects: true, showObjectChanges: false } },
      cursor,
      10,
      false,
    ]);

    if (!result?.data?.length) return;

    const latestDigest = result.data[0]?.digest;
    if (latestDigest) state.cursors.set(normalizedAddress, latestDigest);

    if (cursor === null && result.data.length > 0) {
      logger.debug({ address: normalizedAddress, txCount: result.data.length }, "Baseline established for wallet");
      return;
    }

    for (const tx of result.data) {
      const createdObjects = tx.effects?.created ?? [];
      for (const obj of createdObjects) {
        const objectId        = obj.reference?.objectId;
        const recipientAddress = obj.owner?.AddressOwner;

        if (!objectId || recipientAddress !== address) continue;
        if (state.seenObjects.has(objectId)) continue;

        state.seenObjects.set(objectId, Date.now());

        const objectData  = await fetchObjectType(objectId);
        const objectType  = objectData?.type ?? "unknown::module::Unknown";

        logger.info({ objectId, objectType, address: normalizedAddress }, "New object detected for monitored wallet");
        await analyzeAndStore(objectId, objectType, address, address);
      }
    }
  } catch (err) {
    logger.warn({ err, address }, "Failed to poll wallet — will retry on next interval");
  }
}

async function fetchObjectType(objectId: string): Promise<{ type: string } | null> {
  try {
    const result = await suiRpc<{ data?: { type?: string } }>("sui_getObject", [objectId, { showType: true }]);
    return result?.data?.type ? { type: result.data.type } : null;
  } catch {
    return null;
  }
}

async function analyzeAndStore(
  objectId: string,
  objectType: string,
  senderAddress: string,
  walletAddress: string,
): Promise<void> {
  try {
    // If this objectType matches one of the demo junk modules, provide a
    // human-friendly displayName so seeded objects show correct labels in the UI.
    const moduleSegment = objectType.split("::")?.[1]?.toLowerCase() ?? "";
    logger.info({ objectId, fullObjectType: objectType, extractedModule: moduleSegment }, "Object detected for analysis");

    const DEMO_LABELS: Record<string, string> = {
      malicious_airdrop: "Fake SUI Airdrop Token",
      rug_token: "Rug Meme Coin",
      fake_foundation_nft: "Fake Foundation NFT",
      pool: "Spoofed Cetus LP Position",
      honeypot_defi: "Honeypot DeFi Token",
    };

    const inferredDisplayName = DEMO_LABELS[moduleSegment] ?? null;
    logger.info({ moduleSegment, inferredDisplayName, allLabelsForDebug: Object.keys(DEMO_LABELS) }, "Display name lookup result");

    const verdict = await analyzeThreat({ objectId, objectType, senderAddress, displayName: inferredDisplayName });

    const logPayload = buildThreatLog({
      objectId, objectType, senderAddress,
      displayName: inferredDisplayName, displayUrl: null,
      verdict:    verdict.verdict,
      riskScore:  verdict.risk_score,
      reasonCode: verdict.reason_code,
      confidence: verdict.confidence,
      flags:      verdict.flags,
      reasoning:  verdict.reasoning,
    });

    // BUG FIX #1: Check verdict type AND high score threshold before quarantining
    // Requires BOTH conditions: (1) explicitly MALICIOUS AND (2) score >= 75
    if (verdict.verdict === "MALICIOUS" && verdict.risk_score >= 75) {
      const [walrusBlobId, inserted] = await Promise.all([
        storeThreatLog(logPayload),
        prisma.threat.create({
          data: {
            objectId,
            objectType,
            senderAddress,
            walletAddress,
            displayName: inferredDisplayName ?? null,
            displayUrl: null,
            riskScore:  verdict.risk_score,
            verdict:    verdict.verdict,
            reasonCode: verdict.reason_code,
            confidence: verdict.confidence,
            flags:      verdict.flags,
            reasoning:  verdict.reasoning,
            status:     "quarantined",
            walrusBlobId: null, // backfilled below
          },
        }),
      ]);

      if (walrusBlobId) {
        await prisma.threat.update({
          where: { id: inserted.id },
          data:  { walrusBlobId },
        });
      }

      // BUG FIX #4: Add Sui integration — record quarantine on-chain
      if (isOnChainEnabled()) {
        try {
          const digest = await quarantineOnChain({
            objectId,
            objectType,
            senderAddress,
            riskScore: verdict.risk_score,
            verdict: verdict.verdict,
            reasonCode: verdict.reason_code,
            confidence: verdict.confidence,
            walrusBlobId: walrusBlobId ?? "",
          });

          if (digest) {
            try {
              await prisma.threat.update({
                where: { id: inserted.id },
                data: { quarantineTxDigest: digest },
              });
            } catch {
              // ignore DB update failures
            }
          }
        } catch (err) {
          logger.warn({ err, objectId }, "On-chain quarantine failed (non-blocking)");
        }
      }

      // Increment threatsDetected counter
      await prisma.watchedWallet.update({
        where: { address: walletAddress },
        data:  { threatsDetected: { increment: 1 } },
      });

      logger.warn({ id: inserted.id, objectId, riskScore: verdict.risk_score }, "Threat auto-quarantined");
    } else {
      storeThreatLog(logPayload).catch(() => {});
      logger.info({ objectId, riskScore: verdict.risk_score }, "Object cleared by AI");
    }
  } catch (err) {
    logger.error({ err, objectId }, "Failed to analyze object from monitor");
  }
}

async function suiRpc<T>(method: string, params: unknown[]): Promise<T> {
  const response = await fetch(RPC_URL, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal:  AbortSignal.timeout(15_000),
  });

  if (!response.ok) throw new Error(`Sui RPC HTTP ${response.status}`);

  const json = (await response.json()) as { result?: T; error?: { message: string } };
  if (json.error) throw new Error(`Sui RPC error: ${json.error.message}`);

  return json.result as T;
}

function evictExpiredSeenObjects(): void {
  const now = Date.now();
  for (const [id, ts] of state.seenObjects) {
    if (now - ts > SEEN_OBJECTS_TTL_MS) state.seenObjects.delete(id);
  }
}