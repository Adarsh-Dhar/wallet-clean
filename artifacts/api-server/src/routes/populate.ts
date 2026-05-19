// artifacts/api-server/src/routes/populate.ts
import { Router } from "express";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { prisma } from "@workspace/db";
import { analyzeThreatBatch } from "../lib/gemini";
import { storeThreatLog, buildThreatLog } from "../lib/walrus";
import { quarantineOnChain, isOnChainEnabled } from "../lib/onchain";
import { MIN_RISK_SCORE_FOR_QUARANTINE } from "../lib/constants";

const router = Router();

// ─── Fetch real objects from the target wallet ───────────────────────────────

interface ChainObject {
  objectId:      string;
  objectType:    string;
  senderAddress: string;
  displayName:   string | null;
  displayUrl:    string | null;
  moveAbi:       string | null;
}

async function fetchOriginalSender(
  client: SuiJsonRpcClient,
  objectId: string
): Promise<string | null> {
  try {
    const txs = await client.queryTransactionBlocks({
      filter: { ChangedObject: objectId },
      options: {
        showInput: true,
        showEffects: true,
      },
      limit: 1,
      order: "ascending",
    });

    if (!txs.data || txs.data.length === 0) {
      return null;
    }

    const creationTx = txs.data[0];
    return creationTx.transaction?.data.sender ?? null;
  } catch (err) {
    console.debug("fetchOriginalSender failed:", err);
    return null;
  }
}

async function fetchAllSpamObjectsForWallet(
  client: SuiJsonRpcClient,
  walletAddress: string
): Promise<ChainObject[]> {
  const results: ChainObject[] = [];

  try {
    // Fetch all objects owned by the provided wallet across every page.
    let cursor: string | null | undefined = null;
    do {
      const owned = await client.getOwnedObjects({
        owner: walletAddress,
        cursor: cursor ?? undefined,
        limit: 50,
        options: {
          showType:    true,
          showDisplay: true,
          showContent: true,
        },
      });

      for (const item of owned.data) {
        const obj = item.data;
        if (!obj || !obj.objectId || !obj.type) continue;

        // Skip publishing artifacts not relevant for threat analysis.
        const isDisplayOrPub =
          obj.type.includes("::display::Display") ||
          obj.type.includes("::package::Publisher") ||
          obj.type.includes("::package::UpgradeCap");

        if (isDisplayOrPub) continue;  // skip publishing artifacts

        const sender = await fetchOriginalSender(client, obj.objectId);

        const displayFields = obj.display?.data as Record<string, string> | undefined | null;

        results.push({
          objectId:      obj.objectId,
          objectType:    obj.type,
          senderAddress: sender ?? "unknown",
          displayName:   displayFields?.["name"] ?? null,
          displayUrl:    displayFields?.["link"] ?? displayFields?.["url"] ?? null,
          moveAbi:       null,
        });
      }

      cursor = owned.nextCursor;
      if (!owned.hasNextPage) break;
    } while (cursor);
  } catch (err) {
    console.warn("fetchAllSpamObjectsForWallet: RPC error", err);
  }

  return results;
}

// POST /populate-wallet
router.post("/populate-wallet", async (req, res) => {
  const { targetAddress, txDigest: callerTxDigest } = req.body as {
    targetAddress?: string;
    txDigest?: string | null;
  };

  if (!targetAddress || typeof targetAddress !== "string") {
    res.status(400).json({ error: "targetAddress is required" });
    return;
  }

  const REAL_ONCHAIN = (process.env["REAL_ONCHAIN"] ?? "false").toLowerCase() === "true";
  const SUI_NETWORK = (process.env["SUI_NETWORK"] ?? "testnet") as "testnet" | "mainnet" | "devnet" | "localnet";

  req.log.info(
    { targetAddress, realOnChain: REAL_ONCHAIN, onChainEnabled: isOnChainEnabled(), network: SUI_NETWORK },
    "Populating wallet with real on-chain wallet objects"
  );

  if (REAL_ONCHAIN && !isOnChainEnabled()) {
    req.log.error({ env: Object.keys(process.env) }, "REAL_ONCHAIN requested but on-chain config missing (QUARANTINE_PACKAGE_ID / QUARANTINE_ADMIN_CAP_ID / AGENT_PRIVATE_KEY)");
    res.status(500).json({ error: "REAL_ONCHAIN=true but on-chain configuration (QUARANTINE_PACKAGE_ID, QUARANTINE_ADMIN_CAP_ID, AGENT_PRIVATE_KEY) is missing" });
    return;
  }

  // Connect to the requested Sui network where our contracts are deployed
  type NetworkName = "testnet" | "mainnet" | "devnet" | "localnet";
  const networkName: NetworkName = SUI_NETWORK;
  const client = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl(networkName), network: networkName });

  const injections: ChainObject[] = await fetchAllSpamObjectsForWallet(client, targetAddress);

  req.log.info(
    { onChainObjects: injections.length, targetAddress },
    "Fetched real on-chain objects"
  );

  // Analyze ALL objects in a single model call
  const verdicts = await analyzeThreatBatch(injections);

  const threats = await Promise.all(
    injections.map(async (obj, idx) => {
      const verdict = verdicts[idx] ?? {
        risk_score: 20,
        verdict: "SAFE" as const,
        reason_code: 5,
        confidence: 0.5,
        flags: [],
        reasoning: "No verdict returned",
      };

      const effectiveVerdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS" = verdict.verdict;
      const effectiveRiskScore = verdict.risk_score;

      const logPayload = buildThreatLog({
        objectId:      obj.objectId,
        objectType:    obj.objectType,
        senderAddress: obj.senderAddress,
        displayName:   obj.displayName ?? null,
        displayUrl:    obj.displayUrl  ?? null,
        verdict:       effectiveVerdict,
        riskScore:     effectiveRiskScore,
        reasonCode:    verdict.reason_code,
        confidence:    verdict.confidence,
        flags:         verdict.flags,
        reasoning:     verdict.reasoning,
      });

      try {
        const existing = await prisma.threat.findFirst({
          where: { objectId: obj.objectId, walletAddress: targetAddress },
        });

        if (existing) {
          return {
            objectId:   obj.objectId,
            objectType: obj.objectType,
            verdict:    existing.verdict as "SAFE" | "SUSPICIOUS" | "MALICIOUS",
            riskScore:  existing.riskScore,
            threatId:   existing.status === "quarantined" ? existing.id : null,
            onChainDigest: existing.quarantineTxDigest ?? null,
          };
        }

        const shouldQuarantine = effectiveVerdict === "MALICIOUS" && effectiveRiskScore >= MIN_RISK_SCORE_FOR_QUARANTINE;
        const status = shouldQuarantine ? "quarantined" : "safe";

        const [walrusBlobId, threat] = await Promise.all([
          storeThreatLog(logPayload),
          prisma.threat.create({
            data: {
              objectId:      obj.objectId,
              objectType:    obj.objectType,
              senderAddress: obj.senderAddress,
              walletAddress: targetAddress,
              displayName:   obj.displayName ?? null,
              displayUrl:    obj.displayUrl  ?? null,
              riskScore:     effectiveRiskScore,
              verdict:       effectiveVerdict,
              reasonCode:    verdict.reason_code,
              confidence:    verdict.confidence,
              flags:         verdict.flags,
              reasoning:     verdict.reasoning,
              cleanMethod:   verdict.clean_method,
              status,
            },
          }),
        ]);

        const threatId = status === "quarantined" ? threat.id : null;

        if (walrusBlobId) {
          await prisma.threat.update({ where: { id: threat.id }, data: { walrusBlobId } });
        }

        let onChainDigest: string | null = null;
        if (shouldQuarantine && REAL_ONCHAIN) {
          onChainDigest = await quarantineOnChain({
            objectId:      obj.objectId,
            objectType:    obj.objectType,
            senderAddress: obj.senderAddress,
            riskScore:     effectiveRiskScore,
            verdict:       effectiveVerdict,
            reasonCode:    verdict.reason_code,
            confidence:    verdict.confidence,
            walrusBlobId:  walrusBlobId ?? "",
          });

          if (onChainDigest) {
            await prisma.threat.update({
              where: { id: threat.id },
              data:  { quarantineTxDigest: onChainDigest },
            }).catch(() => {});
          }
        }

        return {
          objectId:      obj.objectId,
          objectType:    obj.objectType,
          verdict:       effectiveVerdict,
          riskScore:     effectiveRiskScore,
          threatId,
          onChainDigest,
        };
      } catch (err) {
        req.log.error({ err, objectId: obj.objectId, objectType: obj.objectType }, "populate-wallet item failed");
        return {
          objectId:      obj.objectId,
          objectType:    obj.objectType,
          verdict:       effectiveVerdict,
          riskScore:     effectiveRiskScore,
          threatId:      null,
          onChainDigest: null,
          error:         err instanceof Error ? err.message : String(err),
        };
      }
    })
  );

  const quarantined    = threats.filter((t) => t.threatId !== null).length;
  const onChainDigests = threats.map((t) => t.onChainDigest).filter(Boolean);

  // Update watchedWallet threat counter
  if (quarantined > 0) {
    await prisma.watchedWallet.update({
      where: { address: targetAddress },
      data:  { threatsDetected: { increment: quarantined } },
    });
  }

  req.log.info(
    { injected: threats.length, quarantined, onChainCount: onChainDigests.length, targetAddress },
    "Wallet population complete"
  );

  res.json({
    injected:      threats.length,
    quarantined,
    txDigest:      callerTxDigest ?? null,
    onChainDigest: onChainDigests[0] ?? null,
    threats,
  });
});

export default router;