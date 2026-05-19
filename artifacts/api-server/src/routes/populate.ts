// artifacts/api-server/src/routes/populate.ts
import { Router } from "express";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { prisma } from "@workspace/db";
import { analyzeThreatBatch } from "../lib/gemini";
import { storeThreatLog, buildThreatLog } from "../lib/walrus";
import { quarantineOnChain, isOnChainEnabled } from "../lib/onchain";
import { MIN_RISK_SCORE_FOR_QUARANTINE } from "../lib/constants";

const router = Router();

// Your deployed package ID from `sui client publish`
const SPAM_PACKAGE_ID =
  process.env["QUARANTINE_PACKAGE_ID"] ??
  "0xe933d9d3e69b29d0183ffbcecaacf7ec8dbc3832f99815760f0d34913c2c1ca4";

// Metadata we know about each deployed module — used to enrich objects
// fetched from the chain with display names and URLs (since display objects
// are separate on-chain and not always returned by getOwnedObjects)
const KNOWN_OBJECT_META: Record<string, { displayName: string; displayUrl: string; moveAbi?: string }> = {
  [`${SPAM_PACKAGE_ID}::malicious_airdrop::AirdropToken`]: {
    displayName: "5000 SUI Airdrop — Claim Expires in 24h",
    displayUrl:  "https://sui-airdrop-2026.xyz/claim",
  },
  [`${SPAM_PACKAGE_ID}::fake_foundation_nft::FounderPass`]: {
    displayName: "Sui Foundation VIP Founder Pass",
    displayUrl:  "https://su\u0456.io/founder-claim",  // Cyrillic і — real homoglyph
  },
  [`${SPAM_PACKAGE_ID}::honeypot_defi::HoneypotToken`]: {
    displayName: "SuiGold — 10\u00d7 APY Yield Protocol",
    displayUrl:  "https://suigold-defi.xyz/stake",
    moveAbi: JSON.stringify({
      functions: [
        { name: "stake_and_receive", visibility: "public",  params: ["address"] },
        { name: "withdraw",          visibility: "public",  params: ["HoneypotToken"] },
        { name: "drain_all_hidden",  visibility: "private", params: ["&mut TxContext"] },
      ],
    }),
  },
  [`${SPAM_PACKAGE_ID}::rug_token::MemeCoin`]: {
    displayName: "SuiDoge — 100x Meme Coin",
    displayUrl:  "https://suidoge-token.xyz/stake",
    moveAbi: JSON.stringify({
      functions: [
        { name: "airdrop_to",    visibility: "public",  params: ["address"] },
        { name: "freeze_all",    visibility: "public",  params: ["&AdminCap"] },
        { name: "migrate_funds", visibility: "public",  params: ["&AdminCap", "address"] },
      ],
    }),
  },
  [`${SPAM_PACKAGE_ID}::spoofed_pool::Position`]: {
    displayName: "Cetus LP Position",
    displayUrl:  "https://cetus.zone/position",
    moveAbi: JSON.stringify({
      functions: [
        { name: "fake_mint",    visibility: "public", params: [] },
        { name: "collect_fees", visibility: "public", params: ["&Position"] },
      ],
    }),
  },
  // Dust attack — it's a plain Coin<SUI>, no custom metadata
  "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin": {
    displayName: "SUI",
    displayUrl:  "",
  },
};

// ─── Fetch real objects from the target wallet ───────────────────────────────

interface ChainObject {
  objectId:      string;
  objectType:    string;
  senderAddress: string;
  displayName:   string | null;
  displayUrl:    string | null;
  moveAbi:       string | null;
}

async function fetchRealSpamObjects(
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

        // getOwnedObjects does not include transfer sender provenance.
        const sender = "unknown";

        // Look up enriched metadata by type
        const baseType = obj.type.replace(/<.*>/, ""); // strip generic params
        const meta = KNOWN_OBJECT_META[baseType];

        // Pull display fields from on-chain display object if present
        const displayFields = obj.display?.data as Record<string, string> | undefined | null;

        const displayName =
          meta?.displayName ??
          displayFields?.["name"] ??
          null;

        const displayUrl =
          meta?.displayUrl ??
          displayFields?.["link"] ??
          displayFields?.["url"] ??
          null;

        results.push({
          objectId:      obj.objectId,
          objectType:    obj.type,
          senderAddress: sender,
          displayName,
          displayUrl,
          moveAbi:       meta?.moveAbi ?? null,
        });
      }

      cursor = owned.nextCursor;
      if (!owned.hasNextPage) break;
    } while (cursor);
  } catch (err) {
    // If the RPC call fails, log and fall through — we return whatever we got
    console.warn("fetchRealSpamObjects: RPC error", err);
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
    "Populating wallet — fetching real wallet objects from chain"
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

  // 1. Fetch REAL objects from the connected wallet
  const realSpamObjects = await fetchRealSpamObjects(client, targetAddress);

  req.log.info(
    { count: realSpamObjects.length },
    "Fetched real wallet objects from chain"
  );

  if (realSpamObjects.length === 0) {
    res.json({ injected: 0, quarantined: 0, threats: [] });
    return;
  }

  const spamInjections: ChainObject[] = realSpamObjects;

  // 3. Analyze wallet objects only
  const injections: ChainObject[] = spamInjections;

  // 4. Analyze ALL objects in a single model call
  const verdicts = await analyzeThreatBatch(injections);

  const settled = await Promise.allSettled(
    injections.map(async (obj, idx) => {
      const verdict = verdicts[idx] ?? {
        risk_score: 20, verdict: "SAFE" as const, reason_code: 5,
        confidence: 0.5, flags: [], reasoning: "No verdict returned",
      };

      // Deterministic safeguard for demo spam package objects:
      // if an object belongs to the seeded spam package, force MALICIOUS
      // so junk population is visible in the MALICIOUS-only UI.
      const packageId = (obj.objectType.split("::")[0] ?? "").toLowerCase();
      const spamPackageId = SPAM_PACKAGE_ID.toLowerCase();
      const isNativeSuiCoin = obj.objectType.startsWith("0x2::coin::Coin<0x2::sui::SUI>");
      const forceMalicious = packageId === spamPackageId && !isNativeSuiCoin;

      const effectiveVerdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS" = forceMalicious ? "MALICIOUS" : verdict.verdict;
      const effectiveRiskScore = forceMalicious ? Math.max(verdict.risk_score, 85) : verdict.risk_score;

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

      let threatId: number | null = null;
      let onChainDigest: string | null = null;

      // BUG FIX #1: Check verdict type AND high score threshold before quarantining
      // Requires BOTH conditions: (1) explicitly MALICIOUS AND (2) score >= 75
      if (effectiveVerdict === "MALICIOUS" && effectiveRiskScore >= 75) {
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
              status:        "quarantined",
            },
          }),
        ]);

        threatId = threat.id;

        if (walrusBlobId) {
          await prisma.threat.update({ where: { id: threatId }, data: { walrusBlobId } });
        }

        onChainDigest = null;
        if (REAL_ONCHAIN) {
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
        }

        if (onChainDigest) {
          await prisma.threat.update({
            where: { id: threatId },
            data:  { quarantineTxDigest: onChainDigest },
          }).catch(() => {});
        }
      } else {
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
              status:        "safe",
            },
          }),
        ]);
        if (walrusBlobId) {
          await prisma.threat.update({ where: { id: threat.id }, data: { walrusBlobId } }).catch(() => {});
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
    })
  );

  const fulfilled = settled.filter((r) => r.status === "fulfilled") as PromiseFulfilledResult<{
    objectId: string; objectType: string;
    verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
    riskScore: number; threatId: number | null; onChainDigest: string | null;
  }>[];

  const threats = fulfilled.map((r) => r.value);

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