// artifacts/api-server/src/routes/populate.ts
import { Router } from "express";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { prisma } from "@workspace/db";
import { analyzeThreatBatch } from "../lib/gemini";
import { storeThreatLog, buildThreatLog } from "../lib/walrus";
import { quarantineOnChain, isOnChainEnabled } from "../lib/onchain";
import { MIN_RISK_SCORE_FOR_QUARANTINE } from "../lib/constants";

const router = Router();

// The wallet address that holds the real deployed spam objects on testnet
const SPAM_WALLET =
  process.env["SPAM_WALLET_ADDRESS"] ??
  "0x4f6a49a13da2bf444278408265c5bac6b49fab206b030663fba4167819666f32";

// Your deployed package ID from `sui client publish`
const SPAM_PACKAGE_ID =
  process.env["QUARANTINE_PACKAGE_ID"] ??
  "0xe933d9d3e69b29d0183ffbcecaacf7ec8dbc3832f99815760f0d34913c2c1ca4";

// The dust-sending throwaway address
const SPAMMER_ADDRESS =
  "0x8cb08623b2514d8e90994ac4800d5c05d01775dfec7e324150be638b74e9932e";

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

// Legitimate packages/objects we add to give the AI a balanced dataset to score
const LEGIT_INJECTIONS = [
  {
    objectId:      "0x0000000000000000000000000000000000000000000000000000000000000101",
    objectType:    "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin",
    senderAddress: "0x0000000000000000000000000000000000000000000000000000000000000002",
    displayName:   "SUI",
    displayUrl:    null,
    moveAbi:       null,
  },
  {
    objectId:      "0x0000000000000000000000000000000000000000000000000000000000000102",
    objectType:    "0x5d4b302506645c37ff133b98c4b50a744f7a58be6b040e4e4d90c5f6b74cbce5::coin::USDC",
    senderAddress: "0x5d4b302506645c37ff133b98c4b50a744f7a58be6b040e4e4d90c5f6b74cbce5",
    displayName:   "USD Coin (USDC)",
    displayUrl:    "https://www.circle.com/usdc",
    moveAbi:       null,
  },
  {
    objectId:      "0x0000000000000000000000000000000000000000000000000000000000000103",
    objectType:    "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb::pool::Position",
    senderAddress: "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb",
    displayName:   "Cetus LP Position",
    displayUrl:    "https://cetus.zone",
    moveAbi:       null,
  },
];

// ─── Fetch real spam objects from the testnet wallet ─────────────────────────

interface ChainObject {
  objectId:      string;
  objectType:    string;
  senderAddress: string;
  displayName:   string | null;
  displayUrl:    string | null;
  moveAbi:       string | null;
}

async function fetchRealSpamObjects(client: SuiJsonRpcClient): Promise<ChainObject[]> {
  const results: ChainObject[] = [];

  try {
    // Fetch all objects owned by the spam wallet
    const owned = await client.getOwnedObjects({
      owner: SPAM_WALLET,
      options: {
        showType:    true,
        showDisplay: true,
        showContent: true,
      },
    });

    for (const item of owned.data) {
      const obj = item.data;
      if (!obj || !obj.objectId || !obj.type) continue;

      // Skip system/gas objects (0x2::coin::Coin<0x2::sui::SUI> from framework)
      // unless they came from the spammer address (dust attack)
      const isCoinSUI = obj.type.includes("0x2::coin::Coin");
      const isDisplayOrPub =
        obj.type.includes("::display::Display") ||
        obj.type.includes("::package::Publisher") ||
        obj.type.includes("::package::UpgradeCap");

      if (isDisplayOrPub) continue;  // skip publishing artifacts

      // Determine sender: for dust it's the spammer, for minted objects it's our wallet
      const sender = isCoinSUI ? SPAMMER_ADDRESS : SPAM_WALLET;

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
    { targetAddress, realOnChain: REAL_ONCHAIN, onChainEnabled: isOnChainEnabled(), spamWallet: SPAM_WALLET, network: SUI_NETWORK },
    "Populating wallet — fetching real spam objects from chain"
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

  // 1. Fetch REAL spam objects from the deployed testnet wallet
  const realSpamObjects = await fetchRealSpamObjects(client);

  req.log.info(
    { count: realSpamObjects.length },
    "Fetched real spam objects from chain"
  );

  // 2. If no real objects found (e.g. network hiccup), fall back to a minimal
  //    synthetic set so the demo still works — but log loudly
  const spamInjections: ChainObject[] = realSpamObjects.length > 0
    ? realSpamObjects
    : (() => {
        req.log.warn(
          { spamWallet: SPAM_WALLET },
          "No real objects found — falling back to synthetic spam. Run `sui client call --module malicious_airdrop --function mint` to seed your wallet."
        );
        return [
          {
            objectId:      "0xfallback0001000000000000000000000000000000000000000000000000000001",
            objectType:    `${SPAM_PACKAGE_ID}::malicious_airdrop::AirdropToken`,
            senderAddress: SPAMMER_ADDRESS,
            displayName:   "5000 SUI Airdrop — Claim Expires in 24h",
            displayUrl:    "https://sui-airdrop-2026.xyz/claim",
            moveAbi:       null,
          },
        ];
      })();

  // 3. Combine with legit objects so the model has a balanced scoring set
  const injections: ChainObject[] = [...spamInjections, ...LEGIT_INJECTIONS];

  // 4. Analyze ALL objects in a single model call
  const verdicts = await analyzeThreatBatch(injections);

  const settled = await Promise.allSettled(
    injections.map(async (obj, idx) => {
      const verdict = verdicts[idx] ?? {
        risk_score: 20, verdict: "SAFE" as const, reason_code: 5,
        confidence: 0.5, flags: [], reasoning: "No verdict returned",
      };

      const logPayload = buildThreatLog({
        objectId:      obj.objectId,
        objectType:    obj.objectType,
        senderAddress: obj.senderAddress,
        displayName:   obj.displayName ?? null,
        displayUrl:    obj.displayUrl  ?? null,
        verdict:       verdict.verdict,
        riskScore:     verdict.risk_score,
        reasonCode:    verdict.reason_code,
        confidence:    verdict.confidence,
        flags:         verdict.flags,
        reasoning:     verdict.reasoning,
      });

      let threatId: number | null = null;
      let onChainDigest: string | null = null;

      // BUG FIX #1: Check verdict type AND high score threshold before quarantining
      // Requires BOTH conditions: (1) explicitly MALICIOUS AND (2) score >= 75
      if (verdict.verdict === "MALICIOUS" && verdict.risk_score >= 75) {
        const [walrusBlobId, threat] = await Promise.all([
          storeThreatLog(logPayload),
          prisma.threat.create({
            data: {
              objectId:      obj.objectId,
              objectType:    obj.objectType,
              senderAddress: obj.senderAddress,
              displayName:   obj.displayName ?? null,
              displayUrl:    obj.displayUrl  ?? null,
              riskScore:     verdict.risk_score,
              verdict:       verdict.verdict,
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
          riskScore:     verdict.risk_score,
          verdict:       verdict.verdict,
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
              displayName:   obj.displayName ?? null,
              displayUrl:    obj.displayUrl  ?? null,
              riskScore:     verdict.risk_score,
              verdict:       verdict.verdict,
              reasonCode:    verdict.reason_code,
              confidence:    verdict.confidence,
              flags:         verdict.flags,
              reasoning:     verdict.reasoning,
              status:        "safe",
            },
          }),
        ]);
        threatId = threat.id;
        if (walrusBlobId) {
          await prisma.threat.update({ where: { id: threatId }, data: { walrusBlobId } }).catch(() => {});
        }
      }

      return {
        objectId:      obj.objectId,
        objectType:    obj.objectType,
        verdict:       verdict.verdict as "SAFE" | "SUSPICIOUS" | "MALICIOUS",
        riskScore:     verdict.risk_score,
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