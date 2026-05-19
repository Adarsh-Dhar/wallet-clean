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
// Metadata we know about each deployed module — used to enrich real wallet objects
// fetched from the chain with display names and URLs
const KNOWN_OBJECT_META: Record<string, { displayName: string; displayUrl: string; moveAbi?: string }> = {
  // Dust attack — it's a plain Coin<SUI>, no custom metadata
  "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin": {
    displayName: "SUI",
    displayUrl:  "",
  },
};

function syntheticObjectId(index: number): string {
  return `0x${index.toString(16).padStart(64, "0")}`;
}


// ─── Synthetic Fixture Set ───────────────────────────────────────────────────
// All junk types the AI needs to classify, injected directly into the analysis
// pipeline so every threat category is always present for testing, regardless
// of what's on-chain. These are synthetic objects with fake objectIds.

function buildSyntheticFixtures(targetAddress: string): ChainObject[] {
  return [
    // 1. Fake airdrop token — urgency language + suspicious TLD
    {
      objectId:      syntheticObjectId(1),
      objectType:    "0xdead0001::scam_airdrop::FreeToken",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000001",
      displayName:   "FREE 5000 SUI — Exclusive Airdrop, Claim Expires in 24h",
      displayUrl:    "https://free-sui-tokens.xyz/airdrop/claim",
      moveAbi:       null,
    },
    // 2. Cyrillic homoglyph phishing — non-ASCII in URL
    {
      objectId:      syntheticObjectId(2),
      objectType:    "0xdead0002::phishing_kit::WalletDrainer",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000002",
      displayName:   "Official Sui Wallet Connect",
      displayUrl:    "https://su\u0456.io/connect",  // Cyrillic і
      moveAbi:       null,
    },
    // 3. Honeypot DeFi — dangerous ABI (_drain_all)
    {
      objectId:      syntheticObjectId(3),
      objectType:    "0xdead0003::honeypot_defi::HoneypotToken",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000003",
      displayName:   "SuiGold — 10x APY DeFi Protocol",
      displayUrl:    "https://suigold-defi.xyz/stake",
      moveAbi:       JSON.stringify({
        functions: [
          { name: "_drain_all",  visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] },
          { name: "stake_free",  visibility: "public",  params: ["address"] },
          { name: "withdraw",    visibility: "public",  params: ["HoneypotToken"] },
        ],
      }),
    },
    // 4. Digit-substitution domain — f0undation
    {
      objectId:      syntheticObjectId(4),
      objectType:    "0xdead0004::fake_foundation::FounderPass",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000004",
      displayName:   "Sui Foundation VIP Founder Pass",
      displayUrl:    "https://sui-f0undation.com/exclusive-nft",
      moveAbi:       null,
    },
    // 5. NFT phishing — mint URL pattern
    {
      objectId:      syntheticObjectId(5),
      objectType:    "0xdead0005::nft_phish::MintPass",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000005",
      displayName:   "Sui Foundation Official NFT",
      displayUrl:    "https://suifoundation-nft.io/mint",
      moveAbi:       null,
    },
    // 6. Protocol impersonation — fake Cetus with untrusted package
    {
      objectId:      syntheticObjectId(6),
      objectType:    "0xdead0006::fake_cetus::LPReceipt",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000006",
      displayName:   "Cetus Protocol — Claim LP Rewards",
      displayUrl:    "https://cetus-protocol.xyz/claim-rewards",
      moveAbi:       null,
    },
    // 7. Approval phish — sweep_all in ABI + Cyrillic URL
    {
      objectId:      syntheticObjectId(7),
      objectType:    "0xdead0007::approval_phish::ApprovalRequest",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000007",
      displayName:   "Sui Wallet Verification Required",
      displayUrl:    "https://verify-su\u0456wallet.com/approve",
      moveAbi:       JSON.stringify({
        functions: [
          { name: "request_approval", visibility: "public",  params: ["address", "u64"] },
          { name: "sweep_all",        visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] },
        ],
      }),
    },
    // 8. Dust attack — bulk sender, near-zero value coin
    {
      objectId:      syntheticObjectId(8),
      objectType:    "0x2::coin::Coin<0x2::sui::SUI>",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000008",
      displayName:   "0.000001 SUI Transfer",
      displayUrl:    "",
      moveAbi:       null,
    },
    // 9. Rug token — freeze_all + migrate_funds in ABI
    {
      objectId:      syntheticObjectId(9),
      objectType:    "0xdead0009::rug_token::MemeCoin",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000009",
      displayName:   "SuiDoge — 100x Meme Coin",
      displayUrl:    "https://suidoge-token.xyz/stake",
      moveAbi:       JSON.stringify({
        functions: [
          { name: "buy",           visibility: "public",  params: ["address", "u64"] },
          { name: "sell",          visibility: "public",  params: ["address", "u64"] },
          { name: "freeze_all",    visibility: "private", params: [] },
          { name: "migrate_funds", visibility: "private", params: ["address"] },
        ],
      }),
    },
    // 10. Fake governance — urgency language + digit-sub domain
    {
      objectId:      syntheticObjectId(10),
      objectType:    "0xdead000a::fake_governance::VoteProposal",
      senderAddress: "0xbadc0ffee000000000000000000000000000000000000000000000000000000a",
      displayName:   "Sui DAO — Urgent Governance Vote (Expires Soon)",
      displayUrl:    "https://sui-gov0rnance.io/vote",
      moveAbi:       null,
    },
    // 11. Spoofed LP position — impersonates real Cetus package
    {
      objectId:      syntheticObjectId(11),
      objectType:    "0xdead000b::spoofed_pool::Position",
      senderAddress: "0xbadc0ffee000000000000000000000000000000000000000000000000000000b",
      displayName:   "Cetus LP Position",
      displayUrl:    "https://cetus.zone/position/fake",
      moveAbi:       JSON.stringify({
        functions: [
          { name: "fake_mint",    visibility: "public", params: [] },
          { name: "collect_fees", visibility: "public", params: ["&Position"] },
        ],
      }),
    },
    // 12. Bridge phishing — fake Wormhole with withdraw_all
    {
      objectId:      syntheticObjectId(12),
      objectType:    "0xdead000c::fake_bridge::BridgeReceipt",
      senderAddress: "0xbadc0ffee000000000000000000000000000000000000000000000000000000c",
      displayName:   "Wormhole Bridge — Claim Bridged Tokens",
      displayUrl:    "https://wormh0le-bridge.io/claim",
      moveAbi:       JSON.stringify({
        functions: [
          { name: "claim",        visibility: "public",  params: ["address"] },
          { name: "withdraw_all", visibility: "private", params: ["address"] },
        ],
      }),
    },
    // 13. Fake staking reward — Bluefin impersonation
    {
      objectId:      syntheticObjectId(13),
      objectType:    "0xdead000d::fake_staking::RewardTicket",
      senderAddress: "0xbadc0ffee000000000000000000000000000000000000000000000000000000d",
      displayName:   "Bluefin Staking Reward — Claim Now",
      displayUrl:    "https://bluefin-rewards.xyz/claim",
      moveAbi:       null,
    },
    // 14. Multiple dust coins — same coin type, different objects (tests merge routing)
    {
      objectId:      syntheticObjectId(14),
      objectType:    "0x2::coin::Coin<0x2::sui::SUI>",
      senderAddress: "0xbadc0ffee000000000000000000000000000000000000000000000000000000e",
      displayName:   "0.000002 SUI Transfer",
      displayUrl:    "",
      moveAbi:       null,
    },
    {
      objectId:      syntheticObjectId(15),
      objectType:    "0x2::coin::Coin<0x2::sui::SUI>",
      senderAddress: "0xbadc0ffee000000000000000000000000000000000000000000000000000000f",
      displayName:   "0.000003 SUI Transfer",
      displayUrl:    "",
      moveAbi:       null,
    },
    // 15. SAFE object — real Sui system coin (AI must not flag this)
    {
      objectId:      syntheticObjectId(16),
      objectType:    "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0x2::sui::SUI>",
      senderAddress: targetAddress,
      displayName:   "SUI",
      displayUrl:    null,
      moveAbi:       null,
    },
    // 16. SAFE object — real DeepBook order (AI must recognise trusted package)
    {
      objectId:      syntheticObjectId(17),
      objectType:    "0x000000000000000000000000000000000000000000000000000000000000dee9::clob_v2::Order",
      senderAddress: targetAddress,
      displayName:   "DeepBook Order",
      displayUrl:    null,
      moveAbi:       null,
    },
  ];
}

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
    "Populating wallet with synthetic fixtures + real wallet objects"
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

  // Build the full synthetic fixture set with targetAddress available
  const syntheticFixtures: ChainObject[] = buildSyntheticFixtures(targetAddress);

  // Fetch real wallet objects — append to synthetics so both are analyzed
  const realObjects = await fetchRealSpamObjects(client, targetAddress);

  // Deduplicate: if a real object has the same objectType as a synthetic one,
  // prefer the synthetic object coverage unless a real object has the exact same objectId.
  const realObjectIds = new Set(realObjects.map((o) => o.objectId));
  const dedupedSynthetics = syntheticFixtures.filter((s) => !realObjectIds.has(s.objectId));

  const injections: ChainObject[] = [...dedupedSynthetics, ...realObjects];

  req.log.info(
    { synthetic: dedupedSynthetics.length, real: realObjects.length, total: injections.length },
    "Populating wallet with full fixture set + real objects"
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