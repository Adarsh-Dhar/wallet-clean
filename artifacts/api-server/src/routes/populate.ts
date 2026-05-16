// artifacts/api-server/src/routes/populate.ts
import { Router } from "express";
import { randomBytes } from "crypto";
import { prisma } from "@workspace/db";
import { analyzeThreat } from "../lib/gemini";
import { storeThreatLog, buildThreatLog } from "../lib/walrus";
import { quarantineOnChain, isOnChainEnabled } from "../lib/onchain";

const router = Router();

const MIN_RISK_SCORE_FOR_QUARANTINE = 65;

const SPAMMER_ADDRESS =
  "0x" + "badc0ffee00000000000000000000000000000000000000000000000000000001".slice(-64);

interface SpamTemplate {
  module: string;
  name: string;
  displayName: string;
  displayUrl: string;
  moveAbi?: string;
}

const SPAM_TEMPLATES: SpamTemplate[] = [
  // -- Existing 5 --
  {
    module: "scam_airdrop",
    name: "FreeToken",
    displayName: "FREE 5000 SUI — Exclusive Airdrop",
    displayUrl: "https://free-sui-tokens.xyz/airdrop/claim",
  },
  {
    module: "phishing_kit",
    name: "WalletDrainer",
    displayName: "Official Sui Wallet Connect",
    displayUrl: "https://su\u0456.io/connect", // Cyrillic i
  },
  {
    module: "honeypot_defi",
    name: "HoneypotToken",
    displayName: "SuiGold — 10\u00d7 APY DeFi Protocol",
    displayUrl: "https://suigold-defi.xyz/stake",
    moveAbi: JSON.stringify({
      functions: [
        { name: "_drain_all", visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] },
        { name: "stake_free", visibility: "public",  params: ["address"] },
      ],
    }),
  },
  {
    module: "fake_foundation",
    name: "FounderPass",
    displayName: "Sui Foundation VIP Founder Pass",
    displayUrl: "https://sui-f0undation.com/exclusive-nft", // digit substitution
  },
  {
    module: "nft_phish",
    name: "MintPass",
    displayName: "Sui Foundation Official NFT",
    displayUrl: "https://suifoundation-nft.io/mint",
  },

  // -- New 5: one per major attack category --
  {
    module: "fake_cetus",
    name: "LPReceipt",
    displayName: "Cetus Protocol — Claim LP Rewards",
    displayUrl: "https://cetus-protocol.xyz/claim-rewards",
  },
  {
    module: "approval_phish",
    name: "ApprovalRequest",
    displayName: "Sui Wallet Verification Required",
    displayUrl: "https://verify-su\u0456wallet.com/approve", // homoglyph
    moveAbi: JSON.stringify({
      functions: [
        { name: "request_approval", visibility: "public",  params: ["address", "u64"] },
        { name: "sweep_all",        visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] },
      ],
    }),
  },
  {
    module: "dust_attack",
    name: "TrackingDust",
    displayName: "0.000001 SUI Transfer",
    displayUrl: "",
  },
  {
    module: "rug_token",
    name: "MemeCoin",
    displayName: "SuiDoge — 100x Meme Coin",
    displayUrl: "https://suidoge-token.xyz/stake",
    moveAbi: JSON.stringify({
      functions: [
        { name: "buy",            visibility: "public",  params: ["address", "u64"] },
        { name: "sell",           visibility: "public",  params: ["address", "u64"] },
        { name: "freeze_all",     visibility: "private", params: [] },
        { name: "migrate_funds",  visibility: "private", params: ["address"] },
      ],
    }),
  },
  {
    module: "fake_governance",
    name: "VoteProposal",
    displayName: "Sui DAO — Urgent Governance Vote (Expires Soon)",
    displayUrl: "https://sui-gov0rnance.io/vote", // digit substitution
  },
];

function randomObjectId(): string {
  return "0x" + randomBytes(32).toString("hex");
}

function fakePackageId(index: number): string {
  const tag = "dead" + String(index + 1).padStart(4, "0");
  return "0x" + (tag + "0".repeat(64)).slice(0, 64);
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

  req.log.info(
    { targetAddress, onChainEnabled: isOnChainEnabled() },
    "Populating wallet with synthetic spam objects"
  );

  // Legit sender (distinct from spammer) and a small set of trusted package fixtures
  const LEGIT_SENDER =
    "0x" + "00000000000000000000000000000000000000000000000000000000000000aa".slice(-64);

  interface LegitTemplate { packageId: string; module: string; name: string; displayName?: string | null; displayUrl?: string | null; moveAbi?: string | null; }
  const LEGIT_TEMPLATES: LegitTemplate[] = [
    {
      packageId: "0x0000000000000000000000000000000000000000000000000000000000000002",
      module: "coin",
      name: "Coin",
      displayName: null,
      displayUrl: null,
    },
    {
      packageId: "0x5d4b302506645c37ff133b98c4b50a744f7a58be6b040e4e4d90c5f6b74cbce5",
      module: "coin",
      name: "USDC",
      displayName: "USD Coin (USDC)",
      displayUrl: "https://www.circle.com/usdc",
    },
    {
      packageId: "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb",
      module: "pool",
      name: "Position",
      displayName: "Cetus LP Position",
      displayUrl: "https://cetus.zone",
    },
    {
      packageId: "0x000000000000000000000000000000000000000000000000000000000000dee9",
      module: "clob_v2",
      name: "Order",
      displayName: "DeepBook Order",
      displayUrl: null,
    },
    {
      packageId: "0x0000000000000000000000000000000000000000000000000000000000000002",
      module: "kiosk",
      name: "Kiosk",
      displayName: null,
      displayUrl: null,
    },
  ];

  const spamInjections = SPAM_TEMPLATES.map((tmpl, i) => ({
    objectId:      randomObjectId(),
    objectType:    `${fakePackageId(i)}::${tmpl.module}::${tmpl.name}`,
    senderAddress: SPAMMER_ADDRESS,
    displayName:   tmpl.displayName,
    displayUrl:    tmpl.displayUrl,
    moveAbi:       tmpl.moveAbi,
  }));

  const legitInjections = LEGIT_TEMPLATES.map((tmpl) => ({
    objectId:      randomObjectId(),
    objectType:    `${tmpl.packageId}::${tmpl.module}::${tmpl.name}`,
    senderAddress: LEGIT_SENDER,
    displayName:   tmpl.displayName ?? null,
    displayUrl:    tmpl.displayUrl ?? null,
    moveAbi:       tmpl.moveAbi ?? null,
  }));

  const injections = [...spamInjections, ...legitInjections];

  const settled = await Promise.allSettled(
    injections.map(async (obj) => {
      const verdict = await analyzeThreat({
        objectId:      obj.objectId,
        objectType:    obj.objectType,
        senderAddress: obj.senderAddress,
        displayName:   obj.displayName,
        displayUrl:    obj.displayUrl,
        moveAbi:       obj.moveAbi,
      });

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

      if (verdict.risk_score >= MIN_RISK_SCORE_FOR_QUARANTINE) {
        // Store to Walrus and DB in parallel
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
          await prisma.threat.update({
            where: { id: threatId },
            data:  { walrusBlobId },
          });
        }

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

        if (onChainDigest) {
          await prisma.threat
            .update({
              where: { id: threatId },
              data:  { quarantineTxDigest: onChainDigest },
            })
            .catch(() => {}); // non-fatal
        }
      } else {
        storeThreatLog(logPayload).catch(() => {});
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

  const threats = settled
    .filter(
      (r): r is PromiseFulfilledResult<{
        objectId: string; objectType: string;
        verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
        riskScore: number; threatId: number | null; onChainDigest: string | null;
      }> => r.status === "fulfilled"
    )
    .map((r) => r.value);

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