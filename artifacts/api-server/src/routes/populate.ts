/**
 * POST /populate-wallet
 *
 * Seeds a target wallet with 5 synthetic spam/phishing objects for demo and
 * testing purposes. Each object is run through the full AI analysis pipeline
 * (Gemini or mock fallback). High-risk objects are quarantined in the DB,
 * logged to Walrus, and optionally recorded on-chain via the deployed
 * quarantine_vault Move contract.
 */

import { Router } from "express";
import { randomBytes } from "crypto";
import { db } from "@workspace/db";
import { threatsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
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
    // Cyrillic 'і' (U+0456) — Unicode homoglyph attack
    displayUrl: "https://su\u0456.io/connect",
  },
  {
    module: "honeypot_defi",
    name: "HoneypotToken",
    displayName: "SuiGold — 10\u00d7 APY DeFi Protocol",
    displayUrl: "https://suigold-defi.xyz/stake",
    moveAbi: JSON.stringify({
      functions: [
        { name: "_drain_all", visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] },
        { name: "stake_free", visibility: "public", params: ["address"] },
      ],
    }),
  },
  {
    module: "fake_foundation",
    name: "FounderPass",
    displayName: "Sui Foundation VIP Founder Pass",
    // Digit-0 homoglyph: f0undation
    displayUrl: "https://sui-f0undation.com/exclusive-nft",
  },
  {
    module: "nft_phish",
    name: "MintPass",
    displayName: "Sui Foundation Official NFT",
    displayUrl: "https://suifoundation-nft.io/mint",
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

  const injections = SPAM_TEMPLATES.map((tmpl, i) => ({
    objectId: randomObjectId(),
    objectType: `${fakePackageId(i)}::${tmpl.module}::${tmpl.name}`,
    senderAddress: SPAMMER_ADDRESS,
    displayName: tmpl.displayName,
    displayUrl: tmpl.displayUrl,
    moveAbi: tmpl.moveAbi,
  }));

  // Fan out all 5 analyses in parallel — they queue through the Gemini rate limiter
  const settled = await Promise.allSettled(
    injections.map(async (obj) => {
      const verdict = await analyzeThreat({
        objectId: obj.objectId,
        objectType: obj.objectType,
        senderAddress: obj.senderAddress,
        displayName: obj.displayName,
        displayUrl: obj.displayUrl,
        moveAbi: obj.moveAbi,
      });

      const logPayload = buildThreatLog({
        objectId: obj.objectId,
        objectType: obj.objectType,
        senderAddress: obj.senderAddress,
        displayName: obj.displayName ?? null,
        displayUrl: obj.displayUrl ?? null,
        verdict: verdict.verdict,
        riskScore: verdict.risk_score,
        reasonCode: verdict.reason_code,
        confidence: verdict.confidence,
        flags: verdict.flags,
        reasoning: verdict.reasoning,
      });

      let threatId: number | null = null;
      let onChainDigest: string | null = null;

      if (verdict.risk_score >= MIN_RISK_SCORE_FOR_QUARANTINE) {
        // 1. Store to Walrus and DB in parallel
        const [walrusBlobId, dbResult] = await Promise.all([
          storeThreatLog(logPayload),
          db
            .insert(threatsTable)
            .values({
              objectId: obj.objectId,
              objectType: obj.objectType,
              senderAddress: obj.senderAddress,
              displayName: obj.displayName ?? null,
              displayUrl: obj.displayUrl ?? null,
              riskScore: verdict.risk_score,
              verdict: verdict.verdict,
              reasonCode: verdict.reason_code,
              confidence: verdict.confidence,
              flags: verdict.flags,
              reasoning: verdict.reasoning,
              status: "quarantined",
            })
            .returning({ id: threatsTable.id }),
        ]);

        threatId = dbResult[0]?.id ?? null;

        // 2. Update DB row with Walrus blob ID
        if (walrusBlobId && threatId) {
          await db
            .update(threatsTable)
            .set({ walrusBlobId })
            .where(eq(threatsTable.id, threatId));
        }

        // 3. Record on-chain via the deployed quarantine_vault contract (non-fatal)
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

        // 4. Persist on-chain digest to DB if we got one
        if (onChainDigest && threatId) {
          await db
            .update(threatsTable)
            .set({ quarantineTxDigest: onChainDigest })
            .where(eq(threatsTable.id, threatId))
            .catch(() => {
              // Column may not exist yet if migration hasn't run — non-fatal
            });
        }
      } else {
        // Fire-and-forget audit log for low-risk objects
        storeThreatLog(logPayload).catch(() => {});
      }

      return {
        objectId: obj.objectId,
        objectType: obj.objectType,
        verdict: verdict.verdict as "SAFE" | "SUSPICIOUS" | "MALICIOUS",
        riskScore: verdict.risk_score,
        threatId,
        onChainDigest,
      };
    })
  );

  const threats = settled
    .filter(
      (
        r
      ): r is PromiseFulfilledResult<{
        objectId: string;
        objectType: string;
        verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
        riskScore: number;
        threatId: number | null;
        onChainDigest: string | null;
      }> => r.status === "fulfilled"
    )
    .map((r) => r.value);

  const quarantined = threats.filter((t) => t.threatId !== null).length;
  const onChainDigests = threats.map((t) => t.onChainDigest).filter(Boolean);

  req.log.info(
    { injected: threats.length, quarantined, onChainCount: onChainDigests.length, targetAddress },
    "Wallet population complete"
  );

  res.json({
    injected: threats.length,
    quarantined,
    txDigest: callerTxDigest ?? null,
    // First on-chain digest (or null) for the UI toast
    onChainDigest: onChainDigests[0] ?? null,
    threats,
  });
});

export default router;