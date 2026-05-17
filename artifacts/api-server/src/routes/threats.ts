// artifacts/api-server/src/routes/threats.ts
import { Router } from "express";
import { prisma } from "@workspace/db";
import {
  ListThreatsQueryParams,
  AnalyzeThreatBody,
  GetThreatParams,
  ReleaseThreatParams,
  BurnThreatParams,
} from "@workspace/api-zod";
import { analyzeThreat, extractStaticSignals } from "../lib/gemini";
import { storeThreatLog, buildThreatLog } from "../lib/walrus";
import { quarantineOnChain, isOnChainEnabled, sendToDeadOnChain } from "../lib/onchain";
import { MIN_RISK_SCORE_FOR_QUARANTINE } from "../lib/constants";

const router = Router();

// GET /threats
router.get("/threats", async (req, res) => {
  const query = ListThreatsQueryParams.safeParse(req.query);
  if (!query.success) {
    res.status(400).json({ error: "Invalid query params" });
    return;
  }

  const { verdict, status, limit = 50, offset = 0 } = query.data;

  const threats = await prisma.threat.findMany({
    where: {
      ...(verdict ? { verdict } : {}),
      ...(status  ? { status }  : {}),
    },
    orderBy: { detectedAt: "desc" },
    take: limit,
    skip: offset,
  });

  res.json(
    threats.map((t) => ({
      ...t,
      detectedAt: t.detectedAt.toISOString(),
      updatedAt:  t.updatedAt.toISOString(),
    }))
  );
});

// POST /threats/analyze
router.post("/threats/analyze", async (req, res) => {
  const body = AnalyzeThreatBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: "Invalid request body" });
    return;
  }

  const input = body.data;
  const startMs = Date.now();

  try {
    const staticSignals = extractStaticSignals(input);
    req.log.info({ staticSignals }, "Static pre-filter signals");

    const verdict = await analyzeThreat({
      objectId:      input.objectId,
      objectType:    input.objectType,
      senderAddress: input.senderAddress,
      displayName:   input.displayName,
      displayUrl:    input.displayUrl,
      moveAbi:       input.moveAbi,
    });

    const latencyMs = Date.now() - startMs;
    req.log.info(
      { latencyMs, verdict: verdict.verdict, riskScore: verdict.risk_score },
      "AI analysis complete"
    );

    const logPayload = buildThreatLog({
      objectId:      input.objectId,
      objectType:    input.objectType,
      senderAddress: input.senderAddress,
      displayName:   input.displayName,
      displayUrl:    input.displayUrl,
      verdict:       verdict.verdict,
      riskScore:     verdict.risk_score,
      reasonCode:    verdict.reason_code,
      confidence:    verdict.confidence,
      flags:         verdict.flags,
      reasoning:     verdict.reasoning,
    });

    let savedThreatId: number | null = null;
    let onChainDigest: string | null = null;

    // BUG FIX #1: Check verdict type AND high score threshold before quarantining
    // Requires BOTH conditions: (1) explicitly MALICIOUS AND (2) score >= 75
    // Prevents false positives where SAFE objects might have borderline scores
    if (verdict.verdict === "MALICIOUS" && verdict.risk_score >= 75) {
      const [walrusBlobId, threat] = await Promise.all([
        storeThreatLog(logPayload),
        prisma.threat.create({
          data: {
            objectId:      input.objectId,
            objectType:    input.objectType,
            senderAddress: input.senderAddress,
            displayName:   input.displayName ?? null,
            displayUrl:    input.displayUrl   ?? null,
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

      savedThreatId = threat.id;

      if (walrusBlobId) {
        await prisma.threat.update({
          where: { id: savedThreatId },
          data:  { walrusBlobId },
        });
      }

      // BUG FIX #4: Add Sui integration — record quarantine on-chain
      if (isOnChainEnabled()) {
        try {
          onChainDigest = await quarantineOnChain({
            objectId:      input.objectId,
            objectType:    input.objectType,
            senderAddress: input.senderAddress,
            riskScore:     verdict.risk_score,
            verdict:       verdict.verdict,
            reasonCode:    verdict.reason_code,
            confidence:    verdict.confidence,
            walrusBlobId:  walrusBlobId ?? "",
          });

          if (onChainDigest) {
            await prisma.threat.update({ where: { id: savedThreatId! }, data: { quarantineTxDigest: onChainDigest } }).catch(() => {});
          }
        } catch (err) {
          req.log.warn({ err, objectId: input.objectId }, "On-chain quarantine failed (non-blocking)");
        }
      }
    } else {
      storeThreatLog(logPayload).catch(() => {});
    }

    res.json({
      riskScore:    verdict.risk_score,
      verdict:      verdict.verdict,
      reasonCode:   verdict.reason_code,
      confidence:   verdict.confidence,
      flags:        verdict.flags,
      reasoning:    verdict.reasoning,
      savedThreatId,
      onChainDigest,
      latencyMs,
      staticSignals,
    });
  } catch (err) {
    req.log.error({ err }, "Threat analysis failed");
    res.status(500).json({ error: "Analysis failed" });
  }
});

// GET /threats/:id
router.get("/threats/:id", async (req, res) => {
  const rawId = Number(req.params["id"]);
  if (!Number.isFinite(rawId) || !Number.isInteger(rawId) || rawId < 1 || rawId > 2147483647) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }
  const params = GetThreatParams.safeParse({ id: rawId });
  if (!params.success) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  const threat = await prisma.threat.findUnique({
    where: { id: params.data.id },
  });

  if (!threat) {
    res.status(404).json({ error: "Threat not found" });
    return;
  }

  res.json({
    ...threat,
    detectedAt: threat.detectedAt.toISOString(),
    updatedAt:  threat.updatedAt.toISOString(),
  });
});

// POST /threats/:id/release
router.post("/threats/:id/release", async (req, res) => {
  const rawId = Number(req.params["id"]);
  if (!Number.isFinite(rawId) || !Number.isInteger(rawId) || rawId < 1 || rawId > 2147483647) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }
  const params = ReleaseThreatParams.safeParse({ id: rawId });
  if (!params.success) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  const existing = await prisma.threat.findUnique({ where: { id: params.data.id } });
  if (!existing) {
    res.status(404).json({ error: "Threat not found" });
    return;
  }
  if (existing.status !== "quarantined") {
    res.status(409).json({ error: `Cannot release asset with status "${existing.status}"` });
    return;
  }

  const updated = await prisma.threat.update({
    where: { id: params.data.id },
    data:  { status: "released" },
  });

  res.json({
    ...updated,
    detectedAt: updated.detectedAt.toISOString(),
    updatedAt:  updated.updatedAt.toISOString(),
  });
});

// POST /threats/:id/burn
router.post("/threats/:id/burn", async (req, res) => {
  const rawId = Number(req.params["id"]);
  if (!Number.isFinite(rawId) || !Number.isInteger(rawId) || rawId < 1 || rawId > 2147483647) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }
  const params = BurnThreatParams.safeParse({ id: rawId });
  if (!params.success) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  const existing = await prisma.threat.findUnique({ where: { id: params.data.id } });
  if (!existing) {
    res.status(404).json({ error: "Threat not found" });
    return;
  }
  if (existing.status !== "quarantined") {
    res.status(409).json({ error: `Cannot burn asset with status "${existing.status}"` });
    return;
  }

  // 1. Flip DB status first so the UI updates immediately
  const updated = await prisma.threat.update({
    where: { id: params.data.id },
    data:  { status: "burned" },
  });

  // 2. Attempt real on-chain object disposal (non-blocking — failure does not
  //    roll back the DB status; the metadata burn is the source of truth)
  let burnTxDigest: string | null = null;
  if (isOnChainEnabled()) {
    burnTxDigest = await sendToDeadOnChain({
      objectId:   existing.objectId,
      objectType: existing.objectType,
    }).catch(() => null);

    if (burnTxDigest) {
      await prisma.threat.update({
        where: { id: params.data.id },
        data:  { burnTxDigest },
      }).catch(() => {});
    } else {
      req.log.warn(
        { objectId: existing.objectId },
        "on-chain send_to_dead failed or skipped — DB burn still recorded"
      );
    }
  }

  res.json({
    ...updated,
    detectedAt:    updated.detectedAt.toISOString(),
    updatedAt:     updated.updatedAt.toISOString(),
    burnTxDigest,
    onChainBurned: burnTxDigest !== null,
  });
});

// POST /clean-wallet — AI-confirmed bulk burn of all quarantined threats
router.post("/clean-wallet", async (req, res) => {
  const quarantined = await prisma.threat.findMany({
    where: { status: "quarantined" },
  });

  if (quarantined.length === 0) {
    res.json({ cleaned: 0, threats: [] });
    return;
  }

  const ids = quarantined.map((t) => t.id);

  // 1. Flip all to burned in DB atomically
  await prisma.threat.updateMany({
    where: { id: { in: ids } },
    data:  { status: "burned" },
  });

  req.log.info({ count: ids.length }, "AI deep clean — DB records burned");

  // 2. Fire real on-chain disposal for each, sequentially to avoid gas races
  const results: Array<{ id: number; objectId: string; burnTxDigest: string | null }> = [];

  if (isOnChainEnabled()) {
    for (const threat of quarantined) {
      const burnTxDigest = await sendToDeadOnChain({
        objectId:   threat.objectId,
        objectType: threat.objectType,
      }).catch(() => null);

      if (burnTxDigest) {
        await prisma.threat.update({
          where: { id: threat.id },
          data:  { burnTxDigest },
        }).catch(() => {});
      }

      results.push({ id: threat.id, objectId: threat.objectId, burnTxDigest });
    }
  } else {
    // On-chain not configured — just record DB-only burns
    quarantined.forEach((t) =>
      results.push({ id: t.id, objectId: t.objectId, burnTxDigest: null })
    );
  }

  res.json({
    cleaned:      ids.length,
    onChainBurned: results.filter((r) => r.burnTxDigest !== null).length,
    threats:      results,
  });
});

export default router;