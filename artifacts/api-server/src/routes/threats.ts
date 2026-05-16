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

    if (verdict.risk_score >= 65) {
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

  const updated = await prisma.threat.update({
    where: { id: params.data.id },
    data:  { status: "burned" },
  });

  res.json({
    ...updated,
    detectedAt: updated.detectedAt.toISOString(),
    updatedAt:  updated.updatedAt.toISOString(),
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

  // Burn them all in DB
  const ids = quarantined.map((t) => t.id);
  await prisma.threat.updateMany({
    where: { id: { in: ids } },
    data:  { status: "burned" },
  });

  req.log.info({ count: ids.length }, "AI deep clean complete — threats burned");

  res.json({
    cleaned: ids.length,
    threats: ids,
  });
});

export default router;