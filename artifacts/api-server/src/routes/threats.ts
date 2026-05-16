import { Router } from "express";
import { db } from "@workspace/db";
import { threatsTable } from "@workspace/db";
import { eq, desc, and, SQL } from "drizzle-orm";
import {
  ListThreatsQueryParams,
  AnalyzeThreatBody,
  GetThreatParams,
  ReleaseThreatParams,
  BurnThreatParams,
} from "@workspace/api-zod";
import { analyzeThreat } from "../lib/gemini";
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

  const conditions: SQL[] = [];
  if (verdict) conditions.push(eq(threatsTable.verdict, verdict));
  if (status) conditions.push(eq(threatsTable.status, status));

  const threats = await db
    .select()
    .from(threatsTable)
    .where(conditions.length > 0 ? and(...conditions) : undefined)
    .orderBy(desc(threatsTable.detectedAt))
    .limit(limit)
    .offset(offset);

  res.json(
    threats.map((t) => ({
      ...t,
      detectedAt: t.detectedAt.toISOString(),
      updatedAt: t.updatedAt.toISOString(),
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
    // Fire AI analysis and Walrus log write in parallel where possible.
    // Walrus write starts before we have AI results, so we serialize it after.
    const verdict = await analyzeThreat({
      objectId: input.objectId,
      objectType: input.objectType,
      senderAddress: input.senderAddress,
      displayName: input.displayName,
      displayUrl: input.displayUrl,
      moveAbi: input.moveAbi,
    });

    const latencyMs = Date.now() - startMs;
    req.log.info({ latencyMs, verdict: verdict.verdict, riskScore: verdict.risk_score }, "AI analysis complete");

    // Build Walrus blob payload and store asynchronously — don't block the response
    const logPayload = buildThreatLog({
      objectId: input.objectId,
      objectType: input.objectType,
      senderAddress: input.senderAddress,
      displayName: input.displayName,
      displayUrl: input.displayUrl,
      verdict: verdict.verdict,
      riskScore: verdict.risk_score,
      reasonCode: verdict.reason_code,
      confidence: verdict.confidence,
      flags: verdict.flags,
      reasoning: verdict.reasoning,
    });

    // Auto-save if risk_score >= 65
    let savedThreatId: number | null = null;
    if (verdict.risk_score >= 65) {
      // Store to Walrus and DB concurrently
      const [walrusBlobId, dbResult] = await Promise.all([
        storeThreatLog(logPayload),
        db
          .insert(threatsTable)
          .values({
            objectId: input.objectId,
            objectType: input.objectType,
            senderAddress: input.senderAddress,
            displayName: input.displayName ?? null,
            displayUrl: input.displayUrl ?? null,
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

      savedThreatId = dbResult[0]?.id ?? null;

      // Backfill the walrus blob ID if we got one
      if (walrusBlobId && savedThreatId) {
        await db
          .update(threatsTable)
          .set({ walrusBlobId })
          .where(eq(threatsTable.id, savedThreatId));
      }
    } else {
      // Low-risk: fire-and-forget Walrus write for audit trail
      storeThreatLog(logPayload).catch(() => {
        // non-fatal
      });
    }

    res.json({
      riskScore: verdict.risk_score,
      verdict: verdict.verdict,
      reasonCode: verdict.reason_code,
      confidence: verdict.confidence,
      flags: verdict.flags,
      reasoning: verdict.reasoning,
      savedThreatId,
      latencyMs,
    });
  } catch (err) {
    req.log.error({ err }, "Threat analysis failed");
    res.status(500).json({ error: "Analysis failed" });
  }
});

// GET /threats/:id
router.get("/threats/:id", async (req, res) => {
  const params = GetThreatParams.safeParse({ id: Number(req.params["id"]) });
  if (!params.success) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  const [threat] = await db
    .select()
    .from(threatsTable)
    .where(eq(threatsTable.id, params.data.id));

  if (!threat) {
    res.status(404).json({ error: "Threat not found" });
    return;
  }

  res.json({
    ...threat,
    detectedAt: threat.detectedAt.toISOString(),
    updatedAt: threat.updatedAt.toISOString(),
  });
});

// POST /threats/:id/release
router.post("/threats/:id/release", async (req, res) => {
  const params = ReleaseThreatParams.safeParse({ id: Number(req.params["id"]) });
  if (!params.success) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  const [threat] = await db
    .select()
    .from(threatsTable)
    .where(eq(threatsTable.id, params.data.id));

  if (!threat) {
    res.status(404).json({ error: "Threat not found" });
    return;
  }

  if (threat.status !== "quarantined") {
    res.status(409).json({ error: `Cannot release asset with status "${threat.status}"` });
    return;
  }

  const [updated] = await db
    .update(threatsTable)
    .set({ status: "released", updatedAt: new Date() })
    .where(eq(threatsTable.id, params.data.id))
    .returning();

  res.json({
    ...updated,
    detectedAt: updated!.detectedAt.toISOString(),
    updatedAt: updated!.updatedAt.toISOString(),
  });
});

// POST /threats/:id/burn
router.post("/threats/:id/burn", async (req, res) => {
  const params = BurnThreatParams.safeParse({ id: Number(req.params["id"]) });
  if (!params.success) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  const [threat] = await db
    .select()
    .from(threatsTable)
    .where(eq(threatsTable.id, params.data.id));

  if (!threat) {
    res.status(404).json({ error: "Threat not found" });
    return;
  }

  if (threat.status !== "quarantined") {
    res.status(409).json({ error: `Cannot burn asset with status "${threat.status}"` });
    return;
  }

  const [updated] = await db
    .update(threatsTable)
    .set({ status: "burned", updatedAt: new Date() })
    .where(eq(threatsTable.id, params.data.id))
    .returning();

  res.json({
    ...updated,
    detectedAt: updated!.detectedAt.toISOString(),
    updatedAt: updated!.updatedAt.toISOString(),
  });
});

export default router;
