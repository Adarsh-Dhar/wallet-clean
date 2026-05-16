import { Router } from "express";
import { db } from "@workspace/db";
import { threatsTable, watchedWalletsTable } from "@workspace/db";
import { eq, count, avg, desc } from "drizzle-orm";
import { GetRecentActivityQueryParams } from "@workspace/api-zod";

const router = Router();

const REASON_LABELS: Record<number, string> = {
  1: "Honeypot",
  2: "Phishing",
  3: "Spoofed Address",
  4: "Spam",
  5: "Unknown",
};

// GET /stats/dashboard
router.get("/stats/dashboard", async (_req, res) => {
  const [totals] = await db
    .select({ count: count() })
    .from(threatsTable);

  const [quarantined] = await db
    .select({ count: count() })
    .from(threatsTable)
    .where(eq(threatsTable.status, "quarantined"));

  const [burned] = await db
    .select({ count: count() })
    .from(threatsTable)
    .where(eq(threatsTable.status, "burned"));

  const [released] = await db
    .select({ count: count() })
    .from(threatsTable)
    .where(eq(threatsTable.status, "released"));

  const [malicious] = await db
    .select({ count: count() })
    .from(threatsTable)
    .where(eq(threatsTable.verdict, "MALICIOUS"));

  const [suspicious] = await db
    .select({ count: count() })
    .from(threatsTable)
    .where(eq(threatsTable.verdict, "SUSPICIOUS"));

  const [safe] = await db
    .select({ count: count() })
    .from(threatsTable)
    .where(eq(threatsTable.verdict, "SAFE"));

  const [wallets] = await db
    .select({ count: count() })
    .from(watchedWalletsTable)
    .where(eq(watchedWalletsTable.isActive, true));

  const [avgScore] = await db
    .select({ avg: avg(threatsTable.riskScore) })
    .from(threatsTable);

  res.json({
    totalThreats: totals?.count ?? 0,
    quarantined: quarantined?.count ?? 0,
    burned: burned?.count ?? 0,
    released: released?.count ?? 0,
    maliciousCount: malicious?.count ?? 0,
    suspiciousCount: suspicious?.count ?? 0,
    safeCount: safe?.count ?? 0,
    walletsMonitored: wallets?.count ?? 0,
    avgRiskScore: Number(avgScore?.avg ?? 0),
  });
});

// GET /stats/activity
router.get("/stats/activity", async (req, res) => {
  const query = GetRecentActivityQueryParams.safeParse(req.query);
  const limit = query.success ? (query.data.limit ?? 10) : 10;

  const recent = await db
    .select()
    .from(threatsTable)
    .orderBy(desc(threatsTable.updatedAt))
    .limit(limit);

  const events = recent.flatMap((t) => {
    const events = [];

    // Always emit "detected"
    events.push({
      id: t.id * 10 + 1,
      type: "detected",
      objectId: t.objectId,
      objectType: t.objectType,
      verdict: t.verdict,
      riskScore: t.riskScore,
      timestamp: t.detectedAt.toISOString(),
    });

    if (t.status === "quarantined") {
      events.push({
        id: t.id * 10 + 2,
        type: "quarantined",
        objectId: t.objectId,
        objectType: t.objectType,
        verdict: t.verdict,
        riskScore: t.riskScore,
        timestamp: t.updatedAt.toISOString(),
      });
    } else if (t.status === "released") {
      events.push({
        id: t.id * 10 + 3,
        type: "released",
        objectId: t.objectId,
        objectType: t.objectType,
        verdict: t.verdict,
        riskScore: t.riskScore,
        timestamp: t.updatedAt.toISOString(),
      });
    } else if (t.status === "burned") {
      events.push({
        id: t.id * 10 + 4,
        type: "burned",
        objectId: t.objectId,
        objectType: t.objectType,
        verdict: t.verdict,
        riskScore: t.riskScore,
        timestamp: t.updatedAt.toISOString(),
      });
    }

    return events;
  });

  // Sort by timestamp desc and take limit
  events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  res.json(events.slice(0, limit));
});

// GET /stats/risk-breakdown
router.get("/stats/risk-breakdown", async (_req, res) => {
  const rows = await db
    .select({ reasonCode: threatsTable.reasonCode, count: count() })
    .from(threatsTable)
    .groupBy(threatsTable.reasonCode)
    .orderBy(threatsTable.reasonCode);

  res.json(
    rows.map((r) => ({
      reasonCode: r.reasonCode,
      label: REASON_LABELS[r.reasonCode] ?? "Unknown",
      count: r.count,
    }))
  );
});

export default router;
