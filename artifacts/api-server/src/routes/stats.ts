// artifacts/api-server/src/routes/stats.ts
import { Router } from "express";
import { prisma } from "@workspace/db";
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
  // Run all counts in parallel with Promise.all for performance
  const [
    totalThreats,
    quarantined,
    burned,
    released,
    maliciousCount,
    suspiciousCount,
    safeCount,
    walletsMonitored,
    avgResult,
  ] = await Promise.all([
    prisma.threat.count(),
    prisma.threat.count({ where: { status:  "quarantined" } }),
    prisma.threat.count({ where: { status:  "burned"      } }),
    prisma.threat.count({ where: { status:  "released"    } }),
    prisma.threat.count({ where: { verdict: "MALICIOUS"   } }),
    prisma.threat.count({ where: { verdict: "SUSPICIOUS"  } }),
    prisma.threat.count({ where: { verdict: "SAFE"        } }),
    prisma.watchedWallet.count({ where: { isActive: true } }),
    prisma.threat.aggregate({ _avg: { riskScore: true } }),
  ]);

  res.json({
    totalThreats,
    quarantined,
    burned,
    released,
    maliciousCount,
    suspiciousCount,
    safeCount,
    walletsMonitored,
    avgRiskScore: avgResult._avg.riskScore ?? 0,
  });
});

// GET /stats/activity
router.get("/stats/activity", async (req, res) => {
  const query = GetRecentActivityQueryParams.safeParse(req.query);
  const limit = query.success ? (query.data.limit ?? 10) : 10;

  const recent = await prisma.threat.findMany({
    orderBy: { updatedAt: "desc" },
    take: limit,
  });

  const events = recent.flatMap((t) => {
    const evts = [];

    evts.push({
      id:         t.id * 10 + 1,
      type:       "detected",
      objectId:   t.objectId,
      objectType: t.objectType,
      verdict:    t.verdict,
      riskScore:  t.riskScore,
      timestamp:  t.detectedAt.toISOString(),
    });

    if (t.status === "quarantined") {
      evts.push({ id: t.id * 10 + 2, type: "quarantined", objectId: t.objectId, objectType: t.objectType, verdict: t.verdict, riskScore: t.riskScore, timestamp: t.updatedAt.toISOString() });
    } else if (t.status === "released") {
      evts.push({ id: t.id * 10 + 3, type: "released",    objectId: t.objectId, objectType: t.objectType, verdict: t.verdict, riskScore: t.riskScore, timestamp: t.updatedAt.toISOString() });
    } else if (t.status === "burned") {
      evts.push({ id: t.id * 10 + 4, type: "burned",      objectId: t.objectId, objectType: t.objectType, verdict: t.verdict, riskScore: t.riskScore, timestamp: t.updatedAt.toISOString() });
    }

    return evts;
  });

  events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  res.json(events.slice(0, limit));
});

// GET /stats/risk-breakdown
router.get("/stats/risk-breakdown", async (_req, res) => {
  const rows = await prisma.threat.groupBy({
    by:      ["reasonCode"],
    _count:  { reasonCode: true },
    orderBy: { reasonCode: "asc" },
  });

  res.json(
    rows.map((r) => ({
      reasonCode: r.reasonCode,
      label:      REASON_LABELS[r.reasonCode] ?? "Unknown",
      count:      r._count.reasonCode,
    }))
  );
});

export default router;