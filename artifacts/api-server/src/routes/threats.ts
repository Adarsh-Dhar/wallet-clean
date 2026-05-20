// artifacts/api-server/src/routes/threats.ts
import { Router } from "express";
import { prisma } from "@workspace/db";
import {
  ListThreatsQueryParams,
  AnalyzeThreatBody,
  GetThreatParams,
  ReleaseThreatParams,
  BurnThreatParams,
  CleanWalletBody,
} from "@workspace/api-zod";
import { analyzeThreat, extractStaticSignals } from "../lib/gemini";
import { storeThreatLog, buildThreatLog } from "../lib/walrus";
import {
  quarantineOnChain,
  isOnChainEnabled,
  sendToDeadOnChain,
  mergeDustOnChain,
  fetchWalletActivityObjects,
  getSuiRpcUrl,
} from "../lib/onchain";
import { MIN_RISK_SCORE_FOR_QUARANTINE } from "../lib/constants";

async function fetchObjectAbilities(objectType: string): Promise<string[]> {
  try {
    const parts = objectType.split("::");
    const pkgAddress = parts[0];
    const moduleName = parts[1];
    const structName = parts[2]?.split("<")[0];
    if (!pkgAddress || !moduleName || !structName) return [];

    const response = await fetch(getSuiRpcUrl(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "sui_getNormalizedMoveModulesByPackage",
        params: [pkgAddress],
      }),
    });
    const json = (await response.json().catch(() => null)) as any;
    return json?.result?.[moduleName]?.structs?.[structName]?.abilities?.abilities ?? [];
  } catch {
    return [];
  }
}

async function fetchCoinObjects(
  walletAddress: string,
  coinType: string
): Promise<{ coinObjectId: string; balance: string }[]> {
  try {
    const response = await fetch(getSuiRpcUrl(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "suix_getCoins",
        params: [walletAddress, coinType, null, 50],
      }),
    });
    const json = (await response.json().catch(() => null)) as any;
    const coins: { coinObjectId: string; balance: string }[] = json?.result?.data ?? [];
    coins.sort((a, b) => (BigInt(b.balance) > BigInt(a.balance) ? 1 : -1));
    return coins;
  } catch {
    return [];
  }
}

const router = Router();

// GET /threats
router.get("/threats", async (req, res) => {
  const query = ListThreatsQueryParams.safeParse(req.query);
  if (!query.success) {
    res.status(400).json({ error: "Invalid query params" });
    return;
  }

  const queryData = query.data as typeof query.data & { walletAddress?: string };
  const { verdict, status, walletAddress, limit = 50, offset = 0 } = queryData;

  const threats = await prisma.threat.findMany({
    where: {
      ...(verdict ? { verdict } : {}),
      ...(status  ? { status }  : {}),
      ...(walletAddress ? { walletAddress: { equals: walletAddress, mode: "insensitive" } } : {}),
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
    if (
      (verdict.verdict === "MALICIOUS" || verdict.verdict === "SUSPICIOUS") &&
      verdict.risk_score >= 75
    ) {
      const [walrusBlobId, threat] = await Promise.all([
        storeThreatLog(logPayload),
        prisma.threat.create({
          data: {
            objectId:      input.objectId,
            objectType:    input.objectType,
            senderAddress: input.senderAddress,
            displayName:   input.displayName ?? null,
            displayUrl:    input.displayUrl   ?? null,
            walletAddress: input.walletAddress ?? null,
            riskScore:     verdict.risk_score,
            verdict:       verdict.verdict,
            reasonCode:    verdict.reason_code,
            confidence:    verdict.confidence,
            flags:         verdict.flags,
            reasoning:     verdict.reasoning,
            cleanMethod:   verdict.clean_method,
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

  const existing = (await prisma.threat.findUnique({ where: { id: params.data.id } })) as any;
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

  const existing = (await prisma.threat.findUnique({ where: { id: params.data.id } })) as any;
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
    if (existing.cleanMethod === "merge_dust") {
      const coinTypeMatch = existing.objectType.match(/::coin::Coin<(.+)>$/);
      const coinType = coinTypeMatch?.[1] ?? null;

      if (coinType && existing.walletAddress) {
        const coins = await fetchCoinObjects(existing.walletAddress, coinType);
        if (coins.length >= 2) {
          burnTxDigest = await mergeDustOnChain({
            coinType,
            primaryCoinId: coins[0].coinObjectId,
            dustCoinIds: coins.slice(1).map((coin) => coin.coinObjectId),
          }).catch(() => null);
        } else if (coins.length === 1) {
          const abilities = existing.hasStoreAbility
            ? ["Store"]
            : await fetchObjectAbilities(existing.objectType);
          if (abilities.map((ability) => ability.toLowerCase()).includes("store")) {
            burnTxDigest = await sendToDeadOnChain({
              objectId: existing.objectId,
              objectType: existing.objectType,
            }).catch(() => null);
          }
        }
      }
    } else if (existing.cleanMethod === "transfer_to_dead" || existing.cleanMethod === "vault_burn") {
      const abilities = existing.hasStoreAbility
        ? ["Store"]
        : await fetchObjectAbilities(existing.objectType);
      if (abilities.map((ability) => ability.toLowerCase()).includes("store")) {
        burnTxDigest = await sendToDeadOnChain({
          objectId: existing.objectId,
          objectType: existing.objectType,
        }).catch(() => null);
      } else {
        req.log.warn(
          { objectId: existing.objectId, abilities },
          "Object lacks store ability — send_to_dead skipped"
        );
      }
    }

    if (burnTxDigest) {
      await prisma.threat.update({
        where: { id: params.data.id },
        data:  { burnTxDigest },
      }).catch(() => {});
    } else {
      req.log.warn(
        { objectId: existing.objectId, cleanMethod: existing.cleanMethod },
        "on-chain clean failed or skipped - DB burn still recorded"
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

// POST /clean-wallet — wallet-signed bulk burn confirmation
router.post("/clean-wallet", async (req, res) => {
  const body = CleanWalletBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: "Invalid request body" });
    return;
  }

  const requestedIds = [...new Set(body.data.threatIds)];
  const digest = body.data.burnTxDigest;
  const authAddress = res.locals.authSession?.address;

  const quarantined = await prisma.threat.findMany({
    where: {
      id: { in: requestedIds },
      status: "quarantined",
      ...(authAddress ? { walletAddress: { equals: authAddress, mode: "insensitive" } } : {}),
    },
    select: {
      id: true,
      objectId: true,
      objectType: true,
    },
  });

  if (authAddress && quarantined.length < requestedIds.length) {
    res.status(403).json({ error: "Access denied: Not all threats belong to your wallet" });
    return;
  }

  if (quarantined.length === 0) {
    res.json({ cleaned: 0, onChainBurned: 0, threats: [] });
    return;
  }

  const idsToUpdate = quarantined.map((t) => t.id);

  await prisma.threat.updateMany({
    where: {
      id: { in: idsToUpdate },
      status: "quarantined",
    },
    data: {
      status: "burned",
      burnTxDigest: digest,
    },
  });

  req.log.info({ count: idsToUpdate.length, digest }, "Wallet-signed deep clean recorded");

  // Best-effort server-side cleanup for every selected object.
  // The wallet-signed PTB remains the source of truth for disposal.
  let serverBurnedCount = 0;
  if (isOnChainEnabled()) {
    const deadThreats = await prisma.threat.findMany({
      where: {
        id: { in: idsToUpdate },
        cleanMethod: { in: ["transfer_to_dead", "vault_burn"] },
      },
      select: { id: true, objectId: true, objectType: true, hasStoreAbility: true },
    });

    const dustThreats = await prisma.threat.findMany({
      where: { id: { in: idsToUpdate }, cleanMethod: "merge_dust" },
      select: { id: true, objectId: true, objectType: true, walletAddress: true, hasStoreAbility: true },
    });

    const dustGroups = Object.values(
      dustThreats.reduce((acc, threat) => {
        const coinTypeMatch = threat.objectType.match(/::coin::Coin<(.+)>$/);
        const coinType = coinTypeMatch?.[1] ?? null;
        if (!coinType || !threat.walletAddress) return acc;
        const key = `${threat.walletAddress}::${coinType}`;
        if (!acc[key]) {
          acc[key] = { walletAddress: threat.walletAddress, coinType, threats: [] as typeof dustThreats };
        }
        acc[key].threats.push(threat);
        return acc;
      }, {} as Record<string, { walletAddress: string; coinType: string; threats: typeof dustThreats }>)
    );

    const settled = await Promise.allSettled([
      ...deadThreats.map(async (threat) => {
        const abilities = threat.hasStoreAbility
          ? ["Store"]
          : await fetchObjectAbilities(threat.objectType);
        if (!abilities.map((ability) => ability.toLowerCase()).includes("store")) {
          req.log.warn({ objectId: threat.objectId }, "Object lacks store ability — send_to_dead skipped");
          return null;
        }

        const burnDigest = await sendToDeadOnChain({
          objectId: threat.objectId,
          objectType: threat.objectType,
        }).catch(() => null);

        if (burnDigest) {
          await prisma.threat.update({
            where: { id: threat.id },
            data:  { burnTxDigest: burnDigest },
          }).catch(() => {});
        }
        return burnDigest;
      }),
      ...dustGroups.map(async ({ walletAddress, coinType, threats }) => {
        const coins = await fetchCoinObjects(walletAddress, coinType);
        if (coins.length >= 2) {
          const burnDigest = await mergeDustOnChain({
            coinType,
            primaryCoinId: coins[0].coinObjectId,
            dustCoinIds: coins.slice(1).map((coin) => coin.coinObjectId),
          }).catch(() => null);

          if (burnDigest) {
            await prisma.threat.updateMany({
              where: { id: { in: threats.map((threat) => threat.id) } },
              data:  { burnTxDigest: burnDigest },
            }).catch(() => {});
          }
          return burnDigest;
        }

        if (coins.length === 1) {
          const firstThreat = threats[0];
          const abilities = firstThreat.hasStoreAbility
            ? ["Store"]
            : await fetchObjectAbilities(firstThreat.objectType);
          if (!abilities.map((ability) => ability.toLowerCase()).includes("store")) {
            return null;
          }

          const burnDigest = await sendToDeadOnChain({
            objectId: firstThreat.objectId,
            objectType: firstThreat.objectType,
          }).catch(() => null);
          if (burnDigest) {
            await prisma.threat.updateMany({
              where: { id: { in: threats.map((threat) => threat.id) } },
              data:  { burnTxDigest: burnDigest },
            }).catch(() => {});
          }
          return burnDigest;
        }

        req.log.warn({ walletAddress, coinType }, "merge_dust skipped - no coin objects found");
        return null;
      }),
    ]);

    serverBurnedCount = settled.filter(
      (result) => result.status === "fulfilled" && result.value !== null
    ).length;
  }

  res.json({
    cleaned: idsToUpdate.length,
    onChainBurned: serverBurnedCount,
    threats: quarantined.map((t) => ({
      id: t.id,
      objectId: t.objectId,
      burnTxDigest: digest,
    })),
  });
});

// POST /scan-wallet — full wallet scan with SSE progress updates
router.post("/scan-wallet", async (req, res) => {
  const body = req.body as { walletAddress?: string };
  const walletAddress = body?.walletAddress?.trim();
  if (!walletAddress) {
    res.status(400).json({ error: "walletAddress is required" });
    return;
  }

  const authAddress = res.locals.authSession?.address as string | undefined;
  if (authAddress && authAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    res.status(403).json({ error: "Access denied: wallet mismatch" });
    return;
  }

  res.status(200);
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  (res as any).flushHeaders?.();

  const emit = (event: string, data: Record<string, unknown>) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  const emitLog = (
    step: string,
    message: string,
    extra: Record<string, unknown> = {},
    status: "running" | "done" | "error" = "done",
  ) => {
    emit("log", { step, message, status, ...extra });
  };

  try {
    emitLog("fetch", "Fetching all owned objects…", {}, "running");
    const objects = await fetchWalletActivityObjects(walletAddress);
    emitLog("fetch", `Found ${objects.length} object(s) across wallet history`, { count: objects.length });

    const existing = await prisma.threat.findMany({
      where: {
        walletAddress: { equals: walletAddress, mode: "insensitive" },
      },
      select: { objectId: true },
    });
    const existingObjectIds = new Set(existing.map((row) => row.objectId));
    const toAnalyze = objects.filter((object) => !existingObjectIds.has(object.objectId));

    emitLog(
      "filter",
      `${toAnalyze.length} new object(s) to analyze (${existingObjectIds.size} already recorded)`,
      { count: toAnalyze.length },
    );

    let quarantined = 0;
    let safe = 0;

    for (const object of toAnalyze) {
      emitLog(
        "analyze",
        `Analyzing ${object.objectType}`,
        { objectId: object.objectId, objectType: object.objectType, stillOwned: object.stillOwned },
        "running",
      );

      try {
        const verdict = await analyzeThreat({
          objectId: object.objectId,
          objectType: object.objectType,
          senderAddress: walletAddress,
          displayName: object.displayName,
          displayUrl: object.displayUrl,
          moveAbi: object.moveAbi,
        });

        if (
          (verdict.verdict === "MALICIOUS" || verdict.verdict === "SUSPICIOUS") &&
          verdict.risk_score >= MIN_RISK_SCORE_FOR_QUARANTINE
        ) {
          const logPayload = buildThreatLog({
            objectId: object.objectId,
            objectType: object.objectType,
            senderAddress: walletAddress,
            displayName: object.displayName,
            displayUrl: object.displayUrl,
            verdict: verdict.verdict,
            riskScore: verdict.risk_score,
            reasonCode: verdict.reason_code,
            confidence: verdict.confidence,
            flags: verdict.flags,
            reasoning: verdict.reasoning,
          });

          const walrusBlobId = await storeThreatLog(logPayload).catch(() => null);
          const threat = await prisma.threat.create({
            data: {
              objectId: object.objectId,
              objectType: object.objectType,
              senderAddress: walletAddress,
              walletAddress,
              displayName: object.displayName ?? null,
              displayUrl: object.displayUrl ?? null,
              riskScore: verdict.risk_score,
              verdict: verdict.verdict,
              reasonCode: verdict.reason_code,
              confidence: verdict.confidence,
              flags: verdict.flags,
              reasoning: verdict.reasoning,
              cleanMethod: verdict.clean_method,
              hasStoreAbility: false,
              status: "quarantined",
              walrusBlobId: walrusBlobId ?? null,
            },
          });

          let onChainDigest: string | null = null;
          if (isOnChainEnabled()) {
            onChainDigest = await quarantineOnChain({
              objectId: object.objectId,
              objectType: object.objectType,
              senderAddress: walletAddress,
              riskScore: verdict.risk_score,
              verdict: verdict.verdict,
              reasonCode: verdict.reason_code,
              confidence: verdict.confidence,
              walrusBlobId: walrusBlobId ?? "",
            }).catch(() => null);

            if (onChainDigest) {
              await prisma.threat.update({
                where: { id: threat.id },
                data: { quarantineTxDigest: onChainDigest },
              }).catch(() => {});
            }
          }

          quarantined += 1;
          emitLog(
            "quarantine",
            `Quarantined ${object.objectType}`,
            { objectId: object.objectId, threatId: threat.id, onChainDigest, riskScore: verdict.risk_score, verdict: verdict.verdict, stillOwned: object.stillOwned },
          );
        } else {
          safe += 1;
          emitLog(
            "analyze",
            `Safe ${object.objectType}`,
            { objectId: object.objectId, riskScore: verdict.risk_score, verdict: verdict.verdict },
          );
        }
      } catch (error) {
        emitLog(
          "analyze",
          `Failed to analyze ${object.objectType}`,
          { objectId: object.objectId, error: error instanceof Error ? error.message : String(error) },
          "error",
        );
      }
    }

    emit("done", {
      total: objects.length,
      analyzed: toAnalyze.length,
      quarantined,
      safe,
    });
  } catch (error) {
    emit("error", {
      message: error instanceof Error ? error.message : "Wallet scan failed",
    });
  } finally {
    res.end();
  }
});

// POST /clean-wallet-scan — scan historical wallet activity and clean in one pass
router.post("/clean-wallet-scan", async (req, res) => {
  const body = req.body as { walletAddress?: string };
  const walletAddress = body?.walletAddress?.trim();
  if (!walletAddress) {
    res.status(400).json({ error: "walletAddress is required" });
    return;
  }

  const authAddress = res.locals.authSession?.address as string | undefined;
  if (authAddress && authAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    res.status(403).json({ error: "Access denied: wallet mismatch" });
    return;
  }

  res.status(200);
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  (res as any).flushHeaders?.();

  const emit = (event: string, data: Record<string, unknown>) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  const emitLog = (
    step: string,
    message: string,
    extra: Record<string, unknown> = {},
    status: "running" | "done" | "error" = "done",
  ) => {
    emit("log", { step, message, status, ...extra });
  };

  try {
    emitLog("fetch", "Fetching full on-chain activity for wallet…", {}, "running");
    const activityObjects = await fetchWalletActivityObjects(walletAddress);
    emitLog("fetch", `Found ${activityObjects.length} objects in wallet history`, { count: activityObjects.length });

    const existing = await prisma.threat.findMany({
      where: { walletAddress: { equals: walletAddress, mode: "insensitive" } },
      select: { objectId: true, status: true },
    });
    const existingIds = new Set(existing.map((row) => row.objectId));
    const toAnalyze = activityObjects.filter((object) => !existingIds.has(object.objectId));

    emitLog("filter", `${toAnalyze.length} new objects to analyze (${existingIds.size} already known)`, { count: toAnalyze.length });

    let quarantined = 0;
    let safe = 0;
    let cleaned = 0;

    for (const object of toAnalyze) {
      emitLog(
        "analyze",
        `Analyzing ${object.objectType}`,
        { objectId: object.objectId, objectType: object.objectType, stillOwned: object.stillOwned },
        "running",
      );

      try {
        const verdict = await analyzeThreat({
          objectId: object.objectId,
          objectType: object.objectType,
          senderAddress: walletAddress,
          displayName: object.displayName,
          displayUrl: object.displayUrl,
          moveAbi: object.moveAbi,
        });

        if ((verdict.verdict === "MALICIOUS" || verdict.verdict === "SUSPICIOUS") && verdict.risk_score >= MIN_RISK_SCORE_FOR_QUARANTINE) {
          const logPayload = buildThreatLog({
            objectId: object.objectId,
            objectType: object.objectType,
            senderAddress: walletAddress,
            displayName: object.displayName,
            displayUrl: object.displayUrl,
            verdict: verdict.verdict,
            riskScore: verdict.risk_score,
            reasonCode: verdict.reason_code,
            confidence: verdict.confidence,
            flags: verdict.flags,
            reasoning: verdict.reasoning,
          });

          const walrusBlobId = await storeThreatLog(logPayload).catch(() => null);
          const threat = await prisma.threat.create({
            data: {
              objectId: object.objectId,
              objectType: object.objectType,
              senderAddress: walletAddress,
              walletAddress,
              displayName: object.displayName ?? null,
              displayUrl: object.displayUrl ?? null,
              riskScore: verdict.risk_score,
              verdict: verdict.verdict,
              reasonCode: verdict.reason_code,
              confidence: verdict.confidence,
              flags: verdict.flags,
              reasoning: verdict.reasoning,
              cleanMethod: verdict.clean_method,
              hasStoreAbility: false,
              status: "quarantined",
              walrusBlobId: walrusBlobId ?? null,
            },
          });

          quarantined += 1;
          emitLog(
            "quarantine",
            `Quarantined ${object.objectType}`,
            { objectId: object.objectId, threatId: threat.id, riskScore: verdict.risk_score, verdict: verdict.verdict, stillOwned: object.stillOwned },
          );

          if (object.stillOwned && isOnChainEnabled()) {
            emitLog("clean", `Attempting on-chain clean for ${object.objectId}…`, { objectId: object.objectId }, "running");

            let burnDigest: string | null = null;

            if (verdict.clean_method === "merge_dust") {
              const coinType = object.objectType.match(/::coin::Coin<(.+)>$/)?.[1] ?? null;
              if (coinType) {
                const coins = await fetchCoinObjects(walletAddress, coinType);
                if (coins.length >= 2) {
                  burnDigest = await mergeDustOnChain({
                    coinType,
                    primaryCoinId: coins[0].coinObjectId,
                    dustCoinIds: coins.slice(1).map((coin) => coin.coinObjectId),
                  }).catch(() => null);
                }
              }
            } else {
              const abilities = await fetchObjectAbilities(object.objectType);
              if (abilities.map((ability) => ability.toLowerCase()).includes("store")) {
                burnDigest = await sendToDeadOnChain({
                  objectId: object.objectId,
                  objectType: object.objectType,
                }).catch(() => null);
              }
            }

            if (burnDigest) {
              await prisma.threat.update({ where: { id: threat.id }, data: { status: "burned", burnTxDigest: burnDigest } }).catch(() => {});
              cleaned += 1;
              emitLog("clean", `Cleaned ${object.objectId}`, { objectId: object.objectId, burnTxDigest: burnDigest });
            } else {
              emitLog("clean", `Could not auto-clean ${object.objectId} (manual burn needed)`, { objectId: object.objectId }, "error");
            }
          } else if (!object.stillOwned) {
            emitLog("skip", `Object no longer in wallet — skipping burn`, { objectId: object.objectId });
          }
        } else {
          safe += 1;
          emitLog("analyze", `Safe ${object.objectType}`, { objectId: object.objectId, riskScore: verdict.risk_score, verdict: verdict.verdict });
        }
      } catch (error) {
        emitLog(
          "analyze",
          `Failed to analyze ${object.objectType}`,
          { objectId: object.objectId, error: error instanceof Error ? error.message : String(error) },
          "error",
        );
      }
    }

    emit("done", {
      total: activityObjects.length,
      analyzed: toAnalyze.length,
      quarantined,
      safe,
      cleaned,
    });
  } catch (error) {
    emit("error", { message: error instanceof Error ? error.message : "Clean scan failed" });
  } finally {
    res.end();
  }
});

export default router;