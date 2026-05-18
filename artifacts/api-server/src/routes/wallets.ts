// artifacts/api-server/src/routes/wallets.ts
import { Router } from "express";
import { prisma } from "@workspace/db";
import { AddWatchedWalletBody, RemoveWatchedWalletParams } from "@workspace/api-zod";
import { isValidSuiAddress, normalizeSuiAddress } from "@mysten/sui/utils";

const router = Router();

// GET /monitor/wallets
router.get("/monitor/wallets", async (_req, res) => {
  const wallets = await prisma.watchedWallet.findMany({
    orderBy: { createdAt: "asc" },
  });

  res.json(
    wallets.map((w) => ({
      ...w,
      createdAt: w.createdAt.toISOString(),
    }))
  );
});

// POST /monitor/wallets
router.post("/monitor/wallets", async (req, res) => {
  try {
    const body = AddWatchedWalletBody.safeParse(req.body);
    if (!body.success) {
      res.status(400).json({ error: "Invalid request body", details: body.error });
      return;
    }

    const normalizedAddress = normalizeSuiAddress(body.data.address);
    if (!isValidSuiAddress(normalizedAddress)) {
      res.status(400).json({ error: "Invalid Sui address" });
      return;
    }

    const wallet = await prisma.watchedWallet.upsert({
      where: { address: normalizedAddress },
      update: {
        label:    body.data.label,
        isActive: true,
      },
      create: {
        address:  normalizedAddress,
        label:    body.data.label,
        isActive: true,
      },
    });

    res.status(201).json({
      ...wallet,
      createdAt: wallet.createdAt.toISOString(),
    });
  } catch (err) {
    req.log.error({ err }, "Failed to create wallet");
    res.status(500).json({ 
      error: err instanceof Error ? err.message : "Internal server error",
      type: err?.constructor?.name,
    });
  }
});

// DELETE /monitor/wallets/:id
router.delete("/monitor/wallets/:id", async (req, res) => {
  const rawId = Number(req.params["id"]);
  if (!Number.isFinite(rawId) || !Number.isInteger(rawId) || rawId < 1 || rawId > 2147483647) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }
  const params = RemoveWatchedWalletParams.safeParse({ id: rawId });
  if (!params.success) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  // Check it exists first so we can return 404 instead of a Prisma error
  const existing = await prisma.watchedWallet.findUnique({ where: { id: params.data.id } });
  if (!existing) {
    res.status(404).json({ error: "Wallet not found" });
    return;
  }

  const wallet = await prisma.watchedWallet.delete({
    where: { id: params.data.id },
  });

  res.json({
    ...wallet,
    createdAt: wallet.createdAt.toISOString(),
  });
});

export default router;