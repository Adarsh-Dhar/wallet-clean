import { Router } from "express";
import { db } from "@workspace/db";
import { watchedWalletsTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { AddWatchedWalletBody, RemoveWatchedWalletParams } from "@workspace/api-zod";

const router = Router();

// GET /monitor/wallets
router.get("/monitor/wallets", async (_req, res) => {
  const wallets = await db
    .select()
    .from(watchedWalletsTable)
    .orderBy(watchedWalletsTable.createdAt);

  res.json(
    wallets.map((w) => ({
      ...w,
      createdAt: w.createdAt.toISOString(),
    }))
  );
});

// POST /monitor/wallets
router.post("/monitor/wallets", async (req, res) => {
  const body = AddWatchedWalletBody.safeParse(req.body);
  if (!body.success) {
    res.status(400).json({ error: "Invalid request body" });
    return;
  }

  const [wallet] = await db
    .insert(watchedWalletsTable)
    .values({
      address: body.data.address,
      label: body.data.label,
      isActive: true,
    })
    .returning();

  res.status(201).json({
    ...wallet,
    createdAt: wallet!.createdAt.toISOString(),
  });
});

// DELETE /monitor/wallets/:id
router.delete("/monitor/wallets/:id", async (req, res) => {
  const params = RemoveWatchedWalletParams.safeParse({ id: Number(req.params["id"]) });
  if (!params.success) {
    res.status(400).json({ error: "Invalid id" });
    return;
  }

  const [wallet] = await db
    .delete(watchedWalletsTable)
    .where(eq(watchedWalletsTable.id, params.data.id))
    .returning();

  if (!wallet) {
    res.status(404).json({ error: "Wallet not found" });
    return;
  }

  res.json({
    ...wallet,
    createdAt: wallet.createdAt.toISOString(),
  });
});

export default router;
