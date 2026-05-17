import { Router } from "express";
import { isValidSuiAddress } from "@mysten/sui/utils";
import { issueChallenge, loginWithSignature, requireAuth } from "../lib/auth";

const router = Router();

router.get("/auth/challenge", async (req, res) => {
  const address = typeof req.query["address"] === "string" ? req.query["address"] : "";

  if (!address || !isValidSuiAddress(address)) {
    res.status(400).json({ error: "Invalid address" });
    return;
  }

  const challenge = issueChallenge(address);
  res.setHeader("Cache-Control", "no-store");
  res.json(challenge);
});

router.post("/auth/login", async (req, res) => {
  const address = req.body?.address;
  const signature = req.body?.signature;

  if (typeof address !== "string" || typeof signature !== "string") {
    res.status(400).json({ error: "address and signature are required" });
    return;
  }

  try {
    const session = await loginWithSignature(address, signature);
    res.setHeader("Cache-Control", "no-store");
    res.json(session);
  } catch (error) {
    res.status(401).json({ error: error instanceof Error ? error.message : "Login failed" });
  }
});

router.get("/auth/session", requireAuth, async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json(res.locals.authSession);
});

router.post("/auth/logout", async (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.status(204).end();
});

export default router;
