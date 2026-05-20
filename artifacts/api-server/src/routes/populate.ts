// artifacts/api-server/src/routes/populate.ts
import { Router } from "express";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { logger } from "../lib/logger";

const router = Router();

// ─── Fetch real objects from the target wallet ───────────────────────────────

interface ChainObject {
  objectId:      string;
  objectType:    string;
  senderAddress: string;
  displayName:   string | null;
  displayUrl:    string | null;
  moveAbi:       string | null;
}

// ─── On-Chain Junk Seeding ────────────────────────────────────────────────────

interface SeedJunkResult {
  seeded: number;
  digests: string[];
  objects: ChainObject[];
}

/**
 * Parse and load the agent's private key for seeding junk objects.
 * Supports suiprivkey1..., hex, base64, and JSON formats.
 */
function parseAgentPrivateKey(raw: string): Uint8Array | null {
  if (!raw) return null;
  const s = raw.trim();

  // suiprivkey1... (official Sui format)
  if (s.startsWith("suiprivkey1")) {
    try {
      const { secretKey } = decodeSuiPrivateKey(s);
      return secretKey;
    } catch {
      return null;
    }
  }

  // Hex (0x or bare)
  if (/^0x[0-9a-fA-F]+$/.test(s) || /^[0-9a-fA-F]+$/.test(s)) {
    try {
      const clean = s.startsWith("0x") ? s.slice(2) : s;
      if (clean.length % 2 !== 0) return null;
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
      }
      return bytes;
    } catch {
      return null;
    }
  }

  // Try base64
  try {
    const buf = Buffer.from(s, "base64");
    if (buf.length === 32 || buf.length === 64) return new Uint8Array(buf);
  } catch {
    return null;
  }

  return null;
}

/**
 * Seed real on-chain junk objects by calling the spam package mint functions.
 * Each junk type is minted in its own PTB for resilience.
 */
async function seedOnChainJunk(
  client: SuiJsonRpcClient,
  targetAddress: string,
  spamPackageId: string,
  rawPrivateKey: string,
  network: string
): Promise<SeedJunkResult> {
  const result: SeedJunkResult = {
    seeded: 0,
    digests: [],
    objects: [],
  };

  try {
    // Parse and load keypair
    const secretKeyBytes = parseAgentPrivateKey(rawPrivateKey);
    if (!secretKeyBytes) {
      logger.warn("Failed to parse AGENT_PRIVATE_KEY for seeding");
      return result;
    }

    const keypair = Ed25519Keypair.fromSecretKey(secretKeyBytes);
    const agentAddress = keypair.toSuiAddress();

    logger.info(
      { targetAddress, spamPackageId, agentAddress, network },
      "Starting on-chain junk seeding"
    );

    // Introspect on-chain Move function signatures to diagnose arity/resolution issues.
    async function logMoveFunctionSig(moduleName: string, fnName: string) {
      try {
        // Use core client helper to fetch normalized Move function definition
        // (some client builds expose this via `core.getMoveFunction`).
        // Use any-cast to avoid type issues in this compiled runtime.
        const def = await (client as any).core.getMoveFunction({ packageId: spamPackageId, moduleName, name: fnName });
        logger.info({ fn: `${spamPackageId}::${moduleName}::${fnName}`, def: def.function }, "Move function definition");
      } catch (e) {
        logger.warn({ err: e, fn: `${spamPackageId}::${moduleName}::${fnName}` }, "Could not fetch Move function definition");
      }
    }

    // Log signatures for all junk mint functions before attempting PTBs
    await Promise.all([
      logMoveFunctionSig("malicious_airdrop", "mint"),
      logMoveFunctionSig("rug_token", "airdrop_to"),
      logMoveFunctionSig("fake_foundation_nft", "mint"),
      logMoveFunctionSig("pool", "mint"),
      logMoveFunctionSig("honeypot_defi", "stake_and_receive"),
    ]);

    async function executeAndWait(tx: Transaction): Promise<string> {
      const result = await executeTransactionWithRetry(tx);
      return result.digest;
    }

    // Execute and return the full RPC result (effects + digest)
    async function executeAndGetResult(tx: Transaction) {
      return executeTransactionWithRetry(tx);
    }

    async function setFreshGasPayment(tx: Transaction) {
      const coinsResponse = await client.getCoins({
        owner: agentAddress,
        coinType: "0x2::sui::SUI",
        limit: 10,
      });

      const gasCoin = coinsResponse.data?.[0];
      if (gasCoin) {
        tx.setGasPayment([{ objectId: gasCoin.coinObjectId, version: gasCoin.version, digest: gasCoin.digest }]);
      }
    }

    async function executeTransactionWithRetry(tx: Transaction, attempt = 1): Promise<any> {
      await setFreshGasPayment(tx);

      try {
        const result = await client.signAndExecuteTransaction({
          signer: keypair,
          transaction: tx,
          options: { showEffects: true, showObjectChanges: true },
        });

        const status = result.effects?.status?.status;
        if (status !== "success") {
          const err = result.effects?.status?.error ?? "unknown error";
          throw new Error(`Transaction failed: ${err}`);
        }

        await client.waitForTransaction({ digest: result.digest });
        return result;
      } catch (error: any) {
        const message = String(error?.message ?? error ?? "");
        const isStaleObjectError =
          message.includes("unavailable for consumption") ||
          message.includes("needs to be rebuilt") ||
          message.includes("already locked by a different transaction");

        if (attempt < 2 && isStaleObjectError) {
          logger.warn({ attempt, err: error }, "Retrying transaction with fresh gas coin");
          return executeTransactionWithRetry(tx, attempt + 1);
        }

        throw error;
      }
    }

    async function mintAirdropToken(): Promise<string> {
      const tx = new Transaction();
      tx.setSender(agentAddress);

      tx.moveCall({
        target: `${spamPackageId}::malicious_airdrop::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });

      const res = await executeAndGetResult(tx);

      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      if (created.length === 0) {
        console.warn("Mint airdrop effects:", JSON.stringify((res as any).effects, null, 2));
        console.warn("Mint airdrop objectChanges:", JSON.stringify(((res as any).effects?.objectChanges) ?? [], null, 2));
        throw new Error("Mint did not create expected AirdropToken — see server logs for effects");
      }

      return res.digest;
    }

    async function mintRugToken(): Promise<string> {
      const tx = new Transaction();
      tx.moveCall({
        target: `${spamPackageId}::rug_token::airdrop_to`,
        arguments: [tx.pure.address(targetAddress)],
      });
      return executeAndWait(tx);
    }

    async function mintFakeFoundationNft(): Promise<string> {
      const tx = new Transaction();
      tx.setSender(agentAddress);

      tx.moveCall({
        target: `${spamPackageId}::fake_foundation_nft::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });

      const res = await executeAndGetResult(tx);
      const createdFromEffectsNft = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChangesNft = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const createdNft = createdFromEffectsNft.length ? createdFromEffectsNft : createdFromChangesNft;
      if (createdNft.length === 0) {
        console.warn("Mint nft effects:", JSON.stringify((res as any).effects, null, 2));
        console.warn("Mint nft objectChanges:", JSON.stringify(((res as any).effects?.objectChanges) ?? [], null, 2));
        throw new Error("Mint did not create expected FounderPass — see server logs for effects");
      }

      return res.digest;
    }

    async function mintSpoofedPool(): Promise<string> {
      const tx = new Transaction();
      tx.setSender(agentAddress);

      tx.moveCall({
        target: `${spamPackageId}::pool::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });

      const res = await executeAndGetResult(tx);
      const createdFromEffectsPool = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChangesPool = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const createdPool = createdFromEffectsPool.length ? createdFromEffectsPool : createdFromChangesPool;
      if (createdPool.length === 0) {
        console.warn("Mint pool effects:", JSON.stringify((res as any).effects, null, 2));
        console.warn("Mint pool objectChanges:", JSON.stringify(((res as any).effects?.objectChanges) ?? [], null, 2));
        throw new Error("Mint did not create expected Position — see server logs for effects");
      }

      return res.digest;
    }

    async function mintHoneypotToken(): Promise<string> {
      const tx = new Transaction();
      tx.setSender(agentAddress);

      tx.moveCall({
        target: `${spamPackageId}::honeypot_defi::stake_and_receive`,
        arguments: [tx.pure.address(targetAddress)],
      });

      const res = await executeAndGetResult(tx);
      const createdFromEffectsHoney = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChangesHoney = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const createdHoney = createdFromEffectsHoney.length ? createdFromEffectsHoney : createdFromChangesHoney;
      if (createdHoney.length === 0) {
        console.warn("Mint honeypot effects:", JSON.stringify((res as any).effects, null, 2));
        console.warn("Mint honeypot objectChanges:", JSON.stringify(((res as any).effects?.objectChanges) ?? [], null, 2));
        throw new Error("Mint did not create expected HoneypotToken — see server logs for effects");
      }

      return res.digest;
    }

    const jobs: Array<{ key: string; label: string; fn: () => Promise<string> }> = [
      { key: "airdrop", label: "Fake SUI Airdrop Token", fn: mintAirdropToken },
      { key: "rug", label: "Rug Meme Coin", fn: mintRugToken },
      { key: "nft", label: "Fake Foundation NFT", fn: mintFakeFoundationNft },
      { key: "pool", label: "Spoofed Cetus LP Position", fn: mintSpoofedPool },
      { key: "honeypot", label: "Honeypot DeFi Token", fn: mintHoneypotToken },
    ];

    for (const job of jobs) {
      try {
        const digest = await job.fn();
        logger.info({ digest, job: job.key, network }, `Seeded ${job.label} successfully`);
        result.seeded++;
        result.digests.push(digest);

        // Keep a record of the intended object type for downstream UI/logging.
        result.objects.push({
          objectId: `${job.key}:${digest}`,
          objectType: job.key === "airdrop"
            ? `${spamPackageId}::malicious_airdrop::AirdropToken`
            : job.key === "rug"
              ? `${spamPackageId}::rug_token::MemeCoin`
              : job.key === "nft"
                ? `${spamPackageId}::fake_foundation_nft::FounderPass`
                : job.key === "pool"
                  ? `${spamPackageId}::pool::Position`
                  : `${spamPackageId}::honeypot_defi::HoneypotToken`,
          senderAddress: agentAddress,
          displayName: job.label,
          displayUrl: null,
          moveAbi: null,
        });
      } catch (jobErr) {
        logger.warn({ err: jobErr, job: job.key }, `Exception seeding ${job.label}`);
      }
    }

    logger.info(
      { seeded: result.seeded, totalJobs: jobs.length, targetAddress },
      "On-chain junk seeding complete"
    );
  } catch (err) {
    logger.warn({ err, targetAddress }, "On-chain junk seeding failed (non-fatal)");
  }

  return result;
}

// POST /populate-wallet
router.post("/populate-wallet", async (req, res) => {
  const { targetAddress } = req.body as {
    targetAddress?: string;
  };

  if (!targetAddress || typeof targetAddress !== "string") {
    res.status(400).json({ error: "targetAddress is required" });
    return;
  }

  const SUI_NETWORK = (process.env["SUI_NETWORK"] ?? "testnet") as "testnet" | "mainnet" | "devnet" | "localnet";
  type NetworkName = "testnet" | "mainnet" | "devnet" | "localnet";
  const networkName: NetworkName = SUI_NETWORK;
  const client = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl(networkName), network: networkName });

  let seedResult: SeedJunkResult = {
    seeded: 0,
    digests: [],
    objects: [],
  };
  const SPAM_PACKAGE_ID = process.env["SPAM_PACKAGE_ID"]?.trim() ?? process.env["QUARANTINE_PACKAGE_ID"]?.trim();
  const SPAM_AGENT_KEY = process.env["AGENT_PRIVATE_KEY"]?.trim();

  if (SPAM_PACKAGE_ID && SPAM_AGENT_KEY) {
    req.log.info(
      { targetAddress, spamPackageId: SPAM_PACKAGE_ID },
      "Attempting to seed on-chain junk objects"
    );
    seedResult = await seedOnChainJunk(
      client,
      targetAddress,
      SPAM_PACKAGE_ID,
      SPAM_AGENT_KEY,
      SUI_NETWORK
    );
    if (seedResult.seeded > 0) {
      req.log.info(
        { seeded: seedResult.seeded, digests: seedResult.digests },
        "Successfully seeded junk objects on-chain"
      );
    }
  } else if (SPAM_PACKAGE_ID || SPAM_AGENT_KEY) {
    req.log.warn(
      {
        hasSpamPackageId: !!SPAM_PACKAGE_ID,
        hasAgentKey: !!SPAM_AGENT_KEY,
      },
      "Incomplete spam seeding configuration (need both SPAM_PACKAGE_ID and AGENT_PRIVATE_KEY)"
    );
  }

  req.log.info(
    {
      targetAddress,
      network: SUI_NETWORK,
      spamPackageId: SPAM_PACKAGE_ID,
      hasAgentKey: !!SPAM_AGENT_KEY,
    },
    "Populating wallet with on-chain junk objects only"
  );

  res.json({
    injected: seedResult.seeded,
    digests: seedResult.digests,
    objects: seedResult.objects,
    targetAddress,
    network: SUI_NETWORK,
  });
});

export default router;