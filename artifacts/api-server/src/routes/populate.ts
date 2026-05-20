// artifacts/api-server/src/routes/populate.ts
import { Router } from "express";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { logger } from "../lib/logger";
import { analyzeThreatBatch } from "../lib/gemini";
import { storeThreatLog, buildThreatLog } from "../lib/walrus";
import { prisma } from "@workspace/db";

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

    // Probe deployed package for all supported mint functions so we can
    // skip jobs that aren't present in the published spam package and
    // avoid "FunctionNotFound" simulation errors.
    // We'll also fetch the list of normalized modules from the package
    // and resolve the actual module names to use in moveCall targets.
    const MODULE_FN_PAIRS: Array<{ module: string; fn: string; key: string }> = [
      { module: "malicious_airdrop", fn: "mint", key: "airdrop" },
      { module: "rug_token", fn: "airdrop_to", key: "rug" },
      { module: "fake_foundation_nft", fn: "mint", key: "nft" },
      { module: "pool", fn: "mint", key: "pool" },
      { module: "honeypot_defi", fn: "stake_and_receive", key: "honeypot" },
      { module: "fake_staking", fn: "mint", key: "staking" },
      { module: "counterfeit_nft", fn: "mint", key: "counterfeit" },
      { module: "flash_loan_faker", fn: "mint", key: "flash_loan" },
      { module: "marketplace_escrow", fn: "mint", key: "escrow" },
      { module: "swap_tracker", fn: "mint", key: "swap" },
      { module: "fake_governance", fn: "mint", key: "governance" },
      { module: "bridge_faker", fn: "mint", key: "bridge" },
      { module: "subscription_token", fn: "mint", key: "subscription" },
    ];
    const available = new Set<string>();
    const resolvedModuleByKey = new Map<string, string>();

    // Fetch normalized modules for the package so we can match actual
    // compiled module names (defensively handling various RPC shapes).
    try {
      const norm = await (client as any).core.getNormalizedMoveModulesByPackage({ package: spamPackageId });
      // defensive extraction of module list
      const modList: any[] = Array.isArray(norm)
        ? norm
        : (norm && (norm.modules || norm.data || norm.result)) || [];

      const names = modList.map((m: any) => {
        // different RPC shapes may expose the module name under different keys
        return m?.name ?? m?.module ?? (typeof m === "string" ? m : undefined);
      }).filter(Boolean);

      logger.info({ package: spamPackageId, modules: names }, "Normalized modules in package");

      await Promise.all(
        MODULE_FN_PAIRS.map(async ({ module, fn, key }) => {
          try {
            // prefer direct getMoveFunction probe (handles named-address resolution),
            // but also try to detect an actual module name from the normalized list
            const def = await (client as any).core.getMoveFunction({ packageId: spamPackageId, moduleName: module, name: fn });
            if (def && def.function) {
              available.add(key);
              resolvedModuleByKey.set(key, module);
              logger.info({ fn: `${spamPackageId}::${module}::${fn}` }, "Move function available");
              return;
            }
          } catch (e) {
            // fallthrough to attempt name resolution via normalized module list
          }

          // try to find a normalized module that contains the expected module token
          const found = names.find((n: string) => n === module || n.endsWith(`::${module}`) || n.endsWith(module));
          if (found) {
            try {
              const def2 = await (client as any).core.getMoveFunction({ packageId: spamPackageId, moduleName: found, name: fn });
              if (def2 && def2.function) {
                available.add(key);
                resolvedModuleByKey.set(key, found);
                logger.info({ fn: `${spamPackageId}::${found}::${fn}` }, "Move function available (resolved from normalized list)");
                return;
              }
            } catch (e2) {
              logger.warn({ err: e2, fn: `${spamPackageId}::${found}::${fn}` }, "Move function not found using resolved module name");
            }
          }

          logger.warn({ fn: `${spamPackageId}::${module}::${fn}` }, "Move function not found in deployed package");
        })
      );
    } catch (e) {
      logger.warn({ err: e }, "Could not list normalized modules for package");
      // fallback to conservative probing of each module name
      await Promise.all(
        MODULE_FN_PAIRS.map(async ({ module, fn, key }) => {
          try {
            const def = await (client as any).core.getMoveFunction({ packageId: spamPackageId, moduleName: module, name: fn });
            if (def && def.function) {
              available.add(key);
              resolvedModuleByKey.set(key, module);
              logger.info({ fn: `${spamPackageId}::${module}::${fn}` }, "Move function available");
            }
          } catch (e2) {
            logger.warn({ err: e2, fn: `${spamPackageId}::${module}::${fn}` }, "Move function not found in deployed package (fallback)");
          }
        })
      );
    }

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

    async function mintAirdropToken(): Promise<{ digest: string; created: string[] }> {
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

      return { digest: res.digest, created };
    }

    async function mintRugToken(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      tx.moveCall({
        target: `${spamPackageId}::rug_token::airdrop_to`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    async function mintFakeFoundationNft(): Promise<{ digest: string; created: string[] }> {
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

      return { digest: res.digest, created: createdNft };
    }

    async function mintSpoofedPool(): Promise<{ digest: string; created: string[] }> {
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

      return { digest: res.digest, created: createdPool };
    }

    async function mintHoneypotToken(): Promise<{ digest: string; created: string[] }> {
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

      return { digest: res.digest, created: createdHoney };
    }

    async function mintFakeStaking(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      const moduleForStaking = resolvedModuleByKey.get("staking") ?? "fake_staking";
      tx.moveCall({
        target: `${spamPackageId}::${moduleForStaking}::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    async function mintCounterfeitNft(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      const moduleForCounterfeit = resolvedModuleByKey.get("counterfeit") ?? "counterfeit_nft";
      tx.moveCall({
        target: `${spamPackageId}::${moduleForCounterfeit}::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    async function mintFlashLoanTicket(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      const moduleForFlash = resolvedModuleByKey.get("flash_loan") ?? "flash_loan_faker";
      tx.moveCall({
        target: `${spamPackageId}::${moduleForFlash}::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    async function mintMarketplaceEscrow(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      const moduleForEscrow = resolvedModuleByKey.get("escrow") ?? "marketplace_escrow";
      tx.moveCall({
        target: `${spamPackageId}::${moduleForEscrow}::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    async function mintSwapReceipt(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      const moduleForSwap = resolvedModuleByKey.get("swap") ?? "swap_tracker";
      tx.moveCall({
        target: `${spamPackageId}::${moduleForSwap}::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    async function mintFakeGovernanceToken(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      const moduleForGovernance = resolvedModuleByKey.get("governance") ?? "fake_governance";
      tx.moveCall({
        target: `${spamPackageId}::${moduleForGovernance}::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    async function mintBridgeNotification(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      const moduleForBridge = resolvedModuleByKey.get("bridge") ?? "bridge_faker";
      tx.moveCall({
        target: `${spamPackageId}::${moduleForBridge}::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    async function mintSubscriptionToken(): Promise<{ digest: string; created: string[] }> {
      const tx = new Transaction();
      const moduleForSubscription = resolvedModuleByKey.get("subscription") ?? "subscription_token";
      tx.moveCall({
        target: `${spamPackageId}::${moduleForSubscription}::mint`,
        arguments: [tx.pure.address(targetAddress)],
      });
      const res = await executeAndGetResult(tx);
      const createdFromEffects = (((res as any).effects?.created) ?? []).map((c: any) => c?.reference?.objectId).filter(Boolean);
      const createdFromChanges = (((res as any).effects?.objectChanges) ?? []).filter((c: any) => c.type === "created").map((c: any) => c.objectId);
      const created = createdFromEffects.length ? createdFromEffects : createdFromChanges;
      return { digest: res.digest, created };
    }

    const ALL_POSSIBLE_JOBS: Array<{ key: string; label: string; fn: () => Promise<{ digest: string; created: string[] }> }> = [
      { key: "airdrop", label: "Fake SUI Airdrop Token", fn: mintAirdropToken },
      { key: "rug", label: "Rug Meme Coin", fn: mintRugToken },
      { key: "nft", label: "Fake Foundation NFT", fn: mintFakeFoundationNft },
      { key: "pool", label: "Spoofed Cetus LP Position", fn: mintSpoofedPool },
      { key: "honeypot", label: "Honeypot DeFi Token", fn: mintHoneypotToken },
      { key: "staking", label: "Fake Staking Receipt", fn: mintFakeStaking },
      { key: "counterfeit", label: "Counterfeit NFT", fn: mintCounterfeitNft },
      { key: "flash_loan", label: "Flash Loan Ticket", fn: mintFlashLoanTicket },
      { key: "escrow", label: "Marketplace Escrow Ticket", fn: mintMarketplaceEscrow },
      { key: "swap", label: "Malicious Swap Receipt", fn: mintSwapReceipt },
      { key: "governance", label: "Suspicious Governance Token", fn: mintFakeGovernanceToken },
      { key: "bridge", label: "Bridge Notification", fn: mintBridgeNotification },
      { key: "subscription", label: "Subscription Token", fn: mintSubscriptionToken },
    ];

    // Filter jobs to only those whose mint function was discovered in the deployed package.
    const jobs = ALL_POSSIBLE_JOBS.filter((j) => {
      if (!available.has(j.key)) {
        logger.warn({ job: j.key }, `Skipping ${j.label}: mint function not found in package ${spamPackageId}`);
        return false;
      }
      return true;
    });

    for (const job of jobs) {
      try {
        const out = await job.fn();
        const digest = out?.digest ?? (out as any);
        const createdIds: string[] = Array.isArray(out?.created) && out!.created.length > 0 ? out!.created : [];
        logger.info({ digest, job: job.key, network }, `Seeded ${job.label} successfully`);
        result.seeded++;
        result.digests.push(digest);

        // Keep a record of the intended object type for downstream UI/logging.
        const objectType = job.key === "airdrop"
          ? `${spamPackageId}::malicious_airdrop::AirdropToken`
          : job.key === "rug"
            ? `${spamPackageId}::rug_token::MemeCoin`
            : job.key === "nft"
              ? `${spamPackageId}::fake_foundation_nft::FounderPass`
              : job.key === "pool"
                ? `${spamPackageId}::pool::Position`
                : job.key === "honeypot"
                  ? `${spamPackageId}::honeypot_defi::HoneypotToken`
                  : job.key === "staking"
                    ? `${spamPackageId}::fake_staking::StakingReceipt`
                    : job.key === "counterfeit"
                      ? `${spamPackageId}::counterfeit_nft::CounterfeitCollectable`
                      : job.key === "flash_loan"
                        ? `${spamPackageId}::flash_loan_faker::FlashLoanTicket`
                        : job.key === "escrow"
                          ? `${spamPackageId}::marketplace_escrow::EscrowTicket`
                          : job.key === "swap"
                            ? `${spamPackageId}::swap_tracker::SwapReceipt`
                            : job.key === "governance"
                              ? `${spamPackageId}::fake_governance::GovernanceToken`
                              : job.key === "bridge"
                                ? `${spamPackageId}::bridge_faker::BridgeNotification`
                                : `${spamPackageId}::subscription_token::SubscriptionToken`;

        if (createdIds.length > 0) {
          for (const objId of createdIds) {
            result.objects.push({
              objectId: objId,
              objectType,
              senderAddress: agentAddress,
              displayName: job.label,
              displayUrl: null,
              moveAbi: null,
            });
          }
        } else {
          // Fallback to legacy placeholder if we couldn't extract created IDs
          result.objects.push({
            objectId: `${job.key}:${digest}`,
            objectType,
            senderAddress: agentAddress,
            displayName: job.label,
            displayUrl: null,
            moveAbi: null,
          });
        }
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

  // If we seeded objects, run them through the AI analyser so the UI shows
  // quarantined threats immediately and links them to the target wallet.
  const threatsOut: Array<{ objectId: string; objectType: string; verdict: string; riskScore: number; threatId?: number | null }> = [];

  if (seedResult.objects.length > 0) {
    try {
      const inputs = seedResult.objects.map((o) => ({
        objectId: o.objectId,
        objectType: o.objectType,
        senderAddress: o.senderAddress,
        displayName: o.displayName,
        displayUrl: o.displayUrl,
        moveAbi: o.moveAbi,
      }));

      const results = await analyzeThreatBatch(inputs as any);

      for (let i = 0; i < results.length; i++) {
        const r = results[i];
        const src = seedResult.objects[i];
        // If the object was minted from our spam package, treat it as malicious
        // for UI/db purposes so seeded types appear in the Threats list.
        const isFromSpamPackage = typeof src.objectType === "string" && SPAM_PACKAGE_ID ? src.objectType.startsWith(SPAM_PACKAGE_ID) : false;
        const shouldQuarantine = (r.verdict === "MALICIOUS" && r.risk_score >= 75) || isFromSpamPackage;

        if (shouldQuarantine) {
          const verdictToUse = isFromSpamPackage ? "MALICIOUS" : r.verdict;
          const riskToUse = isFromSpamPackage ? 95 : r.risk_score;

          const logPayload = buildThreatLog({
            objectId: src.objectId,
            objectType: src.objectType,
            senderAddress: src.senderAddress,
            displayName: src.displayName,
            displayUrl: src.displayUrl,
            verdict: verdictToUse,
            riskScore: riskToUse,
            reasonCode: r.reason_code,
            confidence: r.confidence,
            flags: r.flags,
            reasoning: r.reasoning,
          });

          const walrusBlobId = await storeThreatLog(logPayload).catch(() => null);

          const inserted = await prisma.threat.create({
            data: {
              objectId: src.objectId,
              objectType: src.objectType,
              senderAddress: src.senderAddress,
              walletAddress: targetAddress,
              displayName: src.displayName ?? null,
              displayUrl: src.displayUrl ?? null,
              riskScore: riskToUse,
              verdict: verdictToUse,
              reasonCode: r.reason_code,
              confidence: r.confidence,
              flags: r.flags,
              reasoning: r.reasoning,
              cleanMethod: r.clean_method,
              hasStoreAbility: false,
              status: "quarantined",
              walrusBlobId: walrusBlobId ?? null,
            },
          });

          threatsOut.push({ objectId: src.objectId, objectType: src.objectType, verdict: verdictToUse, riskScore: riskToUse, threatId: inserted.id });
        } else {
          threatsOut.push({ objectId: src.objectId, objectType: src.objectType, verdict: r.verdict, riskScore: r.risk_score, threatId: null });
        }
      }
    } catch (err) {
      req.log.warn({ err }, "Analysis of seeded objects failed — returning seed result without DB threats");
    }
  }

  res.json({
    injected: seedResult.seeded,
    digests: seedResult.digests,
    objects: seedResult.objects,
    targetAddress,
    network: SUI_NETWORK,
    threats: threatsOut,
  });
});

export default router;