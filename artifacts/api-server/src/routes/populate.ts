// artifacts/api-server/src/routes/populate.ts
import { Router } from "express";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { prisma } from "@workspace/db";
import { analyzeThreatBatch } from "../lib/gemini";
import { storeThreatLog, buildThreatLog } from "../lib/walrus";
import { quarantineOnChain, getOnChainConfigStatus } from "../lib/onchain";
import { MIN_RISK_SCORE_FOR_QUARANTINE } from "../lib/constants";
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

    // Define junk types to mint
    interface JunkJob {
      key: string;
      label: string;
      moveModule: string;
      moveFunction: string;
      needsRecipient: boolean;
      requiresTransfer: boolean;
    }

    const jobs: JunkJob[] = [
      {
        key: "airdrop",
        label: "Fake SUI Airdrop Token",
        moveModule: "malicious_airdrop",
        moveFunction: "mint",
        needsRecipient: false,
        requiresTransfer: true,
      },
      {
        key: "rug",
        label: "Rug Meme Coin",
        moveModule: "rug_token",
        moveFunction: "airdrop_to",
        needsRecipient: true,
        requiresTransfer: false,
      },
      {
        key: "nft",
        label: "Fake Foundation NFT",
        moveModule: "fake_foundation_nft",
        moveFunction: "mint",
        needsRecipient: false,
        requiresTransfer: true,
      },
      {
        key: "pool",
        label: "Spoofed Cetus LP Position",
        moveModule: "pool",
        moveFunction: "fake_mint",
        needsRecipient: false,
        requiresTransfer: true,
      },
      {
        key: "honeypot",
        label: "Honeypot DeFi Token",
        moveModule: "honeypot_defi",
        moveFunction: "stake_and_receive",
        needsRecipient: false,
        requiresTransfer: true,
      },
    ];

    // Execute each mint in its own PTB
    for (const job of jobs) {
      try {
        const tx = new Transaction();
        tx.setSender(agentAddress);
        tx.setGasBudget(5_000_000);

        if (job.needsRecipient) {
          // Functions like airdrop_to that take recipient directly
          tx.moveCall({
            target: `${spamPackageId}::${job.moveModule}::${job.moveFunction}`,
            arguments: [tx.pure.address(targetAddress)],
          });
        } else {
          // Functions that mint to ctx.sender()
          const [object] = tx.moveCall({
            target: `${spamPackageId}::${job.moveModule}::${job.moveFunction}`,
            arguments: [],
          });

          if (job.requiresTransfer) {
            // Transfer immediately to target
            tx.transferObjects([object], tx.pure.address(targetAddress));
          }
        }

        // Sign and execute
        const bytes = await tx.build({ client });
        const { signature, bytes: signedBytes } = await keypair.signTransaction(bytes);
        const txResult = await client.executeTransactionBlock({
          transactionBlock: signedBytes,
          signature: signature,
          options: { showEffects: true, showObjectChanges: true },
        });

        const status = txResult.effects?.status?.status;
        if (status === "success") {
          const createdObject = (txResult.objectChanges ?? []).find(
            (change: any) => change?.type === "created" || change?.type === "transferred"
          ) as any;

          logger.info(
            { digest: txResult.digest, job: job.key, network },
            `Seeded ${job.label} successfully`
          );
          result.seeded++;
          result.digests.push(txResult.digest);

          // Record the minted object as a ChainObject for analysis when the SDK returns it.
          // The wallet fetch below is still the source of truth, but this keeps the
          // seeded items visible even if the follow-up object scan is incomplete.
          if (createdObject?.objectId) {
            result.objects.push({
              objectId: createdObject.objectId,
              objectType: createdObject.objectType ?? `${spamPackageId}::${job.moveModule}::${job.key.toUpperCase()}`,
              senderAddress: agentAddress,
              displayName: job.label,
              displayUrl: null,
              moveAbi: null,
            });
          }
        } else {
          const err = txResult.effects?.status?.error ?? "unknown error";
          logger.warn(
            { digest: txResult.digest, job: job.key, error: err },
            `Failed to seed ${job.label}`
          );
        }
      } catch (jobErr) {
        logger.warn(
          { err: jobErr, job: job.key },
          `Exception seeding ${job.label}`
        );
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

function dedupeObjects(objects: ChainObject[]): ChainObject[] {
  const seen = new Set<string>();
  return objects.filter((object) => {
    if (seen.has(object.objectId)) return false;
    seen.add(object.objectId);
    return true;
  });
}

function buildSyntheticFixtures(targetAddress: string): ChainObject[] {
  return [
    {
      objectId: "0xfixture_spam_0001",
      objectType: "0xdead0001::scam_airdrop::FreeToken",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000001",
      displayName: "FREE 5000 SUI - Exclusive Airdrop",
      displayUrl: "https://free-sui-tokens.xyz/airdrop/claim",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_spam_0002",
      objectType: "0xdead0002::phishing_kit::WalletDrainer",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000002",
      displayName: "Official Sui Wallet Connect",
      displayUrl: "https://suiofficial-connect.xyz/verify",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_spam_0003",
      objectType: "0xdead0003::honeypot_defi::HoneypotToken",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000003",
      displayName: "SuiGold - 10x APY DeFi Protocol",
      displayUrl: "https://suigold-defi.xyz/stake",
      moveAbi: JSON.stringify({ functions: [{ name: "_drain_all", visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] }] }),
    },
    {
      objectId: "0xfixture_spam_0004",
      objectType: "0xdead0004::fake_foundation::FounderPass",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000004",
      displayName: "Sui Foundation VIP Founder Pass",
      displayUrl: "https://sui-f0undation.com/exclusive-nft",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_spam_0005",
      objectType: "0xdead0005::nft_phish::MintPass",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000005",
      displayName: "Sui Foundation Official NFT",
      displayUrl: "https://suifoundation-nft.io/mint",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_spam_0006",
      objectType: "0xdead0006::fake_cetus::LPReceipt",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000006",
      displayName: "Cetus Protocol - Claim LP Rewards",
      displayUrl: "https://cetus-protocol.xyz/claim-rewards",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_spam_0007",
      objectType: "0xdead0007::approval_phish::ApprovalRequest",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000007",
      displayName: "Sui Wallet Verification Required",
      displayUrl: "https://verify-suiwallet.com/approve",
      moveAbi: JSON.stringify({ functions: [{ name: "sweep_all", visibility: "private", params: ["&mut 0x2::coin::Coin<0x2::sui::SUI>"] }] }),
    },
    {
      objectId: "0xfixture_spam_0008",
      objectType: "0xdead0008::dust_attack::TrackingDust",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000008",
      displayName: "0.000001 SUI Transfer",
      displayUrl: null,
      moveAbi: null,
    },
    {
      objectId: "0xfixture_spam_0009",
      objectType: "0xdead0009::rug_token::MemeCoin",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000009",
      displayName: "SuiDoge - 100x Meme Coin",
      displayUrl: "https://suidoge-token.xyz/stake",
      moveAbi: JSON.stringify({ functions: [{ name: "freeze_all", visibility: "private", params: [] }] }),
    },
    {
      objectId: "0xfixture_spam_0010",
      objectType: "0xdead0010::fake_governance::VoteProposal",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000010",
      displayName: "Sui DAO - Urgent Governance Vote",
      displayUrl: "https://sui-gov0rnance.io/vote",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_spam_0011",
      objectType: "0xdead0011::spoofed_pool::Position",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000011",
      displayName: "Liquidity Position - Urgent Migration",
      displayUrl: "https://cetus-support-claim.xyz/migrate",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_spam_0012",
      objectType: "0xdead0012::fake_validator::DelegationPass",
      senderAddress: "0xbadc0ffee0000000000000000000000000000000000000000000000000000012",
      displayName: "Validator Boost Pass",
      displayUrl: "https://delegate-now-boost.xyz",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_legit_0001",
      objectType: "0x2::coin::Coin<0x2::sui::SUI>",
      senderAddress: targetAddress,
      displayName: "SUI",
      displayUrl: null,
      moveAbi: null,
    },
    {
      objectId: "0xfixture_legit_0002",
      objectType: "0x2::kiosk::Kiosk",
      senderAddress: targetAddress,
      displayName: "Kiosk",
      displayUrl: null,
      moveAbi: null,
    },
    {
      objectId: "0xfixture_legit_0003",
      objectType: "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb::pool::Position",
      senderAddress: targetAddress,
      displayName: "Cetus LP Position",
      displayUrl: "https://cetus.zone",
      moveAbi: null,
    },
    {
      objectId: "0xfixture_legit_0004",
      objectType: "0x5d4b302506645c37ff133b98c4b50a744f7a58be6b040e4e4d90c5f6b74cbce5::coin::USDC",
      senderAddress: targetAddress,
      displayName: "USD Coin (USDC)",
      displayUrl: "https://www.circle.com/usdc",
      moveAbi: null,
    },
  ];
}

async function fetchOriginalSender(
  client: SuiJsonRpcClient,
  objectId: string
): Promise<string | null> {
  try {
    const txs = await client.queryTransactionBlocks({
      filter: { ChangedObject: objectId },
      options: {
        showInput: true,
        showEffects: true,
      },
      limit: 1,
      order: "ascending",
    });

    if (!txs.data || txs.data.length === 0) {
      return null;
    }

    const creationTx = txs.data[0];
    return creationTx.transaction?.data.sender ?? null;
  } catch (err) {
    console.debug("fetchOriginalSender failed:", err);
    return null;
  }
}

async function fetchAllSpamObjectsForWallet(
  client: SuiJsonRpcClient,
  walletAddress: string
): Promise<ChainObject[]> {
  const results: ChainObject[] = [];

  try {
    // Fetch all objects owned by the provided wallet across every page.
    let cursor: string | null | undefined = null;
    do {
      const owned = await client.getOwnedObjects({
        owner: walletAddress,
        cursor: cursor ?? undefined,
        limit: 50,
        options: {
          showType:    true,
          showDisplay: true,
          showContent: true,
        },
      });

      for (const item of owned.data) {
        const obj = item.data;
        if (!obj || !obj.objectId || !obj.type) continue;

        // Skip publishing artifacts not relevant for threat analysis.
        const isDisplayOrPub =
          obj.type.includes("::display::Display") ||
          obj.type.includes("::package::Publisher") ||
          obj.type.includes("::package::UpgradeCap");

        if (isDisplayOrPub) continue;  // skip publishing artifacts

        const sender = await fetchOriginalSender(client, obj.objectId);

        const displayFields = obj.display?.data as Record<string, string> | undefined | null;

        results.push({
          objectId:      obj.objectId,
          objectType:    obj.type,
          senderAddress: sender ?? "unknown",
          displayName:   displayFields?.["name"] ?? null,
          displayUrl:    displayFields?.["link"] ?? displayFields?.["url"] ?? null,
          moveAbi:       null,
        });
      }

      cursor = owned.nextCursor;
      if (!owned.hasNextPage) break;
    } while (cursor);
  } catch (err) {
    console.warn("fetchAllSpamObjectsForWallet: RPC error", err);
  }

  return results;
}

// POST /populate-wallet
router.post("/populate-wallet", async (req, res) => {
  const { targetAddress, txDigest: callerTxDigest, includeSyntheticFixtures } = req.body as {
    targetAddress?: string;
    txDigest?: string | null;
    includeSyntheticFixtures?: boolean;
  };

  if (!targetAddress || typeof targetAddress !== "string") {
    res.status(400).json({ error: "targetAddress is required" });
    return;
  }

  const REAL_ONCHAIN = (process.env["REAL_ONCHAIN"] ?? "false").toLowerCase() === "true";
  const SUI_NETWORK = (process.env["SUI_NETWORK"] ?? "testnet") as "testnet" | "mainnet" | "devnet" | "localnet";
  const onChainConfig = getOnChainConfigStatus();

  req.log.info(
    {
      targetAddress,
      realOnChain: REAL_ONCHAIN,
      onChainEnabled: onChainConfig.onChainEnabled,
      missingOnChainVars: onChainConfig.missingVars,
      privateKeyParseable: onChainConfig.privateKeyParseable,
      network: SUI_NETWORK,
    },
    "Populating wallet with real on-chain wallet objects"
  );

  if (REAL_ONCHAIN && !onChainConfig.onChainEnabled) {
    req.log.error(
      {
        missingOnChainVars: onChainConfig.missingVars,
        privateKeyParseable: onChainConfig.privateKeyParseable,
      },
      "REAL_ONCHAIN requested but on-chain config is incomplete"
    );
    res.status(500).json({
      error: "REAL_ONCHAIN=true but on-chain configuration is incomplete",
      details: {
        requiredVars: ["QUARANTINE_PACKAGE_ID", "QUARANTINE_ADMIN_CAP_ID", "AGENT_PRIVATE_KEY"],
        missingVars: onChainConfig.missingVars,
        privateKeyParseable: onChainConfig.privateKeyParseable,
      },
    });
    return;
  }

  // Connect to the requested Sui network where our contracts are deployed
  type NetworkName = "testnet" | "mainnet" | "devnet" | "localnet";
  const networkName: NetworkName = SUI_NETWORK;
  const client = new SuiJsonRpcClient({ url: getJsonRpcFullnodeUrl(networkName), network: networkName });

  const defaultIncludeFixtures = (process.env["POPULATE_INCLUDE_SYNTHETIC_FIXTURES"] ?? "false").toLowerCase() === "true";
  const shouldIncludeFixtures = typeof includeSyntheticFixtures === "boolean"
    ? includeSyntheticFixtures
    : defaultIncludeFixtures;

  // Try to seed on-chain junk objects if SPAM_PACKAGE_ID is configured
  let seededObjects: ChainObject[] = [];
  const SPAM_PACKAGE_ID = process.env["SPAM_PACKAGE_ID"]?.trim() ?? process.env["QUARANTINE_PACKAGE_ID"]?.trim();
  const SPAM_AGENT_KEY = process.env["AGENT_PRIVATE_KEY"]?.trim();
  
  if (SPAM_PACKAGE_ID && SPAM_AGENT_KEY) {
    req.log.info(
      { targetAddress, spamPackageId: SPAM_PACKAGE_ID },
      "Attempting to seed on-chain junk objects"
    );
    const seedResult = await seedOnChainJunk(
      client,
      targetAddress,
      SPAM_PACKAGE_ID,
      SPAM_AGENT_KEY,
      SUI_NETWORK
    );
    seededObjects = seedResult.objects;
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

  const realObjects: ChainObject[] = await fetchAllSpamObjectsForWallet(client, targetAddress);
  const syntheticFixtures = shouldIncludeFixtures ? buildSyntheticFixtures(targetAddress) : [];
  const injections: ChainObject[] = dedupeObjects([...syntheticFixtures, ...seededObjects, ...realObjects]);


  req.log.info(
    {
      targetAddress,
      seededObjects: seededObjects.length,
      realObjects: realObjects.length,
      syntheticFixtures: syntheticFixtures.length,
      totalObjects: injections.length,
      includeSyntheticFixtures: shouldIncludeFixtures,
    },
    "Prepared objects for wallet population"
  );

  // Analyze ALL objects in a single model call
  const verdicts = await analyzeThreatBatch(injections);

  const threats = await Promise.all(
    injections.map(async (obj, idx) => {
      const verdict = verdicts[idx] ?? {
        risk_score: 20,
        verdict: "SAFE" as const,
        reason_code: 5,
        confidence: 0.5,
        flags: [],
        reasoning: "No verdict returned",
      };

      const effectiveVerdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS" = verdict.verdict;
      const effectiveRiskScore = verdict.risk_score;

      const logPayload = buildThreatLog({
        objectId:      obj.objectId,
        objectType:    obj.objectType,
        senderAddress: obj.senderAddress,
        displayName:   obj.displayName ?? null,
        displayUrl:    obj.displayUrl  ?? null,
        verdict:       effectiveVerdict,
        riskScore:     effectiveRiskScore,
        reasonCode:    verdict.reason_code,
        confidence:    verdict.confidence,
        flags:         verdict.flags,
        reasoning:     verdict.reasoning,
      });

      try {
        const existing = await prisma.threat.findFirst({
          where: { objectId: obj.objectId, walletAddress: targetAddress },
        });

        if (existing) {
          return {
            objectId:   obj.objectId,
            objectType: obj.objectType,
            verdict:    existing.verdict as "SAFE" | "SUSPICIOUS" | "MALICIOUS",
            riskScore:  existing.riskScore,
            threatId:   existing.status === "quarantined" ? existing.id : null,
            onChainDigest: existing.quarantineTxDigest ?? null,
          };
        }

        const shouldQuarantine = effectiveVerdict === "MALICIOUS" && effectiveRiskScore >= MIN_RISK_SCORE_FOR_QUARANTINE;
        const status = shouldQuarantine ? "quarantined" : "safe";

        const [walrusBlobId, threat] = await Promise.all([
          storeThreatLog(logPayload),
          prisma.threat.create({
            data: {
              objectId:      obj.objectId,
              objectType:    obj.objectType,
              senderAddress: obj.senderAddress,
              walletAddress: targetAddress,
              displayName:   obj.displayName ?? null,
              displayUrl:    obj.displayUrl  ?? null,
              riskScore:     effectiveRiskScore,
              verdict:       effectiveVerdict,
              reasonCode:    verdict.reason_code,
              confidence:    verdict.confidence,
              flags:         verdict.flags,
              reasoning:     verdict.reasoning,
              cleanMethod:   verdict.clean_method,
              status,
            },
          }),
        ]);

        const threatId = status === "quarantined" ? threat.id : null;

        if (walrusBlobId) {
          await prisma.threat.update({ where: { id: threat.id }, data: { walrusBlobId } });
        }

        let onChainDigest: string | null = null;
        if (shouldQuarantine && REAL_ONCHAIN) {
          onChainDigest = await quarantineOnChain({
            objectId:      obj.objectId,
            objectType:    obj.objectType,
            senderAddress: obj.senderAddress,
            riskScore:     effectiveRiskScore,
            verdict:       effectiveVerdict,
            reasonCode:    verdict.reason_code,
            confidence:    verdict.confidence,
            walrusBlobId:  walrusBlobId ?? "",
          });

          if (onChainDigest) {
            await prisma.threat.update({
              where: { id: threat.id },
              data:  { quarantineTxDigest: onChainDigest },
            }).catch(() => {});
          }
        }

        return {
          objectId:      obj.objectId,
          objectType:    obj.objectType,
          verdict:       effectiveVerdict,
          riskScore:     effectiveRiskScore,
          threatId,
          onChainDigest,
        };
      } catch (err) {
        req.log.error({ err, objectId: obj.objectId, objectType: obj.objectType }, "populate-wallet item failed");
        return {
          objectId:      obj.objectId,
          objectType:    obj.objectType,
          verdict:       effectiveVerdict,
          riskScore:     effectiveRiskScore,
          threatId:      null,
          onChainDigest: null,
          error:         err instanceof Error ? err.message : String(err),
        };
      }
    })
  );

  const quarantined    = threats.filter((t) => t.threatId !== null).length;
  const onChainDigests = threats.map((t) => t.onChainDigest).filter(Boolean);

  // Update watchedWallet threat counter
  if (quarantined > 0) {
    await prisma.watchedWallet.update({
      where: { address: targetAddress },
      data:  { threatsDetected: { increment: quarantined } },
    });
  }

  req.log.info(
    { injected: threats.length, quarantined, onChainCount: onChainDigests.length, targetAddress },
    "Wallet population complete"
  );

  res.json({
    injected:      threats.length,
    quarantined,
    seededCount: seededObjects.length,
    syntheticCount: syntheticFixtures.length,
    realCount: realObjects.length,
    txDigest:      callerTxDigest ?? null,
    onChainDigest: onChainDigests[0] ?? null,
    threats,
  });
});

export default router;