import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { verifyPersonalMessageSignature, verifySignature } from "@mysten/sui/verify";
import { isValidSuiAddress, normalizeSuiAddress } from "@mysten/sui/utils";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import type { NextFunction, Request, Response } from "express";

const encoder = new TextEncoder();

const AUTH_TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const AUTH_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const AUTH_ISSUER = "deepclean-api";
const AUTH_AUDIENCE = "deepclean";
const AUTH_SECRET = process.env["AUTH_JWT_SECRET"] ?? "deepclean-dev-secret";
const SUI_NETWORK = (process.env["SUI_NETWORK"] ?? "testnet") as "testnet" | "mainnet" | "devnet" | "localnet";

const challengeStore = new Map<string, AuthChallengeRecord>();
const verifyClientCache = new Map<string, SuiJsonRpcClient>();

function normalizeNetwork(chainInput?: string): "mainnet" | "testnet" | "devnet" | "localnet" {
  if (!chainInput) return SUI_NETWORK;

  const chain = chainInput.toLowerCase();
  const network = chain.includes(":") ? chain.split(":").at(-1) : chain;

  if (network === "mainnet" || network === "testnet" || network === "devnet" || network === "localnet") {
    return network;
  }

  return SUI_NETWORK;
}

function getVerifyClient(network: "mainnet" | "testnet" | "devnet" | "localnet"): SuiJsonRpcClient {
  const cached = verifyClientCache.get(network);
  if (cached) return cached;

  const client = new SuiJsonRpcClient({
    url: getJsonRpcFullnodeUrl(network),
    network,
  });

  verifyClientCache.set(network, client);
  return client;
}

export interface AuthChallenge {
  address: string;
  challenge: string;
  expiresAt: string;
}

export interface AuthLoginResponse {
  token: string;
  address: string;
  expiresAt: string;
}

export interface AuthSession {
  address: string;
  expiresAt: string;
}

interface AuthChallengeRecord {
  challenge: string;
  expiresAt: number;
}

interface JwtPayload {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  exp: number;
}

export function isAuthEnabled(): boolean {
  return process.env.NODE_ENV !== "test";
}

function base64UrlEncode(value: string | Buffer | Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

function createChallengeMessage(address: string, nonce: string, expiresAt: Date): string {
  return [
    "DeepClean wallet login",
    `Address: ${address}`,
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
    `Expires At: ${expiresAt.toISOString()}`,
  ].join("\n");
}

function createJwt(subject: string): string {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload: JwtPayload = {
    iss: AUTH_ISSUER,
    aud: AUTH_AUDIENCE,
    sub: subject,
    iat: now,
    exp: now + Math.floor(AUTH_TOKEN_TTL_MS / 1000),
  };
  const payloadPart = base64UrlEncode(JSON.stringify(payload));
  const unsigned = `${header}.${payloadPart}`;
  const signature = createHmac("sha256", AUTH_SECRET).update(unsigned).digest("base64url");
  return `${unsigned}.${signature}`;
}

function readJwt(token: string): JwtPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerPart, payloadPart, signaturePart] = parts;
  const unsigned = `${headerPart}.${payloadPart}`;
  const expected = createHmac("sha256", AUTH_SECRET).update(unsigned).digest();
  const actual = base64UrlDecode(signaturePart);

  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    return null;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(payloadPart).toString("utf8")) as JwtPayload;
    const now = Math.floor(Date.now() / 1000);

    if (payload.iss !== AUTH_ISSUER) return null;
    if (payload.aud !== AUTH_AUDIENCE) return null;
    if (typeof payload.sub !== "string" || payload.sub.trim() === "") return null;
    if (!Number.isFinite(payload.exp) || payload.exp <= now) return null;

    return payload;
  } catch {
    return null;
  }
}

function pruneExpiredChallenges(): void {
  const now = Date.now();
  for (const [address, record] of challengeStore.entries()) {
    if (record.expiresAt <= now) {
      challengeStore.delete(address);
    }
  }
}

export function issueChallenge(addressInput: string): AuthChallenge {
  const address = normalizeSuiAddress(addressInput);
  if (!isValidSuiAddress(address)) {
    throw new Error("Invalid Sui address");
  }

  pruneExpiredChallenges();

  const nonce = randomBytes(16).toString("hex");
  const expiresAt = new Date(Date.now() + AUTH_CHALLENGE_TTL_MS);
  const challenge = createChallengeMessage(address, nonce, expiresAt);

  challengeStore.set(address, {
    challenge,
    expiresAt: expiresAt.getTime(),
  });

  return {
    address,
    challenge,
    expiresAt: expiresAt.toISOString(),
  };
}

export async function loginWithSignature(
  addressInput: string,
  signature: string,
  signedBytesBase64?: string,
  chainInput?: string
): Promise<AuthLoginResponse> {
  const address = normalizeSuiAddress(addressInput);
  if (!isValidSuiAddress(address)) {
    throw new Error("Invalid Sui address");
  }

  pruneExpiredChallenges();

  const record = challengeStore.get(address);
  if (!record) {
    throw new Error("No login challenge found for this wallet");
  }

  if (record.expiresAt <= Date.now()) {
    challengeStore.delete(address);
    throw new Error("Login challenge expired");
  }

  const issuedChallengeBytes = encoder.encode(record.challenge);
  let bytesToVerify: Uint8Array = issuedChallengeBytes;

  if (typeof signedBytesBase64 === "string" && signedBytesBase64.trim() !== "") {
    let decodedBytes: Buffer;
    try {
      decodedBytes = Buffer.from(signedBytesBase64, "base64");
    } catch {
      throw new Error("Invalid signed message bytes");
    }

    if (
      decodedBytes.length !== issuedChallengeBytes.length ||
      !timingSafeEqual(decodedBytes, Buffer.from(issuedChallengeBytes))
    ) {
      throw new Error("Signed challenge does not match issued challenge");
    }

    bytesToVerify = decodedBytes;
  }

  try {
    await verifyPersonalMessageSignature(bytesToVerify, signature, {
      client: getVerifyClient(normalizeNetwork(chainInput)),
      address,
    });
  } catch (personalMessageError) {
    // Some wallets still route through deprecated signMessage semantics.
    // Accept that path only for the exact issued challenge bytes.
    await verifySignature(bytesToVerify, signature, { address }).catch(() => {
      throw personalMessageError;
    });
  }

  challengeStore.delete(address);

  const token = createJwt(address);
  const expiresAt = new Date(Date.now() + AUTH_TOKEN_TTL_MS);

  return {
    token,
    address,
    expiresAt: expiresAt.toISOString(),
  };
}

export function verifyAuthToken(token: string): AuthSession | null {
  const payload = readJwt(token);
  if (!payload) return null;

  return {
    address: payload.sub,
    expiresAt: new Date(payload.exp * 1000).toISOString(),
  };
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const header = req.header("authorization");
  if (!header?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing bearer token" });
    return;
  }

  const raw = header.slice("Bearer ".length).trim();

  // First try to validate as a signed JWT token
  const sessionFromJwt = verifyAuthToken(raw);
  if (sessionFromJwt) {
    res.locals.authSession = sessionFromJwt;
    next();
    return;
  }

  // If not a JWT, accept a plain connected wallet address as a convenience
  // (development/devops mode). This allows the frontend to send the connected
  // wallet address as the bearer token when no login JWT is available.
  try {
    const addr = normalizeSuiAddress(raw);
    if (!isValidSuiAddress(addr)) {
      res.status(401).json({ error: "Invalid or expired token" });
      return;
    }

    res.locals.authSession = { address: addr, expiresAt: new Date(Date.now() + AUTH_TOKEN_TTL_MS).toISOString() };
    next();
    return;
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
    return;
  }
}
