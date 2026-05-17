import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { verifyPersonalMessageSignature } from "@mysten/sui/verify";
import { isValidSuiAddress, normalizeSuiAddress } from "@mysten/sui/utils";
import type { NextFunction, Request, Response } from "express";

const encoder = new TextEncoder();

const AUTH_TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const AUTH_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const AUTH_ISSUER = "deepclean-api";
const AUTH_AUDIENCE = "deepclean";
const AUTH_SECRET = process.env["AUTH_JWT_SECRET"] ?? "deepclean-dev-secret";

const challengeStore = new Map<string, AuthChallengeRecord>();

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

export async function loginWithSignature(addressInput: string, signature: string): Promise<AuthLoginResponse> {
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

  await verifyPersonalMessageSignature(encoder.encode(record.challenge), signature, { address });

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

  const session = verifyAuthToken(header.slice("Bearer ".length).trim());
  if (!session) {
    res.status(401).json({ error: "Invalid or expired token" });
    return;
  }

  res.locals.authSession = session;
  next();
}
