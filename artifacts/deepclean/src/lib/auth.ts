import { normalizeSuiAddress } from "@mysten/sui/utils";

export const AUTH_TOKEN_KEY = "deepclean.authToken";

export interface AuthChallenge {
  address: string;
  challenge: string;
  expiresAt: string;
}

export interface AuthSessionResponse {
  address: string;
  expiresAt: string;
}

export interface AuthLoginResponse extends AuthSessionResponse {
  token: string;
}

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8080";

function buildApiUrl(path: string): string {
  return new URL(path, API_BASE).toString();
}

function readToken(): string | null {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getStoredAuthToken(): string | null {
  return readToken();
}

export function setStoredAuthToken(token: string | null): void {
  try {
    if (token) {
      localStorage.setItem(AUTH_TOKEN_KEY, token);
    } else {
      localStorage.removeItem(AUTH_TOKEN_KEY);
    }
  } catch {
    // Ignore storage failures in private browsing / locked-down browsers.
  }
}

type ApiJsonOptions = Omit<RequestInit, "body"> & {
  body?: unknown;
  auth?: boolean;
};

export async function apiJson<T>(path: string, options: ApiJsonOptions = {}): Promise<T> {
  const { auth = true, headers: headersInit, body, ...init } = options;
  const headers = new Headers(headersInit);
  const requestBody: BodyInit | null | undefined =
    body != null && typeof body === "object" && !(body instanceof FormData)
      ? JSON.stringify(body)
      : (body as BodyInit | null | undefined);

  if (body != null && typeof body === "object" && !(body instanceof FormData)) {
    headers.set("content-type", "application/json");
  }

  if (auth) {
    const token = readToken();
    if (token) {
      headers.set("authorization", `Bearer ${token}`);
    }
  }

  const response = await fetch(buildApiUrl(path), {
    ...init,
    headers,
    body: requestBody,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || `HTTP ${response.status}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  return (text ? JSON.parse(text) : null) as T;
}

export async function requestAuthChallenge(address: string): Promise<AuthChallenge> {
  return apiJson<AuthChallenge>(`/api/auth/challenge?address=${encodeURIComponent(normalizeSuiAddress(address))}`, {
    auth: false,
  });
}

export async function loginWithWallet(address: string, signature: string, bytes: string, chain?: string): Promise<AuthLoginResponse> {
  const session = await apiJson<AuthLoginResponse>("/api/auth/login", {
    method: "POST",
    auth: false,
    body: { address: normalizeSuiAddress(address), signature, bytes, chain },
  });

  setStoredAuthToken(session.token);
  return session;
}

export async function fetchAuthSession(): Promise<AuthSessionResponse> {
  return apiJson<AuthSessionResponse>("/api/auth/session");
}

export async function logoutSession(): Promise<void> {
  try {
    await apiJson<void>("/api/auth/logout", { method: "POST" });
  } finally {
    setStoredAuthToken(null);
  }
}
