import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useCurrentAccount, useSignPersonalMessage } from "@mysten/dapp-kit";
import { fetchAuthSession, getStoredAuthToken, loginWithWallet, logoutSession, requestAuthChallenge, setStoredAuthToken } from "@/lib/auth";

type AuthStatus = "locked" | "needs-sign-in" | "signing" | "checking" | "authenticated";

interface AuthContextValue {
  status: AuthStatus;
  isAuthenticated: boolean;
  walletAddress: string | null;
  error: string | null;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : "Authentication failed";
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const account = useCurrentAccount();
  const { mutateAsync: signPersonalMessage } = useSignPersonalMessage();
  const [status, setStatus] = useState<AuthStatus>("locked");
  const [error, setError] = useState<string | null>(null);
  const [walletAddress, setWalletAddress] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const currentAddress = account?.address ?? null;
    setWalletAddress(currentAddress);

    if (!currentAddress) {
      setStoredAuthToken(null);
      setError(null);
      setStatus("locked");
      return;
    }

    if (!getStoredAuthToken()) {
      setError(null);
      setStatus("needs-sign-in");
      return;
    }

    setStatus("checking");

    try {
      const session = await fetchAuthSession();
      if (session.address.toLowerCase() !== currentAddress.toLowerCase()) {
        throw new Error("Wallet changed");
      }

      setError(null);
      setStatus("authenticated");
    } catch {
      setStoredAuthToken(null);
      setError(null);
      setStatus("needs-sign-in");
    }
  }, [account?.address]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const signIn = useCallback(async () => {
    if (!account) {
      setStatus("locked");
      throw new Error("Connect a Sui wallet first.");
    }

    setStatus("signing");
    setError(null);

    try {
      const challenge = await requestAuthChallenge(account.address);
      const messageBytes = new TextEncoder().encode(challenge.challenge);
      const result = await signPersonalMessage({ message: messageBytes });
      const session = await loginWithWallet(account.address, result.signature);
      setStoredAuthToken(session.token);
      setWalletAddress(session.address);
      setStatus("authenticated");
    } catch (authError) {
      setStoredAuthToken(null);
      setStatus(account ? "needs-sign-in" : "locked");
      setError(formatError(authError));
      throw authError;
    }
  }, [account, signPersonalMessage]);

  const signOut = useCallback(async () => {
    await logoutSession();
    setError(null);
    setWalletAddress(account?.address ?? null);
    setStatus(account ? "needs-sign-in" : "locked");
  }, [account?.address]);

  const value = useMemo<AuthContextValue>(() => ({
    status,
    isAuthenticated: status === "authenticated",
    walletAddress,
    error,
    signIn,
    signOut,
    refresh,
  }), [error, refresh, signIn, signOut, status, walletAddress]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return value;
}
