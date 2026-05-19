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
    const storedToken = getStoredAuthToken();

    // If there's no connected wallet and no stored token → locked
    if (!currentAddress && !storedToken) {
      setWalletAddress(null);
      setError(null);
      setStatus("locked");
      return;
    }

    // If we have a stored token, try to restore the session from the server
    if (storedToken) {
      setStatus("checking");
      try {
        const session = await fetchAuthSession();
        setWalletAddress(session.address);

        // If a wallet is connected ensure it matches the restored session
        if (currentAddress && session.address.toLowerCase() !== currentAddress.toLowerCase()) {
          setStoredAuthToken(null);
          setError(null);
          setStatus("needs-sign-in");
          return;
        }

        setError(null);
        setStatus("authenticated");
        return;
      } catch {
        // Token invalid or expired — clear and continue to determine next state
        setStoredAuthToken(null);
        setError(null);
      }
    }

    // No valid stored token at this point. If wallet connected, require sign-in.
    setWalletAddress(currentAddress);
    if (currentAddress) {
      setStatus("needs-sign-in");
    } else {
      setStatus("locked");
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
      const result = await signPersonalMessage({ message: messageBytes, account });
      const session = await loginWithWallet(account.address, result.signature, result.bytes, account.chains[0]);
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
