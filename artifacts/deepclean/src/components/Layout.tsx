import { Link, useLocation } from "wouter";
import { Shield, LayoutDashboard, AlertTriangle, Search, Wallet, Activity, Lock, Loader2, LogOut, Sparkles } from "lucide-react";
import { ConnectButton } from "@mysten/dapp-kit";
import { useCurrentAccount } from "@mysten/dapp-kit";
import { useEffect, useState } from "react";
import { useListThreats } from "@workspace/api-client-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { useAuth } from "@/components/AuthProvider";
import { Button } from "@/components/ui/button";

const navItems = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/threats", label: "Threats", icon: AlertTriangle },
  { href: "/analyze", label: "Analyze", icon: Search },
  { href: "/wallets", label: "Wallets", icon: Wallet },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const account = useCurrentAccount();
  const { toast } = useToast();
  const auth = useAuth();

  const [hasEthereum, setHasEthereum] = useState(false);
  const [hasSolana, setHasSolana] = useState(false);

  const { data: threats } = useListThreats({ status: "quarantined", limit: 100 });
  const quarantinedCount = Array.isArray(threats) ? threats.length : 0;

  useEffect(() => {
    setHasEthereum(typeof (window as any).ethereum !== "undefined");
    setHasSolana(typeof (window as any).solana !== "undefined" && (window as any).solana.isPhantom);
  }, []);

  async function connectMetaMask() {
    try {
      const ethereum = (window as any).ethereum;
      if (!ethereum) throw new Error("MetaMask not found");
      const accounts: string[] = await ethereum.request({ method: "eth_requestAccounts" });
      const address = accounts[0];
      // persist for other UI pieces to consume
      try { localStorage.setItem("externalWallet", JSON.stringify({ provider: "metamask", address })); } catch (e) {}
      window.dispatchEvent(new CustomEvent("externalWallet:connected", { detail: { provider: "metamask", address } }));
      toast({ title: "MetaMask connected", description: address });
    } catch (err: any) {
      toast({ title: "MetaMask connect failed", description: String(err), variant: "destructive" });
    }
  }

  async function connectPhantom() {
    try {
      const solana = (window as any).solana;
      if (!solana || !solana.isPhantom) throw new Error("Phantom wallet not found");
      const resp = await solana.connect();
      const pubkey = resp?.publicKey?.toString?.() ?? resp?.publicKey ?? String(resp);
      const address = pubkey;
      try { localStorage.setItem("externalWallet", JSON.stringify({ provider: "phantom", address })); } catch (e) {}
      window.dispatchEvent(new CustomEvent("externalWallet:connected", { detail: { provider: "phantom", address } }));
      toast({ title: "Phantom connected", description: address });
    } catch (err: any) {
      toast({ title: "Phantom connect failed", description: String(err), variant: "destructive" });
    }
  }

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      {/* Sidebar */}
      <aside className="w-60 shrink-0 border-r border-border flex flex-col bg-card">
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b border-border">
          <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary/20 border border-primary/30">
            <Shield className="w-4 h-4 text-primary" />
          </div>
          <div>
            <div className="text-sm font-bold tracking-wider text-foreground">DEEPCLEAN</div>
            <div className="text-[10px] text-muted-foreground tracking-widest uppercase">Threat Monitor</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? location === "/" : location.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                data-testid={`nav-${label.toLowerCase()}`}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                  active
                    ? "bg-primary/15 text-primary border border-primary/20"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                )}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {label}
                 {label === "Threats" && quarantinedCount > 0 ? (
                   <span className="ml-auto min-w-[18px] h-[18px] rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center px-1">
                     {quarantinedCount > 99 ? "99+" : quarantinedCount}
                   </span>
                 ) : active && label !== "Threats" ? (
                   <span className="ml-auto w-1.5 h-1.5 rounded-full bg-primary" />
                 ) : null}
              </Link>
            );
          })}
        </nav>

        {/* Wallet & Status Footer */}
        <div className="px-4 py-3 border-t border-border space-y-3">
          {/* Connect Button */}
          <div className="flex justify-center">
            <ConnectButton />
          </div>

          <div className="rounded-md border border-border bg-muted/30 px-3 py-2 text-[11px] text-muted-foreground space-y-1">
            <div className="flex items-center gap-2">
              <Lock className="w-3 h-3" />
              <span className="uppercase tracking-[0.22em] text-[10px]">Session</span>
              <span className="ml-auto text-[10px] text-foreground">
                {auth.status === "authenticated"
                  ? "Unlocked"
                  : auth.status === "signing"
                    ? "Signing"
                    : auth.status === "checking"
                      ? "Checking"
                      : "Locked"}
              </span>
            </div>
            <div className="truncate">
              {auth.walletAddress ? auth.walletAddress : "Connect a wallet to unlock the console"}
            </div>
          </div>

          {auth.isAuthenticated ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="w-full gap-2"
              onClick={() => {
                void auth.signOut();
                toast({ title: "Signed out", description: "Your session token was cleared." });
              }}
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign out
            </Button>
          ) : auth.status === "needs-sign-in" || auth.status === "signing" || auth.status === "checking" ? (
            <Button
              type="button"
              size="sm"
              className="w-full gap-2"
              onClick={() => {
                void auth.signIn().catch((err) => {
                  toast({ title: "Sign in failed", description: String(err), variant: "destructive" });
                });
              }}
              disabled={auth.status !== "needs-sign-in"}
            >
              {auth.status === "signing" || auth.status === "checking" ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Sparkles className="w-3.5 h-3.5" />
              )}
              {auth.status === "signing"
                ? "Waiting for signature"
                : auth.status === "checking"
                  ? "Verifying session"
                  : "Sign in with wallet"}
            </Button>
          ) : null}

          {/* Quick-connect for other injected wallets (MetaMask / Phantom) */}
          <div className="flex justify-center gap-2 mt-2">
            {hasEthereum && (
              <button
                className="text-xs px-2 py-1 rounded-md bg-zinc-800 text-white"
                onClick={connectMetaMask}
                title="Connect MetaMask (EVM)"
              >
                MetaMask
              </button>
            )}
            {hasSolana && (
              <button
                className="text-xs px-2 py-1 rounded-md bg-purple-700 text-white"
                onClick={connectPhantom}
                title="Connect Phantom (Solana)"
              >
                Phantom
              </button>
            )}
            {!hasEthereum && !hasSolana && (
              <div className="text-xs text-muted-foreground">No injected wallets detected</div>
            )}
          </div>

          {/* Connected Address Display */}
          {account && (
            <div className="rounded px-2 py-1.5 bg-primary/10 border border-primary/20">
              <div className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Connected</div>
              <div className="font-mono text-[10px] text-primary truncate" title={account.address}>
                {account.address.slice(0, 10)}...{account.address.slice(-6)}
              </div>
            </div>
          )}

          {/* Agent Status */}
          <div className="flex items-center gap-2">
            <Activity className="w-3 h-3 text-green-400" />
            <span className="text-[11px] text-muted-foreground">Agent Active</span>
            <span className="ml-auto w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        {auth.isAuthenticated ? (
          children
        ) : (
          <div className="relative min-h-screen overflow-hidden">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,197,94,0.18),transparent_30%),radial-gradient(circle_at_bottom_right,rgba(14,165,233,0.18),transparent_32%),linear-gradient(135deg,hsl(var(--background)),hsl(var(--background)))]" />
            <div className="relative flex min-h-screen items-center justify-center px-6 py-10">
              <div className="w-full max-w-xl rounded-2xl border border-border/70 bg-card/95 p-8 shadow-2xl backdrop-blur">
                <div className="flex items-center gap-3">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-primary/30 bg-primary/15">
                    <Shield className="h-6 w-6 text-primary" />
                  </div>
                  <div>
                    <div className="text-xs uppercase tracking-[0.3em] text-muted-foreground">DeepClean access</div>
                    <h1 className="mt-1 text-2xl font-semibold text-foreground">
                      {auth.status === "locked" ? "Connect your wallet" : "Confirm wallet ownership"}
                    </h1>
                  </div>
                </div>

                <p className="mt-4 max-w-lg text-sm leading-6 text-muted-foreground">
                  The console is protected behind a wallet-signed session. Connect a Sui wallet,
                  sign the one-time challenge, and unlock the live threat workflow.
                </p>

                <div className="mt-6 rounded-xl border border-border bg-background/70 p-4">
                  <div className="flex items-center gap-3 text-sm text-foreground">
                    <Lock className="h-4 w-4 text-primary" />
                    <span>Wallet session required for analysis, cleanup, and monitoring routes.</span>
                  </div>
                  {auth.error && (
                    <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 text-sm text-red-300">
                      {auth.error}
                    </div>
                  )}
                </div>

                <div className="mt-6 flex flex-col gap-3 sm:flex-row">
                  {account ? (
                    <Button
                      type="button"
                      className="gap-2"
                      onClick={() => {
                        void auth.signIn().catch((err) => {
                          toast({ title: "Sign in failed", description: String(err), variant: "destructive" });
                        });
                      }}
                      disabled={auth.status === "signing" || auth.status === "checking"}
                    >
                      {auth.status === "signing" || auth.status === "checking" ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Sparkles className="h-4 w-4" />
                      )}
                      {auth.status === "signing"
                        ? "Waiting for signature"
                        : auth.status === "checking"
                          ? "Verifying session"
                          : "Sign in with connected wallet"}
                    </Button>
                  ) : (
                    <div className="flex-1 rounded-md border border-border px-4 py-3 text-sm text-muted-foreground">
                      Use the Connect Wallet button in the sidebar to begin.
                    </div>
                  )}

                  <div className="text-xs text-muted-foreground sm:self-center">
                    {auth.walletAddress ? `Wallet: ${auth.walletAddress}` : "No wallet connected yet"}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
