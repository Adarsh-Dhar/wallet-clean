import { Link, useLocation } from "wouter";
import { Shield, LayoutDashboard, AlertTriangle, Search, Wallet, Activity } from "lucide-react";
import { ConnectButton } from "@mysten/dapp-kit";
import { useCurrentAccount } from "@mysten/dapp-kit";
import { useEffect, useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

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

  const [hasEthereum, setHasEthereum] = useState(false);
  const [hasSolana, setHasSolana] = useState(false);

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
                {active && <span className="ml-auto w-1.5 h-1.5 rounded-full bg-primary" />}
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
        {children}
      </main>
    </div>
  );
}
