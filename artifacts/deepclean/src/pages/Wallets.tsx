import { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useCurrentAccount } from "@mysten/dapp-kit";
import {
  useListWatchedWallets,
  useAddWatchedWallet,
  useRemoveWatchedWallet,
  getListWatchedWalletsQueryKey,
  getGetDashboardStatsQueryKey,
  getListThreatsQueryKey,
  type WatchedWallet,
} from "@workspace/api-client-react";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { walletSchema, type WalletFormValues } from "@/lib/schemas";
import { Trash2, Plus, Wallet, AlertTriangle, Zap } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

type LocalWallet = {
  id: number;
  address: string;
  label: string;
  isActive: boolean;
  threatsDetected?: number;
  createdAt: string;
  localOnly?: boolean;
};

type WalletRow = WatchedWallet & {
  localOnly?: boolean;
};

const LOCAL_WALLETS_KEY = "deepclean.localWatchedWallets";
const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

function readLocalWallets(): WalletRow[] {
  try {
    const raw = localStorage.getItem(LOCAL_WALLETS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeLocalWallets(wallets: WalletRow[]) {
  try {
    localStorage.setItem(LOCAL_WALLETS_KEY, JSON.stringify(wallets));
  } catch {
    // ignore storage failures
  }
}

interface PopulateResult {
  injected: number;
  quarantined: number;
  txDigest: string | null;
  threats: Array<{
    objectId: string;
    objectType: string;
    verdict: string;
    riskScore: number;
    threatId: number | null;
  }>;
}

async function populateWalletApi(targetAddress: string): Promise<PopulateResult> {
  const res = await fetch(new URL("/api/populate-wallet", API_BASE).toString(), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targetAddress }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<PopulateResult>;
}

export default function Wallets() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [populatingId, setPopulatingId] = useState<number | null>(null);
  const account = useCurrentAccount();
  const [externalConnected, setExternalConnected] = useState<{ provider: string; address: string } | null>(null);
  const [localWallets, setLocalWallets] = useState<WalletRow[]>([]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem("externalWallet");
      if (raw) setExternalConnected(JSON.parse(raw));
    } catch (e) {
      setExternalConnected(null);
    }

    const handler = (e: any) => {
      try {
        const d = e?.detail;
        if (d && d.address) setExternalConnected({ provider: d.provider ?? "external", address: d.address });
      } catch {
        /* ignore */
      }
    };
    window.addEventListener("externalWallet:connected", handler as EventListener);
    return () => window.removeEventListener("externalWallet:connected", handler as EventListener);
  }, []);

  useEffect(() => {
    setLocalWallets(readLocalWallets());
  }, []);

  const { data: wallets, isLoading } = useListWatchedWallets();

  const safeWallets: WalletRow[] = Array.isArray(wallets)
    ? wallets.map((wallet) => ({ ...wallet, localOnly: false }))
    : [];
  const mergedWallets: WalletRow[] = [...safeWallets, ...localWallets].filter(
    (wallet, index, list) => list.findIndex((item) => item.address === wallet.address) === index,
  );

  const form = useForm<WalletFormValues>({
    resolver: zodResolver(walletSchema),
    defaultValues: { address: "", label: "" },
  });

  // Auto-fill address when wallet connects
  useEffect(() => {
    const connected = externalConnected?.address ?? account?.address;
    if (connected) {
      form.setValue("address", connected);
    }
  }, [account?.address, externalConnected, form]);

  const add = useAddWatchedWallet({
    mutation: {
      onSuccess: (createdWallet) => {
        queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });
        form.reset();
        setLocalWallets((current) => {
          const next = current.filter((wallet) => wallet.address !== createdWallet.address);
          writeLocalWallets(next);
          return next;
        });
        toast({ title: "Wallet added", description: "Now monitoring this address for threats." });
      },
      onError: (error, variables) => {
        const address = variables.data.address;
        const label = variables.data.label;
        const alreadyVisible = mergedWallets.some((wallet) => wallet.address === address);

        if (!alreadyVisible) {
          const fallbackWallet: WalletRow = {
            id: -Date.now(),
            address,
            label,
            isActive: true,
            threatsDetected: 0,
            createdAt: new Date().toISOString(),
            localOnly: true,
          };

          setLocalWallets((current) => {
            const next = [...current.filter((wallet) => wallet.address !== address), fallbackWallet];
            writeLocalWallets(next);
            return next;
          });
        }

        const isNetworkFailure =
          !navigator.onLine ||
          error instanceof TypeError ||
          (error instanceof Error && /fetch|network/i.test(error.message));

        form.setError("address", {
          message: isNetworkFailure
            ? "Backend is offline. Wallet saved locally for now."
            : error instanceof Error
              ? error.message
              : "Failed to add wallet.",
        });
      },
    },
  });

  const remove = useRemoveWatchedWallet({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });
        toast({ title: "Wallet removed" });
      },
    },
  });

  const populate = useMutation({
    mutationFn: ({ address }: { address: string }) => populateWalletApi(address),
    onMutate: ({ address }) => {
      const wallet = wallets?.find((w) => w.address === address);
      if (wallet) setPopulatingId(wallet.id);
    },
    onSuccess: (result) => {
      setPopulatingId(null);
      queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
      toast({
        title: `${result.quarantined} threats quarantined`,
        description: `Seeded ${result.injected} spam objects — ${result.quarantined} were auto-quarantined by the AI agent.`,
      });
    },
    onError: (error) => {
      setPopulatingId(null);
      toast({
        title: "Population failed",
        description: String(error),
        variant: "destructive",
      });
    },
  });

  function onSubmit(values: WalletFormValues) {
    add.mutate({ data: { address: values.address, label: values.label } });
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div>
        <h1 className="text-xl font-bold text-foreground">Monitored Wallets</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Addresses the agent monitors for incoming threats
        </p>
      </div>

      {/* Add wallet form */}
      <div className="rounded-lg border border-border bg-card p-5">
        <div className="text-sm font-semibold text-foreground mb-4">Add Wallet</div>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="address"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-muted-foreground uppercase tracking-wider">Sui Address</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="0x1234567890abcdef..."
                      className="font-mono text-sm"
                      data-testid="input-wallet-address"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="label"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-muted-foreground uppercase tracking-wider">Label</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="e.g. Primary Wallet, Trading Account..."
                      data-testid="input-wallet-label"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button
              type="submit"
              size="sm"
              className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90"
              disabled={add.isPending}
              data-testid="button-add-wallet"
            >
              <Plus className="w-4 h-4" />
              {add.isPending ? "Adding..." : "Add Wallet"}
            </Button>
          </form>
        </Form>
      </div>

      {/* Wallets list */}
      <div className="space-y-3">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-lg" />
          ))
        ) : mergedWallets.length > 0 ? (
          mergedWallets.map((wallet) => (
            <div
              key={wallet.id}
              data-testid={`card-wallet-${wallet.id}`}
              className="rounded-lg border border-border bg-card p-4 flex items-center gap-4"
            >
              <div className="flex items-center justify-center w-9 h-9 rounded-md bg-violet-500/20 border border-violet-500/20 shrink-0">
                <Wallet className="w-4 h-4 text-violet-400" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-foreground" data-testid={`text-wallet-label-${wallet.id}`}>
                    {wallet.label}
                  </span>
                  {account?.address === wallet.address && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400 font-semibold">
                      Connected
                    </span>
                  )}
                  <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${wallet.isActive ? "bg-green-500/15 text-green-400" : "bg-zinc-500/15 text-zinc-400"}`}>
                    {wallet.isActive ? "Active" : "Inactive"}
                  </span>
                  {wallet.localOnly && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-amber-500/15 text-amber-400">
                      Local
                    </span>
                  )}
                </div>
                <div className="font-mono text-xs text-muted-foreground truncate mt-0.5" data-testid={`text-wallet-address-${wallet.id}`}>
                  {wallet.address}
                </div>
                <div className="flex items-center gap-1 mt-1 text-xs text-muted-foreground">
                  {(wallet.threatsDetected ?? 0) > 0 && (
                    <>
                      <AlertTriangle className="w-3 h-3 text-amber-400" />
                      <span className="text-amber-400">{wallet.threatsDetected} threat{(wallet.threatsDetected ?? 0) !== 1 ? "s" : ""} detected</span>
                    </>
                  )}
                  {(wallet.threatsDetected ?? 0) === 0 && <span>No threats detected</span>}
                  <span className="text-border mx-1">·</span>
                  <span>Added {new Date(wallet.createdAt).toLocaleDateString()}</span>
                </div>
              </div>

              {/* Seed spam button */}
              <Button
                variant="ghost"
                size="sm"
                className="h-8 px-2 gap-1.5 text-xs text-muted-foreground hover:text-cyan-400 hover:bg-cyan-500/10 shrink-0"
                onClick={() => populate.mutate({ address: wallet.address })}
                disabled={populate.isPending}
                title="Seed wallet with 5 synthetic spam objects for demo"
                data-testid={`button-seed-wallet-${wallet.id}`}
              >
                {populatingId === wallet.id ? (
                  <>
                    <span className="w-3 h-3 border border-cyan-400 border-t-transparent rounded-full animate-spin" />
                    <span className="hidden sm:inline">Seeding…</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3 h-3" />
                    <span className="hidden sm:inline">Seed spam</span>
                  </>
                )}
              </Button>

              {/* Remove button */}
              <Button
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0 text-muted-foreground hover:text-red-400 hover:bg-red-500/10 shrink-0"
                onClick={() => remove.mutate({ id: wallet.id })}
                disabled={remove.isPending}
                data-testid={`button-remove-wallet-${wallet.id}`}
              >
                <Trash2 className="w-4 h-4" />
              </Button>
            </div>
          ))
        ) : (
          <div className="rounded-lg border border-border bg-card p-10 text-center">
            <Wallet className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
            <div className="text-sm text-muted-foreground">No wallets monitored yet.</div>
            <div className="text-xs text-muted-foreground mt-1">Add a Sui address above to start monitoring.</div>
          </div>
        )}
      </div>
    </div>
  );
}
