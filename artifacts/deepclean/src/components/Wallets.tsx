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
} from "@workspace/api-client-react";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { walletSchema, type WalletFormValues } from "@/lib/schemas";
import { Trash2, Plus, Wallet, AlertTriangle, Zap, PlugZap, Sparkles, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface PopulateResult {
  injected: number;
  quarantined: number;
  seededCount?: number;
  syntheticCount?: number;
  realCount?: number;
  txDigest: string | null;
  onChainDigest?: string | null;
  threats: Array<{
    objectId: string;
    objectType: string;
    verdict: string;
    riskScore: number;
    threatId: number | null;
  }>;
}

interface ScanSummary {
  total: number;
  analyzed: number;
  quarantined: number;
  safe: number;
}

interface ScanEvent {
  step?: string;
  message: string;
  status?: "running" | "done" | "error";
  objectId?: string;
  objectType?: string;
  threatId?: number;
  riskScore?: number;
  verdict?: string;
  count?: number;
  onChainDigest?: string | null;
  error?: string;
  total?: number;
  analyzed?: number;
  quarantined?: number;
  safe?: number;
  cleaned?: number;
}
async function populateWalletApi(targetAddress: string): Promise<PopulateResult> {
  const res = await fetch("/api/populate-wallet", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targetAddress }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<PopulateResult>;
}

async function scanWalletStream(
  walletAddress: string,
  onEvent: (event: ScanEvent) => void,
): Promise<ScanSummary> {
  const response = await fetch("/api/scan-wallet", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ walletAddress }),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "Scan failed");
    throw new Error(errorText || `Scan failed with status ${response.status}`);
  }

  if (!response.body) {
    throw new Error("Scan response stream is unavailable");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent = "message";
  let dataLines: string[] = [];
  let summary: ScanSummary = { total: 0, analyzed: 0, quarantined: 0, safe: 0 };

  const dispatch = () => {
    if (dataLines.length === 0) return;
    const raw = dataLines.join("\n");
    dataLines = [];

    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return;
    }

    if (currentEvent === "done") {
      summary = {
        total: Number(parsed?.total ?? 0),
        analyzed: Number(parsed?.analyzed ?? 0),
        quarantined: Number(parsed?.quarantined ?? 0),
        safe: Number(parsed?.safe ?? 0),
      };
      onEvent({ message: "Scan complete", status: "done", ...summary });
      return;
    }

    if (currentEvent === "error") {
      onEvent({ message: String(parsed?.message ?? "Scan failed"), status: "error" });
      return;
    }

    onEvent(parsed as ScanEvent);
  };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split(/\r?\n/);
    buffer = lines.pop() ?? "";

    for (const line of lines) {
      if (!line) {
        dispatch();
        currentEvent = "message";
        continue;
      }

      if (line.startsWith("event: ")) {
        currentEvent = line.slice(7).trim();
        continue;
      }

      if (line.startsWith("data: ")) {
        dataLines.push(line.slice(6));
      }
    }
  }

  if (buffer.trim()) {
    for (const line of buffer.split(/\r?\n/)) {
      if (line.startsWith("event: ")) {
        currentEvent = line.slice(7).trim();
      } else if (line.startsWith("data: ")) {
        dataLines.push(line.slice(6));
      }
    }
    dispatch();
  }

  return summary;
}
export default function Wallets() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [populatingId, setPopulatingId] = useState<number | null>(null);
  const [scanningId, setScanningId] = useState<number | null>(null);
  const [scanLogs, setScanLogs] = useState<Record<number, string[]>>({});
  const [scanSummary, setScanSummary] = useState<Record<number, ScanSummary | null>>({});
  const [openScanLog, setOpenScanLog] = useState<number | null>(null);

  // Get the currently connected Sui wallet
  const account = useCurrentAccount();
  const [externalConnected, setExternalConnected] = useState<{ provider: string; address: string } | null>(null);

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

  const { data: wallets, isLoading } = useListWatchedWallets();

  const safeWallets = Array.isArray(wallets) ? wallets : [];

  const form = useForm<WalletFormValues>({
    resolver: zodResolver(walletSchema),
    defaultValues: { address: "", label: "" },
  });

  // Auto-fill the address field whenever the user connects their wallet
  useEffect(() => {
    const connected = externalConnected?.address ?? account?.address;
    if (connected) {
      form.setValue("address", connected, { shouldValidate: true });
    }
  }, [account?.address, form]);

  const add = useAddWatchedWallet({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });
        form.reset();
        toast({ title: "Wallet added", description: "Now monitoring this address for threats." });
      },
      onError: () => {
        form.setError("address", { message: "Failed to add wallet. Address may already be monitored." });
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

      const onChainNote = result.onChainDigest
        ? ` On-chain proof recorded.`
        : "";

      const breakdown: string[] = [];
      if (result.seededCount && result.seededCount > 0) {
        breakdown.push(`${result.seededCount} on-chain seeded`);
      }
      if (result.syntheticCount && result.syntheticCount > 0) {
        breakdown.push(`${result.syntheticCount} synthetic`);
      }
      if (result.realCount && result.realCount > 0) {
        breakdown.push(`${result.realCount} real wallet`);
      }

      const breakdownText = breakdown.length > 0 ? ` (${breakdown.join(", ")})` : "";

      toast({
        title: `${result.quarantined} threats quarantined`,
        description: `Seeded ${result.injected} spam objects${breakdownText} — ${result.quarantined} were auto-quarantined by the AI agent.${onChainNote}`,
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

  const scan = useMutation({
    mutationFn: ({ address, walletId }: { address: string; walletId: number }) =>
      scanWalletStream(address, (event) => {
        setScanLogs((current) => ({
          ...current,
          [walletId]: [
            ...(current[walletId] ?? []),
            event.status === "error"
              ? `✗ ${event.message}`
              : event.status === "running"
                ? `⟳ ${event.message}`
                : event.step === "quarantine"
                  ? `✓ ${event.message}`
                  : `• ${event.message}`,
          ],
        }));

        if (event.status === "done") {
          setScanSummary((current) => ({
            ...current,
            [walletId]: {
              total: event.total ?? 0,
              analyzed: event.analyzed ?? 0,
              quarantined: event.quarantined ?? 0,
              safe: event.safe ?? 0,
            },
          }));
        }
      }),
    onMutate: ({ walletId, address }) => {
      setScanningId(walletId);
      setOpenScanLog(walletId);
      setScanLogs((current) => ({
        ...current,
        [walletId]: [`Starting full wallet scan…`, `Target: ${address}`],
      }));
      setScanSummary((current) => ({ ...current, [walletId]: null }));
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });
    },
    onSettled: () => {
      setScanningId(null);
    },
    onError: (error) => {
      toast({
        title: "Scan failed",
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

      {/* Connected wallet quick-add banner */}
      {account && (
        <div className="rounded-lg border border-violet-500/30 bg-violet-500/5 px-4 py-3 flex items-center gap-3">
          <PlugZap className="w-4 h-4 text-violet-400 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-foreground">Wallet connected</div>
            <div className="font-mono text-xs text-muted-foreground truncate">{account.address}</div>
          </div>
          <Button
            size="sm"
            variant="outline"
            className="shrink-0 text-xs border-violet-500/40 hover:bg-violet-500/10 hover:text-violet-300"
            onClick={() => {
              form.setValue("address", account.address, { shouldValidate: true });
              form.setValue("label", "My Wallet", { shouldValidate: true });
            }}
          >
            Use this address
          </Button>
        </div>
      )}

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
                      placeholder="0x1234567890abcdef…"
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
                      placeholder="e.g. Primary Wallet, Trading Account…"
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
              {add.isPending ? "Adding…" : "Add Wallet"}
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
        ) : safeWallets.length > 0 ? (
          safeWallets.map((wallet) => (
            <div
              key={wallet.id}
              data-testid={`card-wallet-${wallet.id}`}
              className="rounded-lg border border-border bg-card p-4 flex flex-wrap items-center gap-4"
            >
              <div className="flex items-center justify-center w-9 h-9 rounded-md bg-violet-500/20 border border-violet-500/20 shrink-0">
                <Wallet className="w-4 h-4 text-violet-400" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-foreground" data-testid={`text-wallet-label-${wallet.id}`}>
                    {wallet.label}
                  </span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${wallet.isActive ? "bg-green-500/15 text-green-400" : "bg-zinc-500/15 text-zinc-400"}`}>
                    {wallet.isActive ? "Active" : "Inactive"}
                  </span>
                  {/* Badge when this is the connected wallet */}
                  {account?.address === wallet.address && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-violet-500/15 text-violet-400">
                      Connected
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

              <div className="flex items-center gap-2 shrink-0">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 px-2 gap-1.5 text-xs text-muted-foreground hover:text-violet-400 hover:bg-violet-500/10 shrink-0"
                  onClick={() => scan.mutate({ address: wallet.address, walletId: wallet.id })}
                  disabled={scan.isPending}
                  title="Scan all owned objects and quarantine new threats"
                  data-testid={`button-scan-wallet-${wallet.id}`}
                >
                  {scanningId === wallet.id ? (
                    <>
                      <Loader2 className="w-3 h-3 animate-spin" />
                      <span className="hidden sm:inline">Scanning…</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3 h-3" />
                      <span className="hidden sm:inline">Scan</span>
                    </>
                  )}
                </Button>

                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 px-2 gap-1.5 text-xs text-muted-foreground hover:text-cyan-400 hover:bg-cyan-500/10 shrink-0"
                  onClick={() => populate.mutate({ address: wallet.address })}
                  disabled={populate.isPending || scan.isPending}
                  title="Scan wallet objects for threats"
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
                      <span className="hidden sm:inline">Populate</span>
                    </>
                  )}
                </Button>
              </div>

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

              {openScanLog === wallet.id && (
                <div className="basis-full rounded-lg border border-border bg-background/50 p-3 text-xs font-mono space-y-1">
                  <div className="flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
                    <span>Scan Log</span>
                    <button
                      type="button"
                      className="text-muted-foreground hover:text-foreground"
                      onClick={() => setOpenScanLog(null)}
                    >
                      Close
                    </button>
                  </div>

                  {(scanLogs[wallet.id]?.length ?? 0) > 0 ? (
                    <div className="space-y-1">
                      {scanLogs[wallet.id]!.map((line, index) => (
                        <div key={index} className="wrap-break-word text-muted-foreground">
                          {line}
                        </div>
                      ))}
                      {scanSummary[wallet.id] && (
                        <div className="pt-1 text-zinc-400">
                          {scanSummary[wallet.id]!.quarantined} quarantined, {scanSummary[wallet.id]!.safe} safe, {scanSummary[wallet.id]!.analyzed} analyzed.
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-muted-foreground">Waiting for scan output…</div>
                  )}
                </div>
              )}

            </div>
          ))
        ) : (
          <div className="rounded-lg border border-border bg-card p-10 text-center">
            <Wallet className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
            <div className="text-sm text-muted-foreground">No wallets monitored yet.</div>
            <div className="text-xs text-muted-foreground mt-1">
              {account
                ? "Your connected wallet address has been pre-filled above — just add a label and click Add Wallet."
                : "Connect your Sui wallet using the sidebar button, or paste an address above."}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}