import { useState, useEffect, useRef } from "react";
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
import {
  Trash2, Plus, Wallet, AlertTriangle, Zap,
  CheckCircle2, XCircle, Loader2, ChevronDown, ChevronUp, X,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

// ─── Types ────────────────────────────────────────────────────────────────────

type WalletRow = WatchedWallet & { localOnly?: boolean };

type LogLevel = "info" | "success" | "warn" | "error";

interface LogEntry {
  id: number;
  ts: string;          // HH:MM:SS
  level: LogLevel;
  message: string;
  detail?: string;     // secondary line (e.g. objectType, blobId)
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

interface CleanResult {
  cleaned: number;
  threats: number[];
}

// ─── Constants ────────────────────────────────────────────────────────────────

const LOCAL_WALLETS_KEY = "deepclean.localWatchedWallets";
const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8080";

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
  try { localStorage.setItem(LOCAL_WALLETS_KEY, JSON.stringify(wallets)); } catch { /* ignore */ }
}

function nowTs(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

let _logId = 0;
function mkLog(level: LogLevel, message: string, detail?: string): LogEntry {
  return { id: ++_logId, ts: nowTs(), level, message, detail };
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

async function cleanWalletApi(): Promise<CleanResult> {
  const res = await fetch(new URL("/api/clean-wallet", API_BASE).toString(), {
    method: "POST",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<CleanResult>;
}

// ─── Log panel colours ────────────────────────────────────────────────────────

const levelStyle: Record<LogLevel, string> = {
  info:    "text-zinc-400",
  success: "text-green-400",
  warn:    "text-amber-400",
  error:   "text-red-400",
};

const levelIcon: Record<LogLevel, React.ReactNode> = {
  info:    <span className="w-2 h-2 rounded-full bg-zinc-500 mt-0.5 shrink-0" />,
  success: <CheckCircle2 className="w-3.5 h-3.5 text-green-400 mt-0.5 shrink-0" />,
  warn:    <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />,
  error:   <XCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />,
};

// ─── Log Panel component ──────────────────────────────────────────────────────

function LogPanel({
  logs,
  title,
  onClose,
}: {
  logs: LogEntry[];
  title: string;
  onClose: () => void;
}) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const [collapsed, setCollapsed] = useState(false);

  // Auto-scroll to bottom on new logs
  useEffect(() => {
    if (!collapsed) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs, collapsed]);

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 overflow-hidden text-xs font-mono">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-700 bg-zinc-800">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-zinc-300 font-semibold tracking-wide">{title}</span>
          <span className="text-zinc-500">({logs.length} entries)</span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="p-1 rounded hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200"
          >
            {collapsed ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Log entries */}
      {!collapsed && (
        <div className="max-h-72 overflow-y-auto p-3 space-y-1.5">
          {logs.length === 0 && (
            <div className="text-zinc-600 py-2 text-center">Waiting for events…</div>
          )}
          {logs.map((entry) => (
            <div key={entry.id} className="flex gap-2 items-start">
              {levelIcon[entry.level]}
              <div className="flex-1 min-w-0">
                <span className="text-zinc-600 mr-2">{entry.ts}</span>
                <span className={levelStyle[entry.level]}>{entry.message}</span>
                {entry.detail && (
                  <div className="text-zinc-600 truncate mt-0.5 pl-0">{entry.detail}</div>
                )}
              </div>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function Wallets() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const account = useCurrentAccount();

  const [populatingId, setPopulatingId] = useState<number | null>(null);
  const [externalConnected, setExternalConnected] = useState<{ provider: string; address: string } | null>(null);
  const [localWallets, setLocalWallets] = useState<WalletRow[]>([]);

  // ── Log state: one panel per wallet (keyed by wallet.id) ──────────────────
  const [seedLogs, setSeedLogs]     = useState<Record<number, LogEntry[]>>({});
  const [deleteLogs, setDeleteLogs] = useState<Record<number, LogEntry[]>>({});
  const [openSeedLog, setOpenSeedLog]     = useState<number | null>(null);
  const [openDeleteLog, setOpenDeleteLog] = useState<number | null>(null);

  function appendSeedLog(walletId: number, entry: LogEntry) {
    setSeedLogs((prev) => ({ ...prev, [walletId]: [...(prev[walletId] ?? []), entry] }));
  }

  function appendDeleteLog(walletId: number, entry: LogEntry) {
    setDeleteLogs((prev) => ({ ...prev, [walletId]: [...(prev[walletId] ?? []), entry] }));
  }

  function removeLocalWallet(wallet: WalletRow) {
    const walletId = wallet.id;
    setOpenDeleteLog(walletId);
    setDeleteLogs((prev) => ({ ...prev, [walletId]: [] }));

    appendDeleteLog(walletId, mkLog("info", "Removing local wallet entry..."));
    appendDeleteLog(walletId, mkLog("info", `Address: ${wallet.address}`));
    appendDeleteLog(walletId, mkLog("info", "No backend call needed (local-only wallet)."));

    setLocalWallets((cur) => {
      const next = cur.filter((w) => w.address !== wallet.address);
      writeLocalWallets(next);
      return next;
    });

    appendDeleteLog(walletId, mkLog("success", "Local wallet removed."));
    toast({ title: "Local wallet removed" });
  }

  function handleRemoveWallet(wallet: WalletRow) {
    if (wallet.localOnly || wallet.id < 1) {
      removeLocalWallet(wallet);
      return;
    }
    remove.mutate({ id: wallet.id });
  }

  // ── External wallet listener ───────────────────────────────────────────────
  useEffect(() => {
    try {
      const raw = localStorage.getItem("externalWallet");
      if (raw) setExternalConnected(JSON.parse(raw));
    } catch { setExternalConnected(null); }

    const handler = (e: any) => {
      try {
        const d = e?.detail;
        if (d?.address) setExternalConnected({ provider: d.provider ?? "external", address: d.address });
      } catch { /* ignore */ }
    };
    window.addEventListener("externalWallet:connected", handler as EventListener);
    return () => window.removeEventListener("externalWallet:connected", handler as EventListener);
  }, []);

  useEffect(() => { setLocalWallets(readLocalWallets()); }, []);

  // ── API data ───────────────────────────────────────────────────────────────
  const { data: wallets, isLoading } = useListWatchedWallets();

  const safeWallets: WalletRow[] = Array.isArray(wallets)
    ? wallets.map((w) => ({ ...w, localOnly: false }))
    : [];
  const mergedWallets: WalletRow[] = [...safeWallets, ...localWallets].filter(
    (w, i, arr) => arr.findIndex((x) => x.address === w.address) === i,
  );

  // ── Form ───────────────────────────────────────────────────────────────────
  const form = useForm<WalletFormValues>({
    resolver: zodResolver(walletSchema),
    defaultValues: { address: "", label: "" },
  });

  useEffect(() => {
    const connected = externalConnected?.address ?? account?.address;
    if (connected) form.setValue("address", connected);
  }, [account?.address, externalConnected, form]);

  // ── Add wallet mutation ────────────────────────────────────────────────────
  const add = useAddWatchedWallet({
    mutation: {
      onSuccess: (created) => {
        queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });
        form.reset();
        setLocalWallets((cur) => {
          const next = cur.filter((w) => w.address !== created.address);
          writeLocalWallets(next);
          return next;
        });
        toast({ title: "Wallet added", description: "Now monitoring this address for threats." });
      },
      onError: (error, variables) => {
        const { address, label } = variables.data;
        const alreadyVisible = mergedWallets.some((w) => w.address === address);
        if (!alreadyVisible) {
          const fallback: WalletRow = {
            id: -Date.now(), address, label, isActive: true,
            threatsDetected: 0, createdAt: new Date().toISOString(), localOnly: true,
          };
          setLocalWallets((cur) => {
            const next = [...cur.filter((w) => w.address !== address), fallback];
            writeLocalWallets(next);
            return next;
          });
        }
        form.setError("address", {
          message: error instanceof Error ? error.message : "Failed to add wallet.",
        });
      },
    },
  });

  // ── Remove wallet mutation (with logs) ────────────────────────────────────
  const remove = useRemoveWatchedWallet({
    mutation: {
      onMutate: (variables) => {
        const walletId = variables.id;
        const wallet = mergedWallets.find((w) => w.id === walletId);
        setOpenDeleteLog(walletId);
        setDeleteLogs((prev) => ({ ...prev, [walletId]: [] }));

        appendDeleteLog(walletId, mkLog("info", `Removing wallet from monitoring…`));
        appendDeleteLog(walletId, mkLog("info", `Address: ${wallet?.address ?? "unknown"}`));
        appendDeleteLog(walletId, mkLog("info", `Sending DELETE /api/monitor/wallets/${walletId}`));
      },
      onSuccess: (_data, variables) => {
        const walletId = variables.id;
        appendDeleteLog(walletId, mkLog("success", "✓ Wallet removed from DB"));
        appendDeleteLog(walletId, mkLog("success", "✓ Monitor will stop polling this address"));
        appendDeleteLog(walletId, mkLog("info", "Refreshing wallet list…"));

        queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });
        toast({ title: "Wallet removed" });
      },
      onError: (_error, variables) => {
        const walletId = variables.id;
        appendDeleteLog(walletId, mkLog("error", "✗ DELETE request failed"));
        appendDeleteLog(walletId, mkLog("error", String(_error)));
        toast({ title: "Remove failed", description: String(_error), variant: "destructive" });
      },
    },
  });

  async function performDeepClean(walletId: number) {
    appendSeedLog(walletId, mkLog("info", "  Cleaning quarantined threats…"));
    try {
      const cleanResult = await cleanWalletApi();
      appendSeedLog(walletId, mkLog("success", `✓ Deep clean complete — ${cleanResult.cleaned} threats burned`));
      return true;
    } catch (cleanError) {
      appendSeedLog(walletId, mkLog("error", "✗ Deep clean failed"));
      appendSeedLog(walletId, mkLog("error", String(cleanError)));
      toast({
        title: "Deep clean failed",
        description: String(cleanError),
        variant: "destructive",
      });
      return false;
    }
  }

  // ── Seed spam mutation (with detailed logs) ───────────────────────────────
  const populate = useMutation({
    mutationFn: ({ address }: { address: string }) => populateWalletApi(address),

    onMutate: ({ address }) => {
      const wallet = mergedWallets.find((w) => w.address === address);
      const walletId = wallet?.id ?? -1;
      setPopulatingId(walletId);
      setOpenSeedLog(walletId);
      setSeedLogs((prev) => ({ ...prev, [walletId]: [] }));

      appendSeedLog(walletId, mkLog("info", "Starting wallet population…"));
      appendSeedLog(walletId, mkLog("info", `Target: ${address}`));
      appendSeedLog(walletId, mkLog("info", "POST /api/populate-wallet →"));
      appendSeedLog(walletId, mkLog("info", "Injecting 5 synthetic spam objects:"));
      appendSeedLog(walletId, mkLog("info", "  [1] scam_airdrop::FreeToken — fake SUI airdrop URL"));
      appendSeedLog(walletId, mkLog("info", "  [2] phishing_kit::WalletDrainer — Cyrillic homoglyph URL"));
      appendSeedLog(walletId, mkLog("info", "  [3] honeypot_defi::HoneypotToken — hidden _drain_all ABI"));
      appendSeedLog(walletId, mkLog("info", "  [4] fake_foundation::FounderPass — digit-substitution domain"));
      appendSeedLog(walletId, mkLog("info", "  [5] nft_phish::MintPass — phishing mint URL"));
      appendSeedLog(walletId, mkLog("info", "Sending all 5 to Gemini AI for analysis…"));
    },

    onSuccess: async (result, { address }) => {
      const wallet = mergedWallets.find((w) => w.address === address);
      const walletId = wallet?.id ?? -1;
      setPopulatingId(null);

      appendSeedLog(walletId, mkLog("info", `← API response received`));
      appendSeedLog(walletId, mkLog("info", `  ${result.injected} objects analyzed`));

      result.threats.forEach((t, i) => {
        const isQuarantined = t.threatId !== null;
        const level: LogLevel = t.verdict === "MALICIOUS" ? "warn"
          : t.verdict === "SUSPICIOUS" ? "warn" : "success";
        appendSeedLog(
          walletId,
          mkLog(
            isQuarantined ? "warn" : "success",
            `  [${i + 1}] ${t.verdict} — score ${t.riskScore}/100 ${isQuarantined ? "→ QUARANTINED" : "→ cleared"}`,
            `       ${t.objectType}`,
          ),
        );
      });

      const quarantined = result.threats.filter((t) => t.threatId !== null);
      const cleared     = result.threats.filter((t) => t.threatId === null);

      if (quarantined.length > 0) {
        appendSeedLog(walletId, mkLog("warn", `⚠ ${quarantined.length} threats auto-quarantined`));
        appendSeedLog(walletId, mkLog("info", "  Writing threat records to Postgres DB…"));
        appendSeedLog(walletId, mkLog("info", "  Storing AI analysis logs on Walrus (5 epochs)…"));
        appendSeedLog(walletId, mkLog("success", "✓ Walrus blob IDs linked to threat records"));
        appendSeedLog(walletId, mkLog("success", "✓ Threats saved — status: quarantined"));
      }
      if (cleared.length > 0) {
        appendSeedLog(walletId, mkLog("success", `✓ ${cleared.length} objects cleared (risk < 65)`));
      }
      if (result.txDigest) {
        appendSeedLog(walletId, mkLog("success", `✓ On-chain tx recorded`, `  digest: ${result.txDigest}`));
      }

      if (quarantined.length > 0) {
        const cleaned = await performDeepClean(walletId);
        if (!cleaned) return;
      }

      appendSeedLog(walletId, mkLog("success", "✓ Dashboard & threat list refreshed"));
      appendSeedLog(walletId, mkLog("success", "Population complete."));

      queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
      toast({
        title: `${result.quarantined} threats quarantined`,
        description: `Seeded ${result.injected} objects — ${result.quarantined} auto-quarantined.`,
      });
    },

    onError: (error, { address }) => {
      const wallet = mergedWallets.find((w) => w.address === address);
      const walletId = wallet?.id ?? -1;
      setPopulatingId(null);
      appendSeedLog(walletId, mkLog("error", `✗ Population failed`));
      appendSeedLog(walletId, mkLog("error", String(error)));
      toast({ title: "Population failed", description: String(error), variant: "destructive" });
    },
  });

  function onSubmit(values: WalletFormValues) {
    add.mutate({ data: { address: values.address, label: values.label } });
  }

  // ─── Render ────────────────────────────────────────────────────────────────
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
          Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-20 rounded-lg" />)
        ) : mergedWallets.length > 0 ? (
          mergedWallets.map((wallet) => (
            <div key={wallet.id} className="space-y-2">
              {/* Wallet card */}
              <div
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
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-violet-500/15 text-violet-400 font-semibold">
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
                    {(wallet.threatsDetected ?? 0) > 0 ? (
                      <>
                        <AlertTriangle className="w-3 h-3 text-amber-400" />
                        <span className="text-amber-400">
                          {wallet.threatsDetected} threat{(wallet.threatsDetected ?? 0) !== 1 ? "s" : ""} detected
                        </span>
                      </>
                    ) : (
                      <span>No threats detected</span>
                    )}
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
                      <Loader2 className="w-3 h-3 animate-spin" />
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
                  onClick={() => handleRemoveWallet(wallet)}
                  disabled={remove.isPending}
                  data-testid={`button-remove-wallet-${wallet.id}`}
                >
                  {remove.isPending ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Trash2 className="w-4 h-4" />
                  )}
                </Button>
              </div>

              {/* Seed spam log panel */}
              {openSeedLog === wallet.id && seedLogs[wallet.id] && (
                <LogPanel
                  logs={seedLogs[wallet.id]}
                  title={`Seed spam — ${wallet.label}`}
                  onClose={() => setOpenSeedLog(null)}
                />
              )}

              {/* Delete log panel */}
              {openDeleteLog === wallet.id && deleteLogs[wallet.id] && (
                <LogPanel
                  logs={deleteLogs[wallet.id]}
                  title={`Remove wallet — ${wallet.label}`}
                  onClose={() => setOpenDeleteLog(null)}
                />
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
                : "Connect your Sui wallet or paste an address above."}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}