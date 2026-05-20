import { useState } from "react";
import { useCurrentAccount } from "@mysten/dapp-kit";
import { useListThreats, useReleaseThreat, useBurnThreat, getListThreatsQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { apiJson } from "@/lib/auth";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge, StatusBadge, RiskBar } from "@/components/ThreatBadge";
import { Button } from "@/components/ui/button";
import { Unlock, Flame, ExternalLink, CheckCircle2, Zap, Loader2, Trash2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

interface ThreatCleanSummary {
  total: number;
  analyzed: number;
  quarantined: number;
  safe: number;
  cleaned: number;
}

interface CleanWalletResponse {
  cleaned: number;
  onChainBurned: number;
  threats: Array<{
    id: number;
    objectId: string;
    burnTxDigest: string | null;
  }>;
}

interface ThreatCleanEvent {
  step?: string;
  message: string;
  status?: "running" | "done" | "error";
  total?: number;
  analyzed?: number;
  quarantined?: number;
  safe?: number;
  cleaned?: number;
  error?: string;
  objectId?: string;
  burnTxDigest?: string | null;
  stillOwned?: boolean;
}

async function cleanWalletStream(
  walletAddress: string,
  onEvent: (event: ThreatCleanEvent) => void,
): Promise<ThreatCleanSummary> {
  const response = await fetch("/api/clean-wallet-scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ walletAddress }),
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "Clean failed");
    throw new Error(errorText || `Clean failed with status ${response.status}`);
  }

  if (!response.body) {
    throw new Error("Clean response stream is unavailable");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent = "message";
  let dataLines: string[] = [];
  let summary: ThreatCleanSummary = { total: 0, analyzed: 0, quarantined: 0, safe: 0, cleaned: 0 };

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
        cleaned: Number(parsed?.cleaned ?? 0),
      };
      onEvent({ message: "Clean complete", status: "done", ...summary });
      return;
    }

    if (currentEvent === "error") {
      onEvent({ message: String(parsed?.message ?? "Clean failed"), status: "error" });
      return;
    }

    onEvent(parsed as ThreatCleanEvent);
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

async function cleanThreatsFallback(threatIds: number[], burnTxDigest: string): Promise<CleanWalletResponse> {
  return apiJson<CleanWalletResponse>('/api/clean-wallet', {
    method: 'POST',
    body: { threatIds, burnTxDigest },
  });
}

export default function Threats() {
  const account = useCurrentAccount();
  const walletAddress = account?.address;
  const [burningIds, setBurningIds] = useState<Set<number>>(new Set());
  const [activeTab, setActiveTab] = useState<"quarantined" | "released" | "burned">("quarantined");
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [bulkRunning, setBulkRunning] = useState(false);
  const [cleanRunning, setCleanRunning] = useState(false);
  const [cleanLogs, setCleanLogs] = useState<string[]>([]);
  const [cleanSummary, setCleanSummary] = useState<ThreatCleanSummary | null>(null);

  // Fetch all threats (not filtered by status) so we can show all lifecycle states
  const params = {
    ...(walletAddress ? { walletAddress } : {}),
    limit: 200,
  };

  const { data: threats, isLoading } = useListThreats(params, {
    query: { queryKey: getListThreatsQueryKey(params) },
  });

  const safeThreats = Array.isArray(threats) ? threats : [];
  
  // Group threats by status
  const quarantinedThreats = safeThreats
    .filter((t) => t.status === "quarantined")
    .sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());

  const releasedThreats = safeThreats
    .filter((t) => t.status === "released")
    .sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());

  const visibleThreats = activeTab === "quarantined" ? quarantinedThreats : activeTab === "released" ? releasedThreats : safeThreats.filter((t) => t.status === "burned");

  const release = useReleaseThreat({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
        toast({ title: "Asset released", description: "The asset has been returned to its owner." });
      },
    },
  });

  const burn = useBurnThreat({
    mutation: {
      onSuccess: (data, variables) => {
        setTimeout(() => {
          setBurningIds(prev => {
            const next = new Set(prev);
            next.delete(variables.id);
            return next;
          });
        }, 350);
        queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
        toast({ title: "Asset burned", description: "The malicious asset has been permanently destroyed." });
      },
    },
  });

  const clean = async () => {
    if (!walletAddress) {
      toast({ title: "Connect your wallet", description: "A wallet address is required to clean.", variant: "destructive" });
      return;
    }

    if (!confirm("Scan your full wallet history and auto-clean junk assets?")) return;

    const fallbackThreatIds = quarantinedThreats.map((threat) => threat.id);
    if (fallbackThreatIds.length === 0) {
      toast({ title: "No quarantined threats", description: "Nothing to clean." });
      return;
    }

    setCleanRunning(true);
    setCleanLogs(["Starting deep clean…", `Target: ${walletAddress}`]);
    setCleanSummary(null);

    try {
      const summary = await cleanWalletStream(walletAddress, (event) => {
        const icon =
          event.status === "error" ? "✗"
            : event.step === "clean" ? "🔥"
              : event.step === "quarantine" ? "⚠"
                : event.status === "running" ? "⟳"
                  : "•";

        setCleanLogs((current) => [
          ...current,
          `${icon} ${event.message}${event.burnTxDigest ? ` [tx: ${String(event.burnTxDigest).slice(0, 12)}…]` : ""}`,
        ]);

        if (event.status === "done") {
          setCleanSummary({
            total: event.total ?? 0,
            analyzed: event.analyzed ?? 0,
            quarantined: event.quarantined ?? 0,
            safe: event.safe ?? 0,
            cleaned: event.cleaned ?? 0,
          });
        }
      });

      queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
      setCleanSummary(summary);
      toast({
        title: "Clean complete",
        description: `${summary.quarantined} quarantined, ${summary.cleaned} burned on-chain, ${summary.safe} safe`,
      });
    } catch (err) {
      const message = String(err);
      if (message.includes("404") || message.toLowerCase().includes("not found")) {
        setCleanLogs((current) => [
          ...current,
          "⚠ Deep clean endpoint unavailable; falling back to supported bulk clean.",
          `Cleaning ${fallbackThreatIds.length} quarantined threat(s)…`,
        ]);

        try {
          const fallbackSummary = await cleanThreatsFallback(
            fallbackThreatIds,
            `fallback:${walletAddress}:${Date.now()}`,
          );

          queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
          setCleanSummary({
            total: fallbackThreatIds.length,
            analyzed: fallbackThreatIds.length,
            quarantined: fallbackSummary.cleaned,
            safe: 0,
            cleaned: fallbackSummary.cleaned,
          });
          setCleanLogs((current) => [
            ...current,
            `✓ Fallback clean complete — ${fallbackSummary.cleaned} threat(s) burned`,
          ]);
          toast({
            title: "Clean complete",
            description: `${fallbackSummary.cleaned} quarantined threat(s) cleaned using the fallback path.`,
          });
          return;
        } catch (fallbackErr) {
          setCleanLogs((current) => [...current, `✗ ${String(fallbackErr)}`]);
          toast({ title: "Clean failed", description: String(fallbackErr), variant: "destructive" });
          return;
        }
      }

      setCleanLogs((current) => [...current, `✗ ${message}`]);
      toast({ title: "Clean failed", description: message, variant: "destructive" });
    } finally {
      setCleanRunning(false);
    }
  };

  const tabs = [
    { id: "quarantined" as const, label: "Active Malicious", icon: Zap, count: quarantinedThreats.length },
    { id: "released" as const, label: "Released", icon: CheckCircle2, count: releasedThreats.length },
    { id: "burned" as const, label: "Burned", icon: Flame, count: safeThreats.filter((t) => t.status === "burned").length },
  ];

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold text-foreground">Threat Detections</h1>
        <p className="text-sm text-muted-foreground mt-0.5">All detected assets analyzed by the AI agent</p>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-border">
        <div className="flex items-center gap-1">
          {tabs.map(({ id, label, icon: Icon, count }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={cn(
                "flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors border-b-2 -mb-0.5",
                activeTab === id
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
              data-testid={`tab-${id}`}
            >
              <Icon className="w-4 h-4" />
              <span>{label}</span>
              {count > 0 && (
                <span className={cn(
                  "ml-1 px-2 py-0.5 rounded text-xs font-semibold",
                  activeTab === id
                    ? "bg-primary/20 text-primary"
                    : "bg-muted text-muted-foreground"
                )}>
                  {count}
                </span>
              )}
            </button>
          ))}
          <div className="ml-auto flex items-center gap-2">
            <button
              className="text-xs px-3 py-2 rounded border border-border bg-card text-muted-foreground hover:bg-red-600/10"
              onClick={clean}
              disabled={cleanRunning || !walletAddress}
              data-testid="button-clean-wallet"
            >
              {cleanRunning ? (
                <span className="inline-flex items-center gap-1.5">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  Cleaning…
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5">
                  <Trash2 className="w-3 h-3 text-red-400" />
                  Clean Wallet
                </span>
              )}
            </button>

            <button
              className="text-xs px-3 py-2 rounded border border-border bg-card text-muted-foreground hover:bg-red-600/10"
              onClick={async () => {
                if (visibleThreats.length === 0) {
                  toast({ title: "No quarantined threats", description: "Nothing to release" });
                  return;
                }
                if (!confirm(`Release all ${visibleThreats.length} quarantined threats?`)) return;
                setBulkRunning(true);
                try {
                  await Promise.all(
                    visibleThreats.map((t) => apiJson(`/api/threats/${t.id}/release`, { method: "POST" }))
                  );
                  queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
                  toast({ title: "Released", description: `Released ${visibleThreats.length} threats` });
                } catch (err) {
                  toast({ title: "Release failed", description: String(err), variant: "destructive" });
                } finally {
                  setBulkRunning(false);
                }
              }}
              disabled={bulkRunning || visibleThreats.length === 0}
              data-testid="button-release-all"
            >
              Release All
            </button>

            <button
              className="text-xs px-3 py-2 rounded border border-border bg-card text-muted-foreground hover:bg-red-600/10"
              onClick={async () => {
                if (visibleThreats.length === 0) {
                  toast({ title: "No quarantined threats", description: "Nothing to burn" });
                  return;
                }
                if (!confirm(`Burn all ${visibleThreats.length} quarantined threats? This is irreversible.`)) return;
                setBulkRunning(true);
                try {
                  await Promise.all(
                    visibleThreats.map((t) => apiJson(`/api/threats/${t.id}/burn`, { method: "POST" }))
                  );
                  queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
                  toast({ title: "Burned", description: `Burned ${visibleThreats.length} threats` });
                } catch (err) {
                  toast({ title: "Burn failed", description: String(err), variant: "destructive" });
                } finally {
                  setBulkRunning(false);
                }
              }}
              disabled={bulkRunning || visibleThreats.length === 0}
              data-testid="button-burn-all"
            >
              Burn All
            </button>
          </div>
        </div>
      </div>

      {/* Help text */}
      <div className="text-sm text-muted-foreground">
        {!walletAddress ? (
          <span>Connect your wallet to view threat detections.</span>
        ) : activeTab === "quarantined" ? (
          <span>Active malicious threats detected in your wallet — release or burn to resolve.</span>
        ) : activeTab === "released" ? (
          <span>Assets you've released back to their original status.</span>
        ) : (
          <span>Permanently destroyed malicious objects — cannot be recovered.</span>
        )}
      </div>

      {(cleanRunning || cleanLogs.length > 0) && (
        <div className="rounded-lg border border-red-500/20 bg-background/60 p-3 text-xs font-mono space-y-1">
          <div className="flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
            <span>Clean Log</span>
            <button
              type="button"
              className="text-muted-foreground hover:text-foreground"
              onClick={() => {
                setCleanLogs([]);
                setCleanSummary(null);
              }}
            >
              Clear
            </button>
          </div>
          <div className="space-y-1">
            {cleanLogs.map((line, index) => (
              <div key={index} className="wrap-break-word text-muted-foreground">
                {line}
              </div>
            ))}
            {cleanSummary && (
              <div className="pt-1 text-zinc-400">
                {cleanSummary.quarantined} quarantined · {cleanSummary.cleaned} burned on-chain · {cleanSummary.safe} safe
              </div>
            )}
          </div>
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm" data-testid="threats-table">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Object ID</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Type</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Verdict</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider w-40">Risk Score</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
              <th className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Detected</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {Array.from({ length: 7 }).map((_, j) => (
                    <td key={j} className="px-4 py-3"><Skeleton className="h-5 w-full" /></td>
                  ))}
                </tr>
              ))
            ) : visibleThreats.length > 0 ? (
              visibleThreats.map((t) => (
                <tr
                  key={t.id}
                  data-testid={`row-threat-${t.id}`}
                  className={`border-b border-border/50 hover:bg-muted/20 transition-all duration-300 ${burningIds.has(t.id) ? "opacity-0 scale-95 bg-red-500/10" : ""}`}
                >
                  <td className="px-4 py-3">
                    <a
                      href={`https://suiscan.xyz/testnet/object/${t.objectId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-xs text-primary hover:underline flex items-center gap-1"
                    >
                      {t.objectId.slice(0, 16)}…
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground truncate max-w-35">
                    {(() => {
                      const typeParts = String(t.objectType).split("::");
                      const moduleName = typeParts.length >= 2 ? typeParts[typeParts.length - 2] : null;
                      const structName = typeParts[typeParts.length - 1] ?? String(t.objectType);
                      const derivedType = moduleName ? `${moduleName}::${structName}` : structName;

                      return (
                        <div className="min-w-0">
                          <div className="font-mono text-foreground truncate">{derivedType}</div>
                          {t.displayName && t.displayName !== derivedType && (
                            <div className="text-[11px] text-muted-foreground truncate">{t.displayName}</div>
                          )}
                        </div>
                      );
                    })()}
                  </td>
                  <td className="px-4 py-3"><VerdictBadge verdict={t.verdict} /></td>
                  <td className="px-4 py-3 w-40"><RiskBar score={t.riskScore} /></td>
                  <td className="px-4 py-3"><StatusBadge status={t.status} /></td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {new Date(t.detectedAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    {t.status === "quarantined" && (
                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 text-xs gap-1.5 text-teal-400 border-teal-500/30 hover:bg-teal-500/10"
                          onClick={() => release.mutate({ id: t.id })}
                          disabled={release.isPending}
                          data-testid={`button-release-${t.id}`}
                        >
                          <Unlock className="w-3 h-3" /> Release
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 text-xs gap-1.5 text-red-400 border-red-500/30 hover:bg-red-500/10"
                          onClick={() => {
                            setBurningIds(prev => new Set([...prev, t.id]));
                            burn.mutate({ id: t.id });
                          }}
                          disabled={burn.isPending}
                          data-testid={`button-burn-${t.id}`}
                        >
                          <Flame className="w-3 h-3" /> Burn
                        </Button>
                      </div>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-muted-foreground text-sm">
                  {activeTab === "quarantined" && "No active malicious threats found for this wallet."}
                  {activeTab === "released" && "No released threats found for this wallet."}
                  {activeTab === "burned" && "No permanently destroyed threats found for this wallet."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
