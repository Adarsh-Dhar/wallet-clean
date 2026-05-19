import { useState } from "react";
import { useCurrentAccount } from "@mysten/dapp-kit";
import { useListThreats, useReleaseThreat, useBurnThreat, getListThreatsQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge, StatusBadge, RiskBar } from "@/components/ThreatBadge";
import { Button } from "@/components/ui/button";
import { Unlock, Flame, ExternalLink, CheckCircle2, Zap } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

export default function Threats() {
  const account = useCurrentAccount();
  const walletAddress = account?.address;
  const [burningIds, setBurningIds] = useState<Set<number>>(new Set());
  const [activeTab, setActiveTab] = useState<"quarantined" | "released" | "burned">("quarantined");
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const { toast } = useToast();

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
                  <td className="px-4 py-3 text-xs text-muted-foreground font-mono truncate max-w-35">
                    {t.objectType.split("::").pop()}
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
