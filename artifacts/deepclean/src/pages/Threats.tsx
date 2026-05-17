import { useState } from "react";
import { useListThreats, useReleaseThreat, useBurnThreat, getListThreatsQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge, StatusBadge, RiskBar } from "@/components/ThreatBadge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Unlock, Flame, ExternalLink } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Threats() {
  const [verdict, setVerdict] = useState<string>("all");
  const [status, setStatus] = useState<string>("all");
  const [, setLocation] = useLocation();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const params = {
    ...(verdict !== "all" ? { verdict: verdict as "SAFE" | "SUSPICIOUS" | "MALICIOUS" } : {}),
    ...(status !== "all" ? { status: status as "quarantined" | "released" | "burned" } : {}),
    limit: 50,
  };

  const { data: threats, isLoading } = useListThreats(params, {
    query: { queryKey: getListThreatsQueryKey(params) },
  });

  const safeThreats = Array.isArray(threats) ? threats : [];

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
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
        toast({ title: "Asset burned", description: "The malicious asset has been permanently destroyed." });
      },
    },
  });

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-xl font-bold text-foreground">Threat Detections</h1>
        <p className="text-sm text-muted-foreground mt-0.5">All detected assets analyzed by the AI agent</p>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={verdict} onValueChange={setVerdict}>
          <SelectTrigger className="w-40" data-testid="filter-verdict">
            <SelectValue placeholder="All verdicts" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All verdicts</SelectItem>
            <SelectItem value="MALICIOUS">Malicious</SelectItem>
            <SelectItem value="SUSPICIOUS">Suspicious</SelectItem>
            <SelectItem value="SAFE">Safe</SelectItem>
          </SelectContent>
        </Select>
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-40" data-testid="filter-status">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="quarantined">Quarantined</SelectItem>
            <SelectItem value="released">Released</SelectItem>
            <SelectItem value="burned">Burned</SelectItem>
          </SelectContent>
        </Select>
        {(verdict !== "all" || status !== "all") && (
          <Button variant="ghost" size="sm" onClick={() => { setVerdict("all"); setStatus("all"); }}>
            Clear filters
          </Button>
        )}
        <Button
          size="sm"
          variant="destructive"
          className="ml-auto gap-2"
          disabled
          title="Deep clean all is disabled. Clean from a connected wallet row in Wallets."
          data-testid="button-clean-all"
        >
          <Flame className="w-4 h-4" />
          Deep Clean All (Disabled)
        </Button>
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
            ) : safeThreats.length > 0 ? (
              safeThreats.map((t) => (
                <tr
                  key={t.id}
                  data-testid={`row-threat-${t.id}`}
                  className="border-b border-border/50 hover:bg-muted/20 transition-colors"
                >
                  <td className="px-4 py-3">
                    <button
                      onClick={() => setLocation(`/threats/${t.id}`)}
                      className="font-mono text-xs text-primary hover:underline flex items-center gap-1"
                      data-testid={`link-threat-${t.id}`}
                    >
                      {t.objectId.slice(0, 16)}…
                      <ExternalLink className="w-3 h-3" />
                    </button>
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
                          onClick={() => burn.mutate({ id: t.id })}
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
                  No threats found. The agent is monitoring your wallets.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
