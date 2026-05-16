import { useGetThreat, useReleaseThreat, useBurnThreat, getGetThreatQueryKey, getListThreatsQueryKey } from "@workspace/api-client-react";
import { useRoute, useLocation } from "wouter";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Copy, Flame, Unlock, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge, StatusBadge, RiskBar, ReasonLabel } from "@/components/ThreatBadge";
import { useToast } from "@/hooks/use-toast";

export default function ThreatDetail() {
  const [, params] = useRoute("/threats/:id");
  const [, setLocation] = useLocation();
  const id = Number(params?.id);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: threat, isLoading } = useGetThreat(id, {
    query: { enabled: !!id, queryKey: getGetThreatQueryKey(id) },
  });

  const release = useReleaseThreat({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getGetThreatQueryKey(id) });
        queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
        toast({ title: "Asset released" });
      },
    },
  });

  const burn = useBurnThreat({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getGetThreatQueryKey(id) });
        queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
        toast({ title: "Asset burned" });
      },
    },
  });

  function copyToClipboard(text: string, label: string) {
    navigator.clipboard.writeText(text);
    toast({ title: `${label} copied to clipboard` });
  }

  if (isLoading) {
    return (
      <div className="p-6 space-y-5">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  if (!threat) {
    return (
      <div className="p-6">
        <div className="text-muted-foreground">Threat not found.</div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="sm"
          className="gap-2 text-muted-foreground hover:text-foreground"
          onClick={() => setLocation("/threats")}
          data-testid="button-back"
        >
          <ArrowLeft className="w-4 h-4" /> Back
        </Button>
      </div>

      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <VerdictBadge verdict={threat.verdict} />
            <StatusBadge status={threat.status} />
          </div>
          <h1 className="text-lg font-bold text-foreground font-mono mt-2">{threat.objectId}</h1>
          <div className="text-sm text-muted-foreground mt-1 font-mono">{threat.objectType}</div>
        </div>
        {threat.status === "quarantined" && (
          <div className="flex gap-2 shrink-0">
            <Button
              variant="outline"
              size="sm"
              className="gap-2 text-teal-400 border-teal-500/30 hover:bg-teal-500/10"
              onClick={() => release.mutate({ id: threat.id })}
              disabled={release.isPending}
              data-testid="button-release"
            >
              <Unlock className="w-4 h-4" /> Release
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-2 text-red-400 border-red-500/30 hover:bg-red-500/10"
              onClick={() => burn.mutate({ id: threat.id })}
              disabled={burn.isPending}
              data-testid="button-burn"
            >
              <Flame className="w-4 h-4" /> Burn
            </Button>
          </div>
        )}
      </div>

      {/* Risk score */}
      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground font-medium">Risk Score</span>
          <ReasonLabel code={threat.reasonCode} />
        </div>
        <RiskBar score={threat.riskScore} />
        <div className="flex items-center gap-4 text-xs text-muted-foreground pt-1">
          <span>Confidence: <span className="text-foreground font-semibold">{(threat.confidence * 100).toFixed(0)}%</span></span>
          <span>Detected: <span className="text-foreground">{new Date(threat.detectedAt).toLocaleString()}</span></span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* AI Reasoning */}
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-sm font-semibold text-foreground mb-3">AI Analysis</div>
          <blockquote className="border-l-2 border-primary/50 pl-3 text-sm text-muted-foreground leading-relaxed italic">
            {threat.reasoning}
          </blockquote>

          {threat.flags && threat.flags.length > 0 && (
            <div className="mt-4">
              <div className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Flags detected</div>
              <div className="flex flex-wrap gap-2">
                {threat.flags.map((flag, i) => (
                  <span
                    key={i}
                    data-testid={`flag-${i}`}
                    className="inline-flex items-center px-2 py-1 rounded text-xs bg-red-500/10 text-red-400 border border-red-500/20"
                  >
                    {flag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Metadata */}
        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
          <div className="text-sm font-semibold text-foreground mb-3">Asset Metadata</div>
          <div className="space-y-2 text-sm">
            <div>
              <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Sender Address</div>
              <div className="font-mono text-xs text-foreground break-all">{threat.senderAddress}</div>
            </div>
            {threat.displayName && (
              <div>
                <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Display Name</div>
                <div className="text-sm text-foreground">{threat.displayName}</div>
              </div>
            )}
            {threat.displayUrl && (
              <div>
                <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Display URL</div>
                <a
                  href={threat.displayUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-primary hover:underline flex items-center gap-1"
                  data-testid="link-display-url"
                >
                  {threat.displayUrl}
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}
            {threat.walrusBlobId && (
              <div>
                <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Walrus Blob ID</div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-foreground truncate" data-testid="text-walrus-blob-id">
                    {threat.walrusBlobId}
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0 shrink-0"
                    onClick={() => copyToClipboard(threat.walrusBlobId!, "Walrus Blob ID")}
                    data-testid="button-copy-blob-id"
                  >
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              </div>
            )}
            {threat.quarantineTxDigest && (
              <div>
                <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Quarantine TX</div>
                <div className="font-mono text-xs text-foreground break-all">{threat.quarantineTxDigest}</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
