import { cn } from "@/lib/utils";

type Verdict = "SAFE" | "SUSPICIOUS" | "MALICIOUS";
type Status = "quarantined" | "released" | "burned";

export function VerdictBadge({ verdict }: { verdict: string }) {
  return (
    <span
      data-testid={`badge-verdict-${verdict.toLowerCase()}`}
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold tracking-wide uppercase",
        verdict === "MALICIOUS" && "bg-red-500/15 text-red-400 border border-red-500/25",
        verdict === "SUSPICIOUS" && "bg-amber-500/15 text-amber-400 border border-amber-500/25",
        verdict === "SAFE" && "bg-green-500/15 text-green-400 border border-green-500/25"
      )}
    >
      {verdict}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      data-testid={`badge-status-${status}`}
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium tracking-wide uppercase",
        status === "quarantined" && "bg-blue-500/15 text-blue-400 border border-blue-500/25",
        status === "released" && "bg-teal-500/15 text-teal-400 border border-teal-500/25",
        status === "burned" && "bg-zinc-500/15 text-zinc-400 border border-zinc-500/25"
      )}
    >
      {status}
    </span>
  );
}

export function RiskBar({ score }: { score: number }) {
  const color =
    score <= 30 ? "bg-green-500" : score <= 64 ? "bg-amber-500" : "bg-red-500";
  const textColor =
    score <= 30 ? "text-green-400" : score <= 64 ? "text-amber-400" : "text-red-400";
  return (
    <div className="flex items-center gap-2" data-testid={`risk-bar-${score}`}>
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all", color)}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className={cn("text-xs font-mono font-bold w-7 text-right", textColor)}>{score}</span>
    </div>
  );
}

export function ReasonLabel({ code }: { code: number }) {
  const labels: Record<number, string> = {
    1: "Honeypot",
    2: "Phishing",
    3: "Spoofed",
    4: "Spam",
    5: "Unknown",
  };
  return <span className="text-xs text-muted-foreground">{labels[code] ?? "Unknown"}</span>;
}
