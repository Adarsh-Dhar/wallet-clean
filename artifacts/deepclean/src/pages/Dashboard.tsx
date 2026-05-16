import { useGetDashboardStats, useGetRecentActivity, useGetRiskBreakdown } from "@workspace/api-client-react";
import { Shield, AlertTriangle, Flame, Unlock, Wallet, TrendingUp } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge } from "@/components/ThreatBadge";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";

const REASON_COLORS = ["#ef4444", "#f59e0b", "#8b5cf6", "#06b6d4", "#6b7280"];

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  testId,
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  color: string;
  testId: string;
}) {
  return (
    <div
      data-testid={testId}
      className="rounded-lg border border-border bg-card p-4 flex items-start gap-3"
    >
      <div className={`flex items-center justify-center w-9 h-9 rounded-md ${color}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <div className="text-xl font-bold text-foreground">{value}</div>
        <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useGetDashboardStats();
  const { data: activity, isLoading: activityLoading } = useGetRecentActivity({ limit: 8 });
  const { data: breakdown, isLoading: breakdownLoading } = useGetRiskBreakdown();

  const safeBreakdown = Array.isArray(breakdown) ? breakdown : [];
  const safeActivity = Array.isArray(activity) ? activity : [];
  const safeAvgRisk = typeof stats?.avgRiskScore === "number" ? stats!.avgRiskScore : 0;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-foreground">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Live overview of detected threats and agent activity</p>
      </div>

      {/* Stats grid */}
      {statsLoading ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-lg" />
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard icon={Shield} label="Total Detected" value={stats.totalThreats} color="bg-primary/20 text-primary" testId="stat-total" />
          <StatCard icon={AlertTriangle} label="Quarantined" value={stats.quarantined} color="bg-blue-500/20 text-blue-400" testId="stat-quarantined" />
          <StatCard icon={Flame} label="Burned" value={stats.burned} color="bg-red-500/20 text-red-400" testId="stat-burned" />
          <StatCard icon={Unlock} label="Released" value={stats.released} color="bg-teal-500/20 text-teal-400" testId="stat-released" />
          <StatCard icon={AlertTriangle} label="Malicious" value={stats.maliciousCount} color="bg-red-500/20 text-red-400" testId="stat-malicious" />
          <StatCard icon={TrendingUp} label="Suspicious" value={stats.suspiciousCount} color="bg-amber-500/20 text-amber-400" testId="stat-suspicious" />
          <StatCard icon={Shield} label="Safe" value={stats.safeCount} color="bg-green-500/20 text-green-400" testId="stat-safe" />
          <StatCard icon={Wallet} label="Wallets Monitored" value={stats.walletsMonitored} color="bg-violet-500/20 text-violet-400" testId="stat-wallets" />
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk breakdown chart */}
        <div className="rounded-lg border border-border bg-card p-5">
          <div className="text-sm font-semibold text-foreground mb-4">Threat Type Breakdown</div>
          {breakdownLoading ? (
            <Skeleton className="h-48 w-full" />
          ) : safeBreakdown.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={safeBreakdown} barSize={28}>
                <XAxis
                  dataKey="label"
                  tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "6px",
                    color: "hsl(var(--foreground))",
                    fontSize: "12px",
                  }}
                  cursor={{ fill: "rgba(255,255,255,0.04)" }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {safeBreakdown.map((_, i) => (
                    <Cell key={i} fill={REASON_COLORS[i % REASON_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center text-sm text-muted-foreground">No data yet</div>
          )}
        </div>

        {/* Recent activity */}
        <div className="rounded-lg border border-border bg-card p-5">
          <div className="text-sm font-semibold text-foreground mb-4">Recent Activity</div>
          {activityLoading ? (
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          ) : safeActivity.length > 0 ? (
            <div className="space-y-2">
              {safeActivity.map((event) => (
                <div key={event.id} className="flex items-center gap-3 text-sm py-1.5 border-b border-border/50 last:border-0">
                  <VerdictBadge verdict={event.verdict} />
                  <span className="font-mono text-xs text-muted-foreground truncate flex-1">
                    {event.objectId.slice(0, 18)}…
                  </span>
                  <span className={`text-xs capitalize ${
                    event.type === "detected" ? "text-amber-400" :
                    event.type === "quarantined" ? "text-blue-400" :
                    event.type === "burned" ? "text-red-400" : "text-teal-400"
                  }`}>{event.type}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-48 flex items-center justify-center text-sm text-muted-foreground">No activity yet</div>
          )}
        </div>
      </div>

      {/* Avg risk score */}
      {stats && (
        <div className="rounded-lg border border-border bg-card p-4 flex items-center gap-4">
          <div className="text-sm text-muted-foreground">Average Risk Score</div>
          <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${safeAvgRisk <= 30 ? "bg-green-500" : safeAvgRisk <= 64 ? "bg-amber-500" : "bg-red-500"}`}
              style={{ width: `${safeAvgRisk}%` }}
            />
          </div>
          <div className="text-lg font-bold font-mono text-foreground" data-testid="avg-risk-score">
            {safeAvgRisk.toFixed(1)}
          </div>
        </div>
      )}
    </div>
  );
}
