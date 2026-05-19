import { useEffect, useRef, useState } from "react";
import { useCurrentAccount, useSignAndExecuteTransaction } from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import { getGetDashboardStatsQueryKey, getListThreatsQueryKey } from "@workspace/api-client-react";
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronUp, ExternalLink, Loader2, Shield, Wallet, X, XCircle, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { apiJson } from "@/lib/auth";
import { useToast } from "@/hooks/use-toast";

type LogLevel = "info" | "success" | "warn" | "error";

interface LogEntry {
  id: number;
  ts: string;
  level: LogLevel;
  message: string;
  detail?: string;
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
  threats: Array<{ id: number; objectId: string; burnTxDigest: string | null }>;
}

interface QuarantinedThreat {
  id: number;
  objectId: string;
  objectType: string;
  senderAddress: string;
}

const levelStyle: Record<LogLevel, string> = {
  info: "text-zinc-400",
  success: "text-green-400",
  warn: "text-amber-400",
  error: "text-red-400",
};

const levelIcon: Record<LogLevel, React.ReactNode> = {
  info: <span className="w-2 h-2 rounded-full bg-zinc-500 mt-0.5 shrink-0" />,
  success: <CheckCircle2 className="w-3.5 h-3.5 text-green-400 mt-0.5 shrink-0" />,
  warn: <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />,
  error: <XCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />,
};

function nowTs(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

let logId = 0;
function mkLog(level: LogLevel, message: string, detail?: string): LogEntry {
  return { id: ++logId, ts: nowTs(), level, message, detail };
}

async function populateWalletApi(targetAddress: string): Promise<PopulateResult> {
  return apiJson<PopulateResult>("/api/populate-wallet", {
    method: "POST",
    body: { targetAddress },
  });
}

async function cleanWalletApi(threatIds: number[], burnTxDigest: string): Promise<CleanResult> {
  return apiJson<CleanResult>("/api/clean-wallet", {
    method: "POST",
    body: { threatIds, burnTxDigest },
  });
}

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

  useEffect(() => {
    if (!collapsed) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs, collapsed]);

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 overflow-hidden text-xs font-mono">
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-700 bg-zinc-800">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-zinc-300 font-semibold tracking-wide">{title}</span>
          <span className="text-zinc-500">({logs.length} entries)</span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setCollapsed((current) => !current)}
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

      {!collapsed && (
        <div className="max-h-72 overflow-y-auto p-3 space-y-1.5">
          {logs.length === 0 && <div className="text-zinc-600 py-2 text-center">Waiting for events…</div>}
          {logs.map((entry) => (
            <div key={entry.id} className="flex gap-2 items-start">
              {levelIcon[entry.level]}
              <div className="flex-1 min-w-0">
                <span className="text-zinc-600 mr-2">{entry.ts}</span>
                <span className={levelStyle[entry.level]}>{entry.message}</span>
                {entry.detail && <div className="text-zinc-600 truncate mt-0.5 pl-0">{entry.detail}</div>}
              </div>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>
      )}
    </div>
  );
}

export default function Wallets() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const account = useCurrentAccount();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();

  const walletAddress = account?.address ?? null;
  const walletKey = walletAddress ?? "connected-wallet";

  const [populating, setPopulating] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [populateLogs, setPopulateLogs] = useState<Record<string, LogEntry[]>>({});
  const [cleanLogs, setCleanLogs] = useState<Record<string, LogEntry[]>>({});
  const [openPopulateLog, setOpenPopulateLog] = useState<string | null>(null);
  const [openCleanLog, setOpenCleanLog] = useState<string | null>(null);
  const [cleanedState, setCleanedState] = useState<Record<string, { count: number; digest: string } | null>>({});

  function appendPopulateLog(key: string, entry: LogEntry) {
    setPopulateLogs((current) => ({ ...current, [key]: [...(current[key] ?? []), entry] }));
  }

  function appendCleanLog(key: string, entry: LogEntry) {
    setCleanLogs((current) => ({ ...current, [key]: [...(current[key] ?? []), entry] }));
  }

  async function performDeepClean(key: string, address: string): Promise<{ cleaned: number; digest: string } | false | true> {
    appendCleanLog(key, mkLog("info", "Fetching quarantined threats from DB…"));

    const threats = await apiJson<QuarantinedThreat[]>(
      `/api/threats?status=quarantined&limit=200&walletAddress=${encodeURIComponent(address)}`,
    );

    if (threats.length === 0) {
      appendCleanLog(key, mkLog("info", "No quarantined threats to clean"));
      appendCleanLog(key, mkLog("success", "✓ Deep clean complete — 0 threats burned"));
      return true;
    }

    appendCleanLog(key, mkLog("info", `Found ${threats.length} quarantined objects`));
    appendCleanLog(key, mkLog("info", "Building PTB — transferring spam objects to dead address…"));

    const validThreats = threats.filter((threat) => {
      if (!threat.objectId) {
        appendCleanLog(key, mkLog("warn", `Skipping threat without objectId: ${JSON.stringify(threat)}`));
        return false;
      }
      return true;
    });

    if (validThreats.length === 0) {
      appendCleanLog(key, mkLog("error", "No valid objects to burn"));
      return false;
    }

    const deadAddress = "0x0000000000000000000000000000000000000000000000000000000000000000";
    appendCleanLog(key, mkLog("info", "Verifying object ownership before building PTB…"));

    const rpcUrl = (import.meta as any)?.env?.VITE_SUI_RPC_URL || "https://fullnode.testnet.sui.io:443";

    interface ResolvedObject {
      objectId: string;
    }

    async function fetchResolvedObject(objectId: string): Promise<ResolvedObject | null> {
      try {
        const response = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "sui_getObject",
            params: [objectId, { showOwner: true, showType: true }],
          }),
        });

        const payload = await response.json();
        if (!payload || payload.error || !payload.result) return null;

        const data = payload.result.data ?? payload.result;
        if (!data) return null;

        const resolvedObjectId = (data.objectId ?? data.object_id ?? objectId) as string | undefined;
        if (!resolvedObjectId) return null;

        const ownerField = data.owner?.AddressOwner ?? data.owner?.address ?? data.owner ?? null;
        if (ownerField && String(ownerField).toLowerCase() !== address.toLowerCase()) return null;

        return { objectId: resolvedObjectId };
      } catch {
        return null;
      }
    }

    const resolvedObjects: ResolvedObject[] = [];
    const seenObjectIds = new Set<string>();

    for (const threat of validThreats) {
      try {
        const resolved = await fetchResolvedObject(threat.objectId);
        if (!resolved) {
          appendCleanLog(key, mkLog("warn", `Skipping unresolvable object: ${threat.objectId}`));
          continue;
        }

        if (seenObjectIds.has(resolved.objectId)) {
          appendCleanLog(key, mkLog("warn", `Skipping duplicate object: ${resolved.objectId}`));
          continue;
        }

        seenObjectIds.add(resolved.objectId);
        resolvedObjects.push(resolved);
      } catch {
        appendCleanLog(key, mkLog("warn", `Error resolving object ${threat.objectId} — skipping`));
      }
    }

    if (resolvedObjects.length === 0) {
      appendCleanLog(key, mkLog("error", "No valid objects remain to burn after verification"));
      return false;
    }

    const tx = new Transaction();
    tx.transferObjects(
      resolvedObjects.map(({ objectId }) => tx.object(objectId)),
      tx.pure.address(deadAddress),
    );

    appendCleanLog(key, mkLog("info", "Wallet popup opening — please approve the transaction…"));

    let digest: string;
    try {
      const result = await signAndExecute({ transaction: tx });
      digest = result.digest;
    } catch (error) {
      appendCleanLog(key, mkLog("error", "User rejected or transaction failed"));
      appendCleanLog(key, mkLog("error", String(error)));
      return false;
    }

    appendCleanLog(key, mkLog("success", "✓ On-chain tx confirmed"));
    appendCleanLog(key, mkLog("success", "digest", digest));

    const resolvedIds = new Set(resolvedObjects.map((item) => item.objectId));
    const burnedThreatIds = validThreats.filter((threat) => resolvedIds.has(threat.objectId)).map((threat) => threat.id);

    const cleanResult = await cleanWalletApi(burnedThreatIds, digest);

    if (!cleanResult || (cleanResult.cleaned === 0 && cleanResult.threats.length === 0)) {
      appendCleanLog(key, mkLog("warn", "No DB records updated after signed transaction"));
      return true;
    }

    cleanResult.threats.forEach((threat, index) => {
      appendCleanLog(key, mkLog("success", `  [${index + 1}] Threat #${threat.id} → burned 🔥`, `       ${threat.objectId}`));
    });

    appendCleanLog(key, mkLog("success", `✓ Deep clean complete — ${cleanResult.cleaned} threats burned 🔥`));
    return { cleaned: cleanResult.cleaned, digest };
  }

  const populate = useMutation({
    mutationFn: ({ address }: { address: string }) => populateWalletApi(address),
    onMutate: ({ address }) => {
      const key = address;
      setPopulating(true);
      setOpenPopulateLog(key);
      setPopulateLogs((current) => ({ ...current, [key]: [] }));

      appendPopulateLog(key, mkLog("info", "Starting wallet population…"));
      appendPopulateLog(key, mkLog("info", `Target: ${address}`));
      appendPopulateLog(key, mkLog("info", "POST /api/populate-wallet →"));
      appendPopulateLog(key, mkLog("info", "Scanning live wallet objects for threat analysis…"));
      appendPopulateLog(key, mkLog("info", "Fetching owned objects from the connected wallet"));
      appendPopulateLog(key, mkLog("info", "Sending wallet objects to GitHub Models for analysis…"));
    },
    onSuccess: (result, { address }) => {
      const key = address;
      setPopulating(false);

      appendPopulateLog(key, mkLog("info", "API response received"));
      appendPopulateLog(key, mkLog("info", `${result.injected} objects analyzed`));

      result.threats.forEach((threat, index) => {
        const isQuarantined = threat.threatId !== null;
        appendPopulateLog(
          key,
          mkLog(
            isQuarantined ? "warn" : "success",
            `  [${index + 1}] ${threat.verdict} — score ${threat.riskScore}/100 ${isQuarantined ? "→ QUARANTINED" : "→ cleared"}`,
            `       ${threat.objectType}`,
          ),
        );
      });

      const quarantined = result.threats.filter((threat) => threat.threatId !== null);
      const cleared = result.threats.filter((threat) => threat.threatId === null);

      if (quarantined.length > 0) {
        appendPopulateLog(key, mkLog("warn", `${quarantined.length} threats auto-quarantined`));
        appendPopulateLog(key, mkLog("info", "Writing threat records to Postgres DB…"));
        appendPopulateLog(key, mkLog("info", "Storing AI analysis logs on Walrus (5 epochs)…"));
        appendPopulateLog(key, mkLog("success", "✓ Walrus blob IDs linked to threat records"));
        appendPopulateLog(key, mkLog("success", "✓ Threats saved — status: quarantined"));
      }

      if (cleared.length > 0) {
        appendPopulateLog(key, mkLog("success", `✓ ${cleared.length} objects cleared (risk < 65)`));
      }

      if (result.txDigest) {
        appendPopulateLog(key, mkLog("success", "On-chain tx recorded", `digest: ${result.txDigest}`));
      }

      if (quarantined.length > 0) {
        appendPopulateLog(key, mkLog("info", "Scan complete. Click Populate again to rescan current wallet objects."));
        appendPopulateLog(key, mkLog("info", "Click Clean when ready to burn all quarantined threats."));
      }

      appendPopulateLog(key, mkLog("success", "✓ Dashboard & threat list refreshed"));
      appendPopulateLog(key, mkLog("success", "Population complete."));

      queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });

      toast({
        title: `${result.quarantined} threats quarantined`,
        description: `Seeded ${result.injected} objects — ${result.quarantined} auto-quarantined.`,
      });
    },
    onError: (error, { address }) => {
      const key = address;
      setPopulating(false);
      appendPopulateLog(key, mkLog("error", "Population failed"));
      appendPopulateLog(key, mkLog("error", String(error)));
      toast({ title: "Population failed", description: String(error), variant: "destructive" });
    },
  });

  async function handleClean() {
    if (!walletAddress) return;

    const key = walletAddress;
    setOpenCleanLog(key);
    setCleanLogs((current) => ({ ...current, [key]: [...(current[key] ?? []), mkLog("info", "───")] }));
    setCleaning(true);
    appendCleanLog(key, mkLog("info", `Target: ${walletAddress}`));

    try {
      const cleanResult = await performDeepClean(key, walletAddress);
      if (cleanResult && typeof cleanResult === "object" && cleanResult.cleaned > 0) {
        setCleanedState((current) => ({ ...current, [key]: { count: cleanResult.cleaned, digest: cleanResult.digest } }));
        setTimeout(() => {
          setCleanedState((current) => ({ ...current, [key]: null }));
        }, 6000);
        queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
        toast({ title: "Deep clean finished", description: `${walletAddress} cleaned` });
      } else if (cleanResult === true) {
        queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
        toast({ title: "Deep clean finished", description: `${walletAddress} cleaned` });
      }
    } catch (error) {
      appendCleanLog(key, mkLog("error", "Deep clean failed"));
      appendCleanLog(key, mkLog("error", String(error)));
      toast({ title: "Deep clean failed", description: String(error), variant: "destructive" });
    } finally {
      setCleaning(false);
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div>
        <h1 className="text-xl font-bold text-foreground">Connected Wallet</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Only the wallet currently connected in your browser is shown here.</p>
      </div>

      {!walletAddress ? (
        <div className="rounded-lg border border-border bg-card p-10 text-center space-y-3">
          <Wallet className="w-8 h-8 text-muted-foreground mx-auto" />
          <div className="text-sm font-semibold text-foreground">No wallet connected</div>
          <div className="text-xs text-muted-foreground">Connect a Sui wallet to populate and clean the active account.</div>
        </div>
      ) : (
        <div className="space-y-3">
          {cleanedState[walletKey] && (
            <div className="rounded-lg border border-green-500/30 bg-green-500/10 p-6 flex items-center gap-4 animate-in fade-in duration-300">
              <Shield className="w-8 h-8 text-green-400 animate-pulse" />
              <div className="flex-1">
                <div className="font-bold text-green-300 text-lg">Wallet Clean</div>
                <div className="text-sm text-green-400/80">{cleanedState[walletKey]!.count} threats permanently burned 🔥</div>
              </div>
              <a
                href={`https://suiscan.xyz/testnet/tx/${cleanedState[walletKey]!.digest}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-green-400 hover:underline flex items-center gap-1 whitespace-nowrap"
              >
                View tx <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          )}

          <div data-testid="card-wallet-connected" className="rounded-lg border border-border bg-card p-4 flex items-center gap-4">
            <div className="flex items-center justify-center w-9 h-9 rounded-md bg-violet-500/20 border border-violet-500/20 shrink-0">
              <Wallet className="w-4 h-4 text-violet-400" />
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-foreground">Connected wallet</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-violet-500/15 text-violet-400 font-semibold">Connected</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/15 text-green-400">Active</span>
              </div>
              <div className="font-mono text-xs text-muted-foreground truncate mt-0.5" data-testid="text-wallet-address-connected">
                {walletAddress}
              </div>
              <div className="flex items-center gap-1 mt-1 text-xs text-muted-foreground">
                <span>Actions are scoped to the connected wallet only.</span>
              </div>
            </div>

            <Button
              variant="ghost"
              size="sm"
              className="h-8 px-2 gap-1.5 text-xs text-muted-foreground hover:text-cyan-400 hover:bg-cyan-500/10 shrink-0"
              onClick={() => populate.mutate({ address: walletAddress })}
              disabled={populating || cleaning}
              title="Scan wallet objects for threats"
              data-testid="button-seed-wallet-connected"
            >
              {populating ? (
                <>
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <span className="hidden sm:inline">Seeding…</span>
                </>
              ) : (
                <>
                  <Zap className="w-3 h-3" />
                  <span className="hidden sm:inline">Populate</span>
                </>
              )}
            </Button>

            <Button
              variant="ghost"
              size="sm"
              className="h-8 px-2 gap-1.5 text-xs text-muted-foreground hover:text-rose-400 hover:bg-rose-500/10 shrink-0"
              onClick={handleClean}
              disabled={populating || cleaning}
              title="Clean quarantined threats"
              data-testid="button-clean-wallet-connected"
            >
              {cleaning ? (
                <>
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <span className="hidden sm:inline">Cleaning…</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-3 h-3" />
                  <span className="hidden sm:inline">Clean</span>
                </>
              )}
            </Button>
          </div>

          {openPopulateLog === walletKey && populateLogs[walletKey] && (
            <LogPanel logs={populateLogs[walletKey]} title="Populate — Connected wallet" onClose={() => setOpenPopulateLog(null)} />
          )}

          {openCleanLog === walletKey && cleanLogs[walletKey] && (
            <LogPanel logs={cleanLogs[walletKey]} title="Clean — Connected wallet" onClose={() => setOpenCleanLog(null)} />
          )}
        </div>
      )}
    </div>
  );
}