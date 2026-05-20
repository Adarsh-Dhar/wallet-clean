import { useEffect, useRef, useState } from "react";
import { useCurrentAccount, useSignAndExecuteTransaction } from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import { useQueryClient, useMutation } from "@tanstack/react-query";
import { getGetDashboardStatsQueryKey, getListThreatsQueryKey, getListWatchedWalletsQueryKey } from "@workspace/api-client-react";
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronUp, ExternalLink, Loader2, Shield, Sparkles, Wallet, X, XCircle, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { apiJson } from "@/lib/auth";
import { useToast } from "@/hooks/use-toast";

function normalizeObjectType(objType: string | null | undefined) {
  const s = String(objType ?? "");
  const parts = s.split("::").filter(Boolean);
  if (parts.length >= 2) return `${parts[parts.length - 2]}::${parts[parts.length - 1]}`;
  return s;
}

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
  digests: string[];
  objects: Array<{
    objectId: string;
    objectType: string;
    senderAddress: string;
    displayName: string | null;
    displayUrl: string | null;
    moveAbi: string | null;
  }>;
  targetAddress: string;
  network: string;
}

interface CleanResult {
  cleaned: number;
  threats: Array<{ id: number; objectId: string; burnTxDigest: string | null }>;
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
}

interface QuarantinedThreat {
  id: number;
  objectId: string;
  objectType: string;
  senderAddress: string;
  cleanMethod: "transfer_to_dead" | "merge_dust" | "vault_burn" | "release";
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
  const [scanning, setScanning] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [populateLogs, setPopulateLogs] = useState<Record<string, LogEntry[]>>({});
  const [scanLogs, setScanLogs] = useState<Record<string, LogEntry[]>>({});
  const [cleanLogs, setCleanLogs] = useState<Record<string, LogEntry[]>>({});
  const [openPopulateLog, setOpenPopulateLog] = useState<string | null>(null);
  const [openScanLog, setOpenScanLog] = useState<string | null>(null);
  const [openCleanLog, setOpenCleanLog] = useState<string | null>(null);
  const [cleanedState, setCleanedState] = useState<Record<string, { count: number; digest: string } | null>>({});
  const [scanState, setScanState] = useState<Record<string, ScanSummary | null>>({});

  function appendPopulateLog(key: string, entry: LogEntry) {
    setPopulateLogs((current) => ({ ...current, [key]: [...(current[key] ?? []), entry] }));
  }

  function appendScanLog(key: string, entry: LogEntry) {
    setScanLogs((current) => ({ ...current, [key]: [...(current[key] ?? []), entry] }));
  }

  function appendCleanLog(key: string, entry: LogEntry) {
    setCleanLogs((current) => ({ ...current, [key]: [...(current[key] ?? []), entry] }));
  }

  async function performWalletScan(key: string, address: string): Promise<ScanSummary> {
    appendScanLog(key, mkLog("info", "Starting full wallet scan…"));
    appendScanLog(key, mkLog("info", `Target: ${address}`));

    const summary = await scanWalletStream(address, (event) => {
      if (event.status === "error") {
        appendScanLog(key, mkLog("error", event.message));
        return;
      }

      if (event.status === "running") {
        appendScanLog(key, mkLog("info", event.message, event.objectId));
        return;
      }

      const detail = event.objectId ?? event.objectType ?? undefined;
      const level: LogLevel = event.step === "quarantine" ? "success" : event.step === "analyze" && event.verdict === "MALICIOUS" ? "warn" : "info";
      appendScanLog(key, mkLog(level, event.message, detail));
    });

    appendScanLog(
      key,
      mkLog(
        "success",
        `✓ Scan complete — ${summary.quarantined} quarantined, ${summary.safe} safe`,
        `analyzed ${summary.analyzed} of ${summary.total} owned object(s)`,
      ),
    );

    return summary;
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

    // Group by clean_method to apply the right action
    const toTransfer = validThreats.filter(t => t.cleanMethod === "transfer_to_dead" || t.cleanMethod === "vault_burn");
    const toDust     = validThreats.filter(t => t.cleanMethod === "merge_dust");
    const toSkip     = validThreats.filter(t => t.cleanMethod === "release");

    if (toSkip.length > 0) {
      appendCleanLog(key, mkLog("info", `Skipping ${toSkip.length} objects flagged for review (release)`));
    }

    const tx = new Transaction();

    // Standard transfer: phishing NFTs, airdrop tokens, fake governance, dangerous ABI objects
    if (toTransfer.length > 0) {
      const resolved = resolvedObjects.filter(r => toTransfer.some(t => t.objectId === r.objectId));
      if (resolved.length > 0) {
        tx.transferObjects(
          resolved.map(({ objectId }) => tx.object(objectId)),
          tx.pure.address(deadAddress),
        );
        appendCleanLog(key, mkLog("info", `  → transferObjects: ${resolved.length} objects`));
      }
    }

    // Dust merge: group by coin type, merge within each group, then send merged coin to dead
    if (toDust.length > 0) {
      const byType: Record<string, string[]> = {};
      toDust.forEach(t => {
        const key = normalizeObjectType(t.objectType);
        (byType[key] ??= []).push(t.objectId);
      });
      for (const [coinType, ids] of Object.entries(byType)) {
        const ownedIds = ids.filter(id => resolvedObjects.some(r => r.objectId === id));
        if (ownedIds.length === 0) continue;
        const [primary, ...rest] = ownedIds.map(id => tx.object(id));
        if (rest.length > 0) tx.mergeCoins(primary, rest);
        tx.transferObjects([primary], tx.pure.address(deadAddress));
        appendCleanLog(key, mkLog("info", `  → mergeCoins + transfer: ${ownedIds.length} dust coins (${coinType})`));
      }
    }

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
      appendPopulateLog(key, mkLog("info", "Injecting on-chain junk objects only…"));
    },
    onSuccess: (result, { address }) => {
      const key = address;
      setPopulating(false);

      appendPopulateLog(key, mkLog("info", "API response received"));
      appendPopulateLog(key, mkLog("success", `✓ Seeded ${result.injected} on-chain junk object(s)`));

      if (result.objects.length > 0) {
        result.objects.forEach((object, index) => {
          appendPopulateLog(
            key,
            mkLog(
              "info",
              `  [${index + 1}] ${object.displayName ?? normalizeObjectType(object.objectType)}`,
              `       ${object.objectId}`,
            ),
          );
        });
      }

      if (result.digests.length > 0) {
        appendPopulateLog(key, mkLog("success", `✓ ${result.digests.length} on-chain transaction(s) submitted`));
        appendPopulateLog(key, mkLog("success", "On-chain tx recorded", `digests: ${result.digests.join(", ")}`));
      }

      appendPopulateLog(key, mkLog("success", "✓ Dashboard & threat list refreshed"));
      appendPopulateLog(key, mkLog("success", "Population complete."));

      // Refresh threats and dashboard so the Threats page updates after seeding
      // Invalidate & refetch threats and dashboard queries. Use the generated
      // key without passing unknown extra params to satisfy TypeScript types.
      const threatsKey = getListThreatsQueryKey();
      queryClient.invalidateQueries({ queryKey: threatsKey });
      queryClient.refetchQueries({ queryKey: threatsKey });

      const dashboardKey = getGetDashboardStatsQueryKey();
      queryClient.invalidateQueries({ queryKey: dashboardKey });
      queryClient.refetchQueries({ queryKey: dashboardKey });

      queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });

      toast({
        title: "Population complete",
        description: `Seeded ${result.injected} on-chain junk object(s).`,
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

  async function handleScan() {
    if (!walletAddress) return;

    const key = walletAddress;
    setOpenScanLog(key);
    setScanLogs((current) => ({ ...current, [key]: [] }));
    setScanning(true);
    appendScanLog(key, mkLog("info", `Target: ${walletAddress}`));

    try {
      const summary = await performWalletScan(key, walletAddress);
      setScanState((current) => ({ ...current, [key]: summary }));
      queryClient.invalidateQueries({ queryKey: getListThreatsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getGetDashboardStatsQueryKey() });
      queryClient.invalidateQueries({ queryKey: getListWatchedWalletsQueryKey() });
      toast({
        title: "Scan finished",
        description: `${summary.quarantined} quarantined, ${summary.safe} safe`,
      });
    } catch (error) {
      appendScanLog(key, mkLog("error", "Wallet scan failed"));
      appendScanLog(key, mkLog("error", String(error)));
      toast({ title: "Scan failed", description: String(error), variant: "destructive" });
    } finally {
      setScanning(false);
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
              disabled={populating || scanning || cleaning}
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
              className="h-8 px-2 gap-1.5 text-xs text-muted-foreground hover:text-violet-400 hover:bg-violet-500/10 shrink-0"
              onClick={handleScan}
              disabled={populating || scanning || cleaning}
              title="Scan all owned objects and quarantine new threats"
              data-testid="button-scan-wallet-connected"
            >
              {scanning ? (
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
              className="h-8 px-2 gap-1.5 text-xs text-muted-foreground hover:text-rose-400 hover:bg-rose-500/10 shrink-0"
              onClick={handleClean}
              disabled={populating || scanning || cleaning}
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

          {openScanLog === walletKey && scanLogs[walletKey] && (
            <LogPanel logs={scanLogs[walletKey]} title="Scan — Connected wallet" onClose={() => setOpenScanLog(null)} />
          )}

          {openCleanLog === walletKey && cleanLogs[walletKey] && (
            <LogPanel logs={cleanLogs[walletKey]} title="Clean — Connected wallet" onClose={() => setOpenCleanLog(null)} />
          )}

          {scanState[walletKey] && (
            <div className="text-xs text-muted-foreground">
              Last scan: {scanState[walletKey]!.quarantined} quarantined, {scanState[walletKey]!.safe} safe, {scanState[walletKey]!.analyzed} analyzed.
            </div>
          )}
        </div>
      )}
    </div>
  );
}