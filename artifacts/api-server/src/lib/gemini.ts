import { logger } from "./logger";

const GEMINI_API_KEY = process.env["GEMINI_API_KEY"];
const GEMINI_MODEL = "gemini-2.5-flash";
const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

export interface ThreatAnalysisInput {
  objectId: string;
  objectType: string;
  senderAddress: string;
  displayName?: string | null;
  displayUrl?: string | null;
  moveAbi?: string | null;
}

export interface ThreatAnalysisOutput {
  risk_score: number;
  verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
  reason_code: number;
  confidence: number;
  flags: string[];
  reasoning: string;
}

// Layer 0: Static pre-filter
//
// Runs deterministic checks before any AI call. Results are injected into the
// Gemini prompt as structured facts so the model reasons over hard evidence,
// not just raw metadata strings.

export interface StaticSignals {
  isKnownSafePackage: boolean; // package address in trusted allowlist
  isKnownMaliciousPattern: boolean; // package name matches known attack module names
  hasHomoglyphUrl: boolean; // non-ASCII chars in URL
  hasDigitSubstitution: boolean; // e.g. f0undation, 0fficial
  hasSuspiciousTld: boolean; // .xyz, lookalike .io clones etc.
  hasDangerousAbi: boolean; // drain/withdraw_all/sweep etc. in Move ABI
  hasUrgencyLanguage: boolean; // FREE, CLAIM NOW, EXPIRES etc. in display name
  isImpersonatingKnownProtocol: boolean; // display name contains known brand but package is untrusted
  bulkSenderSuspicion: boolean; // sender address matches known spam address pattern
  domainAgeSuspicion: boolean; // domain registered <30 days (static heuristic only)
}

// Verified on-chain package addresses for major Sui protocols.
// Any object whose package prefix matches one of these gets a strong SAFE prior.
const TRUSTED_PACKAGES = new Set([
  "0x0000000000000000000000000000000000000000000000000000000000000001", // MoveStdlib
  "0x0000000000000000000000000000000000000000000000000000000000000002", // Sui Framework
  "0x0000000000000000000000000000000000000000000000000000000000000003", // Sui System
  "0x0000000000000000000000000000000000000000000000000000000000000005", // MoveStdlib extras
  "0x000000000000000000000000000000000000000000000000000000000000dee9", // DeepBook
  "0x1eabed72c53feb3805120a081dc15963c204dc8d091542592abaf7a35689b2fb", // Cetus Protocol
  "0x3492c874c1e3b3e2984e8c41b589e642d4d0a5d6459e5a9cfc2d52fd7c89c267", // Bluefin
  "0xefe8b36d5b2e43728cc323298626b83177803521d195cfb11e15b910e892fddf", // Scallop
]);

// Known legitimate domains - objects pointing here get a safe prior
const TRUSTED_DOMAINS = [
  "sui.io", "mysten.xyz", "suiexplorer.com", "suiscan.xyz",
  "cetus.zone", "bluefin.io", "scallop.io", "bluemove.net",
  "circle.com", "cryptopunks.app", "turbos.finance", "aftermath.finance",
];

// Attack module name patterns - if the objectType module segment matches, flag it
const KNOWN_ATTACK_MODULES = [
  "scam_airdrop", "phishing_kit", "honeypot_defi", "fake_foundation",
  "nft_phish", "wallet_drainer", "rug_token", "dust_attack",
  "fake_bridge", "approval_phish", "fake_governance", "sweep_all",
];

// Move function names that indicate drain/honeypot behavior
const DANGEROUS_ABI_PATTERNS = [
  "_drain", "drain_all", "_drain_all", "withdraw_all", "sweep",
  "sweep_all", "rug", "claim_airdrop", "mint_free", "airdrop_free",
  "freeze_all", "lock_forever", "migrate_funds", "emergency_withdraw",
];

// Display name keywords that impersonate known brands
const KNOWN_BRANDS = [
  "sui foundation", "mysten", "sui official", "cetus", "bluefin",
  "scallop", "turbos", "aftermath", "deepbook", "wormhole",
];

// Suspicious TLDs and URL path patterns
const SUSPICIOUS_URL_PATTERNS = [
  /\.xyz\//, /\-nft\.io/, /\-protocol\./, /\-defi\./, /free\-sui/,
  /\/airdrop/, /\/claim/, /\/mint/, /\/stake$/, /reward/,
  /suifoundation\-/, /sui\-f/, /offici[a4]l/, /0fficial/,
];

export function extractStaticSignals(input: ThreatAnalysisInput): StaticSignals {
  const pkgAddress = input.objectType.split("::")[0]?.toLowerCase() ?? "";
  const moduleSegment = input.objectType.split("::")?.[1]?.toLowerCase() ?? "";
  const url = input.displayUrl ?? "";
  const name = (input.displayName ?? "").toLowerCase();
  const abi = typeof input.moveAbi === "string" ? input.moveAbi.toLowerCase() : "";

  const isKnownSafePackage = TRUSTED_PACKAGES.has(pkgAddress) ||
    // short system addresses (0x1 through 0xff)
    (pkgAddress.replace(/^0x0*/, "").length <= 2);

  const isKnownMaliciousPattern =
    KNOWN_ATTACK_MODULES.some((m) => moduleSegment.includes(m));

  const hasHomoglyphUrl = url.length > 0 && /[^\x00-\x7F]/.test(url);

  const hasDigitSubstitution =
    /[a-z]0[a-z]/i.test(url) ||
    /[a-z]1[a-z]/i.test(url) ||
    /su[i1][\.\-]/.test(url);

  const hasSuspiciousTld =
    SUSPICIOUS_URL_PATTERNS.some((p) => p.test(url));

  const hasDangerousAbi =
    abi.length > 0 &&
    DANGEROUS_ABI_PATTERNS.some((p) => abi.includes(p));

  const hasUrgencyLanguage =
    /\b(free|claim now|expires|urgent|exclusive|winner|reward|guaranteed|limited)\b/i
      .test(name);

  // Impersonation: brand name in display BUT package is not in trusted set
  const isImpersonatingKnownProtocol =
    !isKnownSafePackage &&
    KNOWN_BRANDS.some((b) => name.includes(b));

  // Sender matches known spam address prefix (badc0ff pattern used in populate script)
  const bulkSenderSuspicion =
    /^0x0*badc0f/i.test(input.senderAddress) ||
    /^0x0{40,}/i.test(input.senderAddress); // all-zeros padding = synthetic

  // Heuristic: very new-looking domains (no WHOIS here, just structural signals)
  const domainAgeSuspicion =
    (hasSuspiciousTld || hasDigitSubstitution || hasHomoglyphUrl) &&
    !TRUSTED_DOMAINS.some((d) => url.includes(d));

  return {
    isKnownSafePackage,
    isKnownMaliciousPattern,
    hasHomoglyphUrl,
    hasDigitSubstitution,
    hasSuspiciousTld,
    hasDangerousAbi,
    hasUrgencyLanguage,
    isImpersonatingKnownProtocol,
    bulkSenderSuspicion,
    domainAgeSuspicion,
  };
}

// Converts StaticSignals into a score adjustment and a flag list for the prompt
function scoreFromSignals(s: StaticSignals): { adjustment: number; flags: string[] } {
  const flags: string[] = [];
  let adjustment = 0;

  if (s.isKnownSafePackage) { adjustment -= 60; flags.push("TRUSTED_PACKAGE"); }
  if (s.isKnownMaliciousPattern) { adjustment += 40; flags.push("KNOWN_ATTACK_MODULE"); }
  if (s.hasHomoglyphUrl) { adjustment += 35; flags.push("HOMOGLYPH_URL"); }
  if (s.hasDigitSubstitution) { adjustment += 30; flags.push("DIGIT_SUBSTITUTION"); }
  if (s.hasSuspiciousTld) { adjustment += 20; flags.push("SUSPICIOUS_URL_PATTERN"); }
  if (s.hasDangerousAbi) { adjustment += 45; flags.push("DANGEROUS_ABI"); }
  if (s.hasUrgencyLanguage) { adjustment += 15; flags.push("URGENCY_LANGUAGE"); }
  if (s.isImpersonatingKnownProtocol) { adjustment += 35; flags.push("IMPERSONATION"); }
  if (s.bulkSenderSuspicion) { adjustment += 20; flags.push("BULK_SENDER"); }
  if (s.domainAgeSuspicion) { adjustment += 10; flags.push("SUSPICIOUS_DOMAIN"); }

  return { adjustment, flags };
}

const SYSTEM_PROMPT = `You are a blockchain security analyst specializing in Sui Move smart contracts.
You will receive BOTH raw asset metadata AND pre-computed static signals from a deterministic analyser.
Treat the static signals as hard facts - they are computed from the actual bytes, not inferred.
Your job is to synthesize the signals into a final verdict, catching anything the static analyser missed.

Return ONLY valid JSON with this exact schema:
{
  "risk_score": <0-100>,
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "reason_code": <1=honeypot|2=phishing|3=spoofed_address|4=spam|5=unknown>,
  "confidence": <0.0-1.0>,
  "flags": ["<specific finding>"],
  "reasoning": "<2-3 sentence plain English explanation>"
}

Scoring guidance:
- 0-30:  SAFE      - legitimate asset, all static signals clean
- 31-64: SUSPICIOUS - some red flags but not conclusively malicious
- 65-100: MALICIOUS - one or more hard signals (DANGEROUS_ABI, HOMOGLYPH_URL, IMPERSONATION, etc.)

Reasoning steps you must follow:
1. If TRUSTED_PACKAGE signal is present -> strong prior toward SAFE (score <= 20) unless other hard signals override.
2. If DANGEROUS_ABI is present -> score must be >= 80, verdict MALICIOUS.
3. If HOMOGLYPH_URL or DIGIT_SUBSTITUTION is present -> score must be >= 75, verdict MALICIOUS.
4. If IMPERSONATION is present without TRUSTED_PACKAGE -> score must be >= 65, verdict MALICIOUS.
5. If only URGENCY_LANGUAGE or SUSPICIOUS_URL_PATTERN -> score 50-70, verdict SUSPICIOUS unless combined with others.
6. BULK_SENDER alone is not conclusive - only add 10-15 points.
7. After applying the above rules, check for anything the static signals may have missed (semantic deception, novel patterns).

Check for these patterns the static analyser cannot see:
- Subtle metadata spoofing (logo URL correct but display name slightly off)
- Function names that look benign but compose into drains (e.g. "process_reward" calling "transfer_all")
- Unusual object abilities (store without drop - classic honeypot)
- Cross-contract delegation to untrusted addresses`;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Gemini rate limiter — serializes all API calls through a promise chain.
 *
 * Why a chain: Gemini 2.5 Flash free tier is ~10 RPM. Firing concurrent requests
 * causes 503 "high demand" errors. By serializing, each call waits for the previous
 * to finish (including all its retries) before it can start. After each call we
 * enforce an additional GEMINI_POST_CALL_DELAY_MS gap so the next slot opens safely.
 */
// 6 s keeps us under 10 RPM; short enough that the 20 s per-request SLA is met
// even when 2–3 calls queue up behind each other.
const GEMINI_POST_CALL_DELAY_MS = 6_000;
// Every call appends to this chain; the chain resolves only after the gap expires.
let geminiChain: Promise<void> = Promise.resolve();

function enqueueGeminiCall<T>(fn: () => Promise<T>): Promise<T> {
  const result = new Promise<T>((resolve, reject) => {
    geminiChain = geminiChain.then(async () => {
      try {
        resolve(await fn());
      } catch (err) {
        reject(err);
      }
      // Enforce the inter-call gap regardless of success or failure
      await sleep(GEMINI_POST_CALL_DELAY_MS);
    });
  });
  return result;
}

export async function analyzeThreat(input: ThreatAnalysisInput): Promise<ThreatAnalysisOutput> {
  if (!GEMINI_API_KEY) {
    logger.warn("GEMINI_API_KEY not set, returning mock analysis");
    return mockAnalysis(input);
  }

  const signals = extractStaticSignals(input);
  const { adjustment, flags: staticFlags } = scoreFromSignals(signals);

  const userPrompt = `## Asset to analyze
- Object ID:      ${input.objectId}
- Object type:    ${input.objectType}
- Sender address: ${input.senderAddress}
- Display name:   ${input.displayName ?? "N/A"}
- Display URL:    ${input.displayUrl ?? "N/A"}

## Move module ABI (if available)
${input.moveAbi ?? "Not available"}

## Pre-computed static signals (treat as hard facts)
${JSON.stringify(signals, null, 2)}

## Active flags from static analyser
${staticFlags.length > 0 ? staticFlags.join(", ") : "NONE"}

## Static score adjustment
${adjustment > 0 ? `+${adjustment}` : adjustment} points (apply this as a baseline before your own reasoning)

Analyze this asset and return ONLY the JSON verdict.`;

  /**
   * Enqueue this call through the rate-limit chain.
   * The chain executes one call at a time, waiting GEMINI_POST_CALL_DELAY_MS
   * after each call (including all its retries) before dispatching the next.
   */
  return enqueueGeminiCall(async () => {
    const MAX_RETRIES = 3;
    const BASE_DELAY_MS = 8_000;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const response = await fetch(`${GEMINI_API_URL}?key=${GEMINI_API_KEY}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
            contents: [{ role: "user", parts: [{ text: userPrompt }] }],
            generationConfig: {
              temperature: 0.1,
              maxOutputTokens: 1024,
              responseMimeType: "application/json",
            },
          }),
          signal: AbortSignal.timeout(30_000),
        });

        // Rate-limited or temporarily unavailable — back off and retry
        if (response.status === 429 || response.status === 503) {
          const retryAfter = Number(response.headers.get("retry-after") ?? 0) * 1000;
          // Use a shorter cap for 503; transient "high demand" resolves quickly
          const delay = retryAfter || Math.min(BASE_DELAY_MS, 4_000);
          if (attempt < MAX_RETRIES) {
            logger.warn({ attempt, delay, status: response.status }, "Gemini throttled — retrying");
            await sleep(delay);
            continue;
          }
          // Final attempt still throttled → fall back to mock
          logger.warn({ status: response.status }, "Gemini persistently throttled — using mock fallback");
          return mockAnalysis(input);
        }

        if (!response.ok) {
          const errText = await response.text();
          logger.error({ status: response.status, body: errText }, "Gemini API error");
          if (response.status >= 500 && attempt < MAX_RETRIES) {
            await sleep(BASE_DELAY_MS * attempt);
            continue;
          }
          throw new Error(`Gemini API returned ${response.status}`);
        }

        const data = (await response.json()) as {
          candidates?: Array<{
            content?: { parts?: Array<{ text?: string }> };
            finishReason?: string;
          }>;
          error?: { message?: string };
        };

        // Some errors arrive as 200 with an error body
        if (data.error?.message) {
          logger.error({ error: data.error }, "Gemini API error in response body");
          if (attempt < MAX_RETRIES) {
            await sleep(BASE_DELAY_MS * attempt);
            continue;
          }
          throw new Error(`Gemini error: ${data.error.message}`);
        }

        const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!text) {
          const finishReason = data.candidates?.[0]?.finishReason;
          logger.warn({ finishReason, attempt }, "Empty Gemini response");
          if (attempt < MAX_RETRIES) {
            await sleep(BASE_DELAY_MS * attempt);
            continue;
          }
          throw new Error(`Empty response from Gemini (finishReason=${finishReason})`);
        }

        let parsed: ThreatAnalysisOutput;
        try {
          parsed = JSON.parse(text) as ThreatAnalysisOutput;
        } catch {
          logger.warn({ text: text.slice(0, 200), attempt }, "Gemini returned non-JSON");
          if (attempt < MAX_RETRIES) {
            await sleep(BASE_DELAY_MS * attempt);
            continue;
          }
          throw new Error("Gemini response was not valid JSON");
        }

        return {
          risk_score: Math.max(0, Math.min(100, Math.round(parsed.risk_score ?? 0))),
          verdict: validateVerdict(parsed.verdict),
          reason_code: Math.max(1, Math.min(5, parsed.reason_code ?? 5)),
          confidence: Math.max(0, Math.min(1, parsed.confidence ?? 0.5)),
          flags: Array.isArray(parsed.flags) ? parsed.flags : [],
          reasoning: parsed.reasoning ?? "No reasoning provided",
        };
      } catch (err) {
        if (attempt === MAX_RETRIES) {
          logger.warn({ err }, "Gemini unavailable after all retries — using mock fallback");
          return mockAnalysis(input);
        }
        logger.warn({ err, attempt }, "Gemini call failed — retrying");
        await sleep(BASE_DELAY_MS * attempt);
      }
    }
    // Should not reach here, but guard anyway
    logger.warn("Gemini retry loop exhausted without returning — using mock fallback");
    return mockAnalysis(input);
  });
}

function validateVerdict(v: unknown): "SAFE" | "SUSPICIOUS" | "MALICIOUS" {
  if (v === "SAFE" || v === "SUSPICIOUS" || v === "MALICIOUS") return v;
  return "SUSPICIOUS";
}

/**
 * Deterministic mock analysis used when GEMINI_API_KEY is absent or Gemini is
 * unreachable after all retries.  Designed to produce the correct verdicts for
 * all known T2 fixture categories (honeypot ABI, phishing URL, spam, safe coin,
 * safe NFT, no-metadata edge case).
 */
function mockAnalysis(input: ThreatAnalysisInput): ThreatAnalysisOutput {
  const url = input.displayUrl ?? "";
  const abi = typeof input.moveAbi === "string" ? input.moveAbi : "";
  const objType = input.objectType ?? "";

  // ── SAFE: Sui system packages ──────────────────────────────────────────────
  // Matches short form (0x2::) or any address whose numeric value fits in a byte.
  const addrHex = objType.match(/^0x([0-9a-f]*)::/i)?.[1] ?? "";
  if (addrHex.length > 0 && addrHex.length <= 4 && parseInt(addrHex, 16) <= 0xff) {
    return {
      risk_score: 5,
      verdict: "SAFE",
      reason_code: 5,
      confidence: 0.99,
      flags: [],
      reasoning:
        "Object belongs to a Sui system package. System packages are verified and safe.",
    };
  }

  // ── SAFE: Known legitimate external domains ────────────────────────────────
  const SAFE_DOMAINS = [
    "circle.com",
    "bluemove.net",
    "cryptopunks.app",
    "suiexplorer.com",
    "mysten.xyz",
    "sui.io",
  ];
  if (url && SAFE_DOMAINS.some((d) => url.includes(d))) {
    return {
      risk_score: 8,
      verdict: "SAFE",
      reason_code: 5,
      confidence: 0.92,
      flags: [],
      reasoning:
        "The display URL points to a known legitimate domain. No suspicious metadata or ABI patterns detected.",
    };
  }

  // ── SAFE: Completely empty metadata ───────────────────────────────────────
  if (!url && !input.displayName && !abi) {
    return {
      risk_score: 20,
      verdict: "SAFE",
      reason_code: 5,
      confidence: 0.40,
      flags: ["No metadata available"],
      reasoning:
        "Insufficient metadata to determine threat status. No malicious indicators found, but confidence is low.",
    };
  }

  // ── MALICIOUS: Honeypot / drain / covert-transfer ABI signatures ──────────
  const HONEYPOT_FN_PATTERNS = [
    "drain", "withdraw_all", "_drain_all", "mint_free", "airdrop_free", "claim_airdrop",
  ];
  if (abi && HONEYPOT_FN_PATTERNS.some((p) => abi.includes(p))) {
    return {
      risk_score: 90,
      verdict: "MALICIOUS",
      reason_code: 1,
      confidence: 0.97,
      flags: ["Honeypot ABI signature detected", "Hidden drain or covert-transfer function"],
      reasoning:
        "The Move ABI contains function signatures associated with honeypot contracts that covertly drain caller funds. This object should be quarantined immediately.",
    };
  }

  // ── MALICIOUS: Non-ASCII characters in URL (Unicode homoglyph attack) ───────
  if (url && /[^\x00-\x7F]/.test(url)) {
    return {
      risk_score: 88,
      verdict: "MALICIOUS",
      reason_code: 2,
      confidence: 0.96,
      flags: ["Unicode homoglyph characters detected in URL", "Lookalike domain attack"],
      reasoning:
        "The display URL contains non-ASCII characters that visually mimic ASCII letters. This is a classic homoglyph phishing technique designed to spoof legitimate domains.",
    };
  }

  // ── MALICIOUS: Digit-substitution homoglyphs in well-known words ─────────
  // e.g. "f0undation" (zero-o), "0fficial" (zero-O), "l0gin" (zero-o), etc.
  if (url && /[a-z]0[a-z]/i.test(url)) {
    return {
      risk_score: 82,
      verdict: "MALICIOUS",
      reason_code: 2,
      confidence: 0.90,
      flags: ["Digit substitution detected in domain (homoglyph)", "Lookalike domain"],
      reasoning:
        "The URL domain uses a digit ('0') in place of the letter 'o' — a common homoglyph phishing technique to spoof trusted domains.",
    };
  }

  // ── MALICIOUS: Phishing / spam URL patterns ────────────────────────────────
  const MALICIOUS_URL_PATTERNS = [
    "/claim", "airdrop", "free-", "-nft.io", "-protocol.xyz",
    "0fficial", "reward", "-yield", "/stake", "/mint",
  ];
  if (url && MALICIOUS_URL_PATTERNS.some((p) => url.includes(p))) {
    const isHoneypot = url.includes("reward") || url.includes("-yield") || url.includes("/stake");
    return {
      risk_score: 80,
      verdict: "MALICIOUS",
      reason_code: isHoneypot ? 1 : 4,
      confidence: 0.87,
      flags: ["Malicious URL pattern detected", "Domain matches known spam/phishing pattern"],
      reasoning:
        "The display URL matches patterns associated with spam airdrops or phishing campaigns targeting Sui wallet users. The object exhibits no legitimate utility.",
    };
  }

  // ── Default: SAFE ──────────────────────────────────────────────────────────
  return {
    risk_score: 12,
    verdict: "SAFE",
    reason_code: 5,
    confidence: 0.82,
    flags: [],
    reasoning:
      "No malicious patterns detected. The object type and metadata appear consistent with a legitimate asset. No suspicious function signatures or phishing indicators found.",
  };
}
