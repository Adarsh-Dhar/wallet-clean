/**
 * Shared constants for threat detection and rate limiting.
 * Unified source of truth to prevent inconsistencies.
 */

/** Risk score threshold for quarantining threats (65+) */
export const MIN_RISK_SCORE_FOR_QUARANTINE = 65;

/** Delay between Gemini API calls to stay within 10 RPM rate limit (6 seconds = 10 requests/minute) */
export const GEMINI_POST_CALL_DELAY_MS = 6_000;

/** Delay before batch analysis starts (respects rate limit but optimized for batch efficiency) */
export const BATCH_ANALYSIS_DELAY_MS = 6_000;
