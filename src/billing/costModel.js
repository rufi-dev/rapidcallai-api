// Authoritative, minute-normalized cost model for RapidCall AI voice calls.
// Outputs both per-call USD and per-minute USD for every component.
//
// IMPORTANT UNIT RULE:
// - All variable costs are converted into USD per minute (USD/min) using callMinutes (billed).
// - We still compute per-call USD (USD) as (USD/min * minutes) when the provider cost is duration-based,
//   or from native usage metrics (tokens/chars/seconds) and then normalize to USD/min.

function numEnv(name) {
  const v = process.env[name];
  if (v == null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function boolEnv(name, def = false) {
  const raw = String(process.env[name] ?? "").trim().toLowerCase();
  if (!raw) return def;
  return raw === "1" || raw === "true" || raw === "yes" || raw === "y" || raw === "on";
}

function parseJsonEnv(name) {
  const raw = String(process.env[name] || "").trim();
  if (!raw) return null;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" ? v : null;
  } catch {
    return null;
  }
}

function round4(n) {
  return Math.round(Number(n || 0) * 10000) / 10000;
}

function clampNonNeg(n) {
  const x = Number(n || 0);
  return Number.isFinite(x) ? Math.max(0, x) : 0;
}

function safeDiv(a, b) {
  const denom = Math.max(0.0001, Number(b || 0));
  return Number(a || 0) / denom;
}

// --- LLM pricing (USD per 1M tokens) default catalog (OpenAI-style) ---
// NOTE: Keep in sync with server UI expectations; override via LLM_PRICING_JSON when possible.
const DEFAULT_LLM_PRICING_PER_1M = {
  "gpt-5.2": { input: 1.75, cached_input: 0.175, output: 14.0 },
  "gpt-5.1": { input: 1.25, cached_input: 0.125, output: 10.0 },
  "gpt-5": { input: 1.25, cached_input: 0.125, output: 10.0 },
  "gpt-5-mini": { input: 0.25, cached_input: 0.025, output: 2.0 },
  "gpt-5-nano": { input: 0.05, cached_input: 0.005, output: 0.4 },
  "gpt-5.2-chat-latest": { input: 1.75, cached_input: 0.175, output: 14.0 },
  "gpt-5.1-chat-latest": { input: 1.25, cached_input: 0.125, output: 10.0 },
  "gpt-5-chat-latest": { input: 1.25, cached_input: 0.125, output: 10.0 },
  "gpt-4.1": { input: 2.0, cached_input: 0.5, output: 8.0 },
  "gpt-4.1-mini": { input: 0.4, cached_input: 0.1, output: 1.6 },
  "gpt-4.1-nano": { input: 0.1, cached_input: 0.025, output: 0.4 },
  "gpt-4o": { input: 2.5, cached_input: 1.25, output: 10.0 },
  "gpt-4o-mini": { input: 0.15, cached_input: 0.075, output: 0.6 },
  "gpt-realtime": { input: 4.0, cached_input: 0.4, output: 16.0 },
};

function getLlmPricingPer1k(model) {
  const m = String(model || "").trim();

  const envTable = parseJsonEnv("LLM_PRICING_JSON");
  const rec = envTable && m && envTable[m] ? envTable[m] : null;
  if (rec && typeof rec === "object") {
    const inputPer1K = Number(rec.inputPer1K);
    const cachedPer1K = Number(rec.cachedInputPer1K);
    const outputPer1K = Number(rec.outputPer1K);
    const inputPer1M = Number(rec.inputPer1M);
    const cachedPer1M = Number(rec.cachedInputPer1M);
    const outputPer1M = Number(rec.outputPer1M);

    const resolved = {
      inputPer1K: Number.isFinite(inputPer1K) ? inputPer1K : Number.isFinite(inputPer1M) ? inputPer1M / 1000 : null,
      cachedInputPer1K: Number.isFinite(cachedPer1K)
        ? cachedPer1K
        : Number.isFinite(cachedPer1M)
          ? cachedPer1M / 1000
          : null,
      outputPer1K: Number.isFinite(outputPer1K) ? outputPer1K : Number.isFinite(outputPer1M) ? outputPer1M / 1000 : null,
    };
    if (resolved.inputPer1K != null && resolved.outputPer1K != null) return resolved;
  }

  const d = m && DEFAULT_LLM_PRICING_PER_1M[m] ? DEFAULT_LLM_PRICING_PER_1M[m] : null;
  if (d) {
    return {
      inputPer1K: d.input / 1000,
      cachedInputPer1K: typeof d.cached_input === "number" ? d.cached_input / 1000 : null,
      outputPer1K: d.output / 1000,
    };
  }

  const llmInPer1k = numEnv("LLM_INPUT_USD_PER_1K");
  const llmCachedInPer1k = numEnv("LLM_CACHED_INPUT_USD_PER_1K");
  const llmOutPer1k = numEnv("LLM_OUTPUT_USD_PER_1K");
  if (llmInPer1k != null && llmOutPer1k != null) {
    return { inputPer1K: llmInPer1k, cachedInputPer1K: llmCachedInPer1k, outputPer1K: llmOutPer1k };
  }
  return null;
}

function getSttPricingPerMin(sttModel) {
  const m = String(sttModel || "").trim();
  const envTable = parseJsonEnv("STT_PRICING_JSON");
  const rec = envTable && m && envTable[m] ? envTable[m] : null;
  if (rec && typeof rec === "object") {
    const v = Number(rec.usdPerMin ?? rec.usd_per_min);
    if (Number.isFinite(v)) return v;
  }
  return numEnv("STT_USD_PER_MIN");
}

function getTtsPricingPer1kChars(ttsModel) {
  const m = String(ttsModel || "").trim();
  const envTable = parseJsonEnv("TTS_PRICING_JSON");
  const rec = envTable && m && envTable[m] ? envTable[m] : null;
  if (rec && typeof rec === "object") {
    const v = Number(rec.usdPer1KChars ?? rec.usd_per_1k_chars ?? rec.usdPer1kChars);
    if (Number.isFinite(v)) return v;
  }
  return numEnv("TTS_USD_PER_1K_CHARS");
}

// Telephony pricing: either TELEPHONY_PRICING_JSON with longest-prefix match or TELEPHONY_USD_PER_MIN fallback.
// TELEPHONY_PRICING_JSON format:
//   { "default": { "usdPerMin": 0.013 }, "+1": { "usdPerMin": 0.013 }, "+44": { "usdPerMin": 0.02 } }
function getTelephonyUsdPerMinForNumber(e164OrKey) {
  const table = parseJsonEnv("TELEPHONY_PRICING_JSON");
  const fallback = numEnv("TELEPHONY_USD_PER_MIN");
  const x = String(e164OrKey || "").trim();
  if (!table || typeof table !== "object") return fallback;

  let bestKey = null;
  for (const k of Object.keys(table)) {
    if (k === "default") continue;
    if (x.startsWith(k) && (bestKey == null || k.length > bestKey.length)) bestKey = k;
  }
  const rec = bestKey ? table[bestKey] : table.default;
  const v = rec && typeof rec === "object" ? Number(rec.usdPerMin ?? rec.usd_per_min) : null;
  if (Number.isFinite(v)) return v;
  return fallback;
}

function getLivekitUsdPerParticipantMin() {
  return numEnv("LIVEKIT_USD_PER_PARTICIPANT_MIN");
}

function getRecordingConfig() {
  return {
    enabledDefault: boolEnv("RECORDING_ENABLED_DEFAULT", false),
    retentionDays: clampNonNeg(numEnv("RECORDING_RETENTION_DAYS") ?? 30),
    expectedGets: clampNonNeg(numEnv("RECORDING_EXPECTED_GET_REQUESTS") ?? 0),
  };
}

function computeBilledSeconds(durationSec) {
  const sec = clampNonNeg(durationSec);
  const minBillable = clampNonNeg(numEnv("BILLING_MINIMUM_BILLABLE_SECONDS") ?? 0);
  const roundUpTo = clampNonNeg(numEnv("BILLING_ROUND_UP_TO_SECONDS") ?? 1);
  const rounded = roundUpTo > 1 ? Math.ceil(sec / roundUpTo) * roundUpTo : sec;
  return Math.max(minBillable, rounded);
}

function computeOverheadUsdPerMinFromInputs({ allocatedMinutesPerMonth, budgetsUsdPerMonth }) {
  const minutes = Math.max(0.0001, Number(allocatedMinutesPerMonth || 0));
  const compute = clampNonNeg(budgetsUsdPerMonth?.computeUsdPerMonth);
  const db = clampNonNeg(budgetsUsdPerMonth?.dbUsdPerMonth);
  const logs = clampNonNeg(budgetsUsdPerMonth?.logsUsdPerMonth);
  return {
    computeUsdPerMin: compute / minutes,
    dbUsdPerMin: db / minutes,
    logsUsdPerMin: logs / minutes,
  };
}

function computeCostBreakdownFromUsage({ usage, models }) {
  if (!usage || typeof usage !== "object") {
    return { llmUsd: null, sttUsd: null, ttsUsd: null, totalUsd: null };
  }
  const llmRates = getLlmPricingPer1k(models?.llm);
  const sttPerMin = getSttPricingPerMin(models?.stt ?? usage?.stt_model);
  const ttsPer1kChars = getTtsPricingPer1kChars(models?.tts ?? usage?.tts_model);

  const llmPromptTokens = Number(usage.llm_prompt_tokens || 0);
  const llmPromptCachedTokens = Number(usage.llm_prompt_cached_tokens || 0);
  const llmCompletionTokens = Number(usage.llm_completion_tokens || 0);
  const sttAudioSeconds = Number(usage.stt_audio_duration || 0);
  const ttsCharacters = Number(usage.tts_characters_count || 0);

  const llmUsd =
    llmRates?.inputPer1K != null && llmRates?.outputPer1K != null
      ? round4(
          (llmPromptTokens / 1000) * llmRates.inputPer1K +
            (llmRates.cachedInputPer1K != null ? (llmPromptCachedTokens / 1000) * llmRates.cachedInputPer1K : 0) +
            (llmCompletionTokens / 1000) * llmRates.outputPer1K
        )
      : null;
  const sttUsd = sttPerMin != null ? round4(((sttAudioSeconds / 60) * sttPerMin)) : null;
  const ttsUsd = ttsPer1kChars != null ? round4(((ttsCharacters / 1000) * ttsPer1kChars)) : null;

  const parts = [llmUsd, sttUsd, ttsUsd].filter((v) => typeof v === "number" && Number.isFinite(v));
  const totalUsd = parts.length ? round4(parts.reduce((a, v) => a + v, 0)) : null;
  return {
    llmUsd,
    sttUsd,
    ttsUsd,
    totalUsd,
    raw: {
      llmPromptTokens,
      llmPromptCachedTokens,
      llmCompletionTokens,
      sttAudioSeconds,
      ttsCharacters,
    },
  };
}

function computeRecordingCostsUsd({ recordingSizeBytes, enabled, playbackGetCount }) {
  if (!enabled) return { recordingUsd: 0, storageUsd: 0, egressUsd: 0, s3PutUsd: 0, s3GetUsd: 0, totalUsd: 0 };

  const storagePerGbMonth = clampNonNeg(numEnv("S3_STORAGE_USD_PER_GB_MONTH") ?? 0);
  const egressPerGb = clampNonNeg(numEnv("AWS_EGRESS_USD_PER_GB") ?? 0);
  const putPer1k = clampNonNeg(numEnv("S3_PUT_USD_PER_1K") ?? 0);
  const getPer1k = clampNonNeg(numEnv("S3_GET_USD_PER_1K") ?? 0);

  const { retentionDays, expectedGets } = getRecordingConfig();
  const retentionMonths = retentionDays / 30;

  const bytes = clampNonNeg(recordingSizeBytes);
  const gb = bytes > 0 ? bytes / (1024 * 1024 * 1024) : 0;

  const storageUsd = gb > 0 ? gb * storagePerGbMonth * retentionMonths : 0;
  const egressUsd = gb > 0 ? gb * egressPerGb : 0;
  const s3PutUsd = putPer1k > 0 ? putPer1k / 1000 : 0; // one upload per recording
  const gets = clampNonNeg(playbackGetCount != null ? playbackGetCount : expectedGets);
  const s3GetUsd = gets > 0 && getPer1k > 0 ? (gets * getPer1k) / 1000 : 0;
  const recordingUsd = 0; // reserved if you have provider egress/recording-minute pricing separately
  const totalUsd = storageUsd + egressUsd + s3PutUsd + s3GetUsd + recordingUsd;
  return {
    recordingUsd: round4(recordingUsd),
    storageUsd: round4(storageUsd),
    egressUsd: round4(egressUsd),
    s3PutUsd: round4(s3PutUsd),
    s3GetUsd: round4(s3GetUsd),
    totalUsd: round4(totalUsd),
    derived: { recordingSizeBytes: bytes, recordingSizeGb: gb, retentionMonths },
  };
}

function computeCallCosts({
  durationSec,
  usage,
  models,
  normalizedInput,
  recording,
  overheadUsdPerMin,
}) {
  const billedSeconds = computeBilledSeconds(durationSec);
  const callMinutesBilled = billedSeconds / 60;

  const defaultParticipants = clampNonNeg(numEnv("DEFAULT_PARTICIPANTS_COUNT_AVG") ?? 2);
  const participantsCountAvg =
    Number.isFinite(Number(normalizedInput?.participantsCountAvg)) && Number(normalizedInput?.participantsCountAvg) > 0
      ? Number(normalizedInput?.participantsCountAvg)
      : defaultParticipants;

  const participantMinutes =
    Number.isFinite(Number(normalizedInput?.participantMinutes)) && Number(normalizedInput?.participantMinutes) > 0
      ? Number(normalizedInput.participantMinutes)
      : callMinutesBilled * participantsCountAvg;

  const source = String(normalizedInput?.source || "").trim() || "unknown";
  const telephonyMinutes =
    source === "telephony" || boolEnv("ASSUME_TELEPHONY_MINUTES_FOR_UNKNOWN", false) ? callMinutesBilled : 0;

  const livekitParticipantMinutes = participantMinutes; // primary LiveKit driver

  // --- Provider usage-based costs (COGS) ---
  const usageCogs = computeCostBreakdownFromUsage({ usage, models });

  // Convert usage-based costs into USD/min based on billed minutes.
  const llmUsd = usageCogs.llmUsd ?? 0;
  const sttUsd = usageCogs.sttUsd ?? 0;
  const ttsUsd = usageCogs.ttsUsd ?? 0;
  const llmUsdPerMin = round4(safeDiv(llmUsd, callMinutesBilled));
  const sttUsdPerMin = round4(safeDiv(sttUsd, callMinutesBilled));
  const ttsUsdPerMin = round4(safeDiv(ttsUsd, callMinutesBilled));

  // --- Duration-based direct costs ---
  const telephonyRate = getTelephonyUsdPerMinForNumber(normalizedInput?.telephonyRateKey || normalizedInput?.telephonyTo || "");
  const telephonyUsd = telephonyRate != null ? telephonyMinutes * telephonyRate : 0;
  const telephonyUsdPerMin = telephonyRate != null ? telephonyRate : 0;

  const livekitRate = getLivekitUsdPerParticipantMin();
  const livekitUsd = livekitRate != null ? livekitParticipantMinutes * livekitRate : 0;
  // Convert participant-minute rate into call-minute equivalent for UI:
  const livekitUsdPerMin = livekitRate != null ? livekitRate * participantsCountAvg : 0;

  // --- Recording/S3/Egress costs (COGS) ---
  const recEnabled =
    typeof normalizedInput?.recordingEnabled === "boolean"
      ? normalizedInput.recordingEnabled
      : recording?.enabled != null
        ? Boolean(recording.enabled)
        : getRecordingConfig().enabledDefault;
  const recordingSizeBytes = recording?.sizeBytes ?? normalizedInput?.recordingSizeBytes ?? null;
  const recCosts = computeRecordingCostsUsd({
    recordingSizeBytes,
    enabled: recEnabled,
    playbackGetCount: recording?.playbackGetCount ?? normalizedInput?.playbackGetCount ?? null,
  });

  // --- Overhead allocations (minute-allocated) ---
  const computeUsdPerMin = clampNonNeg(overheadUsdPerMin?.computeUsdPerMin);
  const dbUsdPerMin = clampNonNeg(overheadUsdPerMin?.dbUsdPerMin);
  const logsUsdPerMin = clampNonNeg(overheadUsdPerMin?.logsUsdPerMin);

  const computeUsd = computeUsdPerMin * callMinutesBilled;
  const dbUsd = dbUsdPerMin * callMinutesBilled;
  const logsUsd = logsUsdPerMin * callMinutesBilled;

  // Optional explicit overhead buffer (COGS risk buffer), separate from retail safety buffer.
  const overheadBufferRate = clampNonNeg(numEnv("OVERHEAD_BUFFER_RATE") ?? 0);
  const preBufferCogsUsd =
    llmUsd + sttUsd + ttsUsd + telephonyUsd + livekitUsd + recCosts.totalUsd + computeUsd + dbUsd + logsUsd;
  const overheadBufferUsd = preBufferCogsUsd * overheadBufferRate;
  const overheadBufferUsdPerMin = round4(safeDiv(overheadBufferUsd, callMinutesBilled));

  const totalCogsUsd = round4(preBufferCogsUsd + overheadBufferUsd);
  const totalCogsUsdPerMin = round4(safeDiv(totalCogsUsd, callMinutesBilled));

  const cogsBreakdownUsd = {
    llm: round4(llmUsd),
    stt: round4(sttUsd),
    tts: round4(ttsUsd),
    telephony: round4(telephonyUsd),
    livekit: round4(livekitUsd),
    recording: round4(recCosts.recordingUsd),
    storage: round4(recCosts.storageUsd),
    egress: round4(recCosts.egressUsd),
    s3Put: round4(recCosts.s3PutUsd),
    s3Get: round4(recCosts.s3GetUsd),
    compute: round4(computeUsd),
    db: round4(dbUsd),
    logs: round4(logsUsd),
    overheadBuffer: round4(overheadBufferUsd),
  };

  const cogsBreakdownUsdPerMin = {
    llm: llmUsdPerMin,
    stt: sttUsdPerMin,
    tts: ttsUsdPerMin,
    telephony: round4(telephonyUsdPerMin),
    livekit: round4(livekitUsdPerMin),
    recording: round4(safeDiv(recCosts.recordingUsd, callMinutesBilled)),
    storage: round4(safeDiv(recCosts.storageUsd, callMinutesBilled)),
    egress: round4(safeDiv(recCosts.egressUsd, callMinutesBilled)),
    s3Put: round4(safeDiv(recCosts.s3PutUsd, callMinutesBilled)),
    s3Get: round4(safeDiv(recCosts.s3GetUsd, callMinutesBilled)),
    compute: round4(computeUsdPerMin),
    db: round4(dbUsdPerMin),
    logs: round4(logsUsdPerMin),
    overheadBuffer: overheadBufferUsdPerMin,
  };

  // --- Retail pricing ---
  // Preferred: explicit per-call-minute retail price. This prevents silence-time underpricing.
  const retailUsdPerCallMin = numEnv("RETAIL_USD_PER_CALL_MIN");
  const legacyPlatformUsageFeeRate = clampNonNeg(numEnv("PLATFORM_USAGE_FEE_RATE") ?? 0);
  const legacyRetailMultiplier = 1 + legacyPlatformUsageFeeRate;

  const safetyBufferRate = clampNonNeg(numEnv("SAFETY_BUFFER_RATE") ?? 0.25);
  const targetMarginRate = clampNonNeg(numEnv("TARGET_GROSS_MARGIN_RATE") ?? 0.7);
  const retailMode = String(process.env.RETAIL_MODE || "recommended").trim().toLowerCase();

  const trueCogsWithSafetyUsd = totalCogsUsd * (1 + safetyBufferRate);
  const recommendedRetailUsdPerMin = round4((totalCogsUsdPerMin * (1 + safetyBufferRate)) / Math.max(0.0001, 1 - targetMarginRate));

  let retailTotalUsd = 0;
  let retailUsdPerMin = 0;
  let retailMethod = "recommended_per_call_minute";
  if (retailUsdPerCallMin != null && retailUsdPerCallMin > 0) {
    retailMethod = "fixed_per_call_minute";
    retailUsdPerMin = retailUsdPerCallMin;
    retailTotalUsd = retailUsdPerMin * callMinutesBilled;
  } else {
    if (retailMode === "legacy") {
      retailMethod = "legacy_usage_markup";
      retailTotalUsd = totalCogsUsd * legacyRetailMultiplier;
      retailUsdPerMin = round4(safeDiv(retailTotalUsd, callMinutesBilled));
    } else {
      // Default: compute a per-minute price from true COGS/min, add safety buffer, then enforce target gross margin.
      retailMethod = "recommended_per_call_minute";
      retailUsdPerMin = recommendedRetailUsdPerMin;
      retailTotalUsd = retailUsdPerMin * callMinutesBilled;
    }
  }

  // Retail breakdown: show buffer and margin explicitly.
  const safetyBufferUsd = totalCogsUsd * safetyBufferRate;
  const safetyBufferUsdPerMin = round4(safeDiv(safetyBufferUsd, callMinutesBilled));
  const marginUsd = Math.max(0, retailTotalUsd - (totalCogsUsd + safetyBufferUsd));
  const marginUsdPerMin = round4(safeDiv(marginUsd, callMinutesBilled));
  const impliedGrossMarginRate = retailTotalUsd > 0 ? round4(1 - safeDiv(totalCogsUsd, retailTotalUsd)) : null;

  const retailBreakdownUsd = {
    ...cogsBreakdownUsd,
    safetyBuffer: round4(safetyBufferUsd),
    margin: round4(marginUsd),
  };
  const retailBreakdownUsdPerMin = {
    ...cogsBreakdownUsdPerMin,
    safetyBuffer: safetyBufferUsdPerMin,
    margin: marginUsdPerMin,
  };

  return {
    normalized: {
      billedSeconds: round4(billedSeconds),
      callMinutes: round4(callMinutesBilled),
      participantsCountAvg: round4(participantsCountAvg),
      participantMinutes: round4(participantMinutes),
      telephonyMinutes: round4(telephonyMinutes),
      livekitParticipantMinutes: round4(livekitParticipantMinutes),
      source,
    },
    cogs: {
      totalUsd: totalCogsUsd,
      totalUsdPerMin: totalCogsUsdPerMin,
      breakdownUsd: cogsBreakdownUsd,
      breakdownUsdPerMin: cogsBreakdownUsdPerMin,
    },
    retail: {
      method: retailMethod,
      totalUsd: round4(retailTotalUsd),
      totalUsdPerMin: round4(retailUsdPerMin),
      breakdownUsd: retailBreakdownUsd,
      breakdownUsdPerMin: retailBreakdownUsdPerMin,
      safetyBufferRate: round4(safetyBufferRate),
      targetGrossMarginRate: round4(targetMarginRate),
      impliedGrossMarginRate,
      recommendedRetailUsdPerMin,
      trueCogsUsdPerMinWithSafety: round4(safeDiv(trueCogsWithSafetyUsd, callMinutesBilled)),
    },
    usage: usageCogs.raw ?? null,
    pricingConfigured: {
      llm: Boolean(getLlmPricingPer1k(models?.llm)),
      stt: getSttPricingPerMin(models?.stt ?? usage?.stt_model) != null,
      tts: getTtsPricingPer1kChars(models?.tts ?? usage?.tts_model) != null,
      telephony: numEnv("TELEPHONY_USD_PER_MIN") != null || Boolean(parseJsonEnv("TELEPHONY_PRICING_JSON")),
      livekit: getLivekitUsdPerParticipantMin() != null,
      recording: boolEnv("RECORDING_ENABLED_DEFAULT", false) || Boolean(recording?.enabled),
      overhead: true,
    },
  };
}

module.exports = {
  DEFAULT_LLM_PRICING_PER_1M,
  parseJsonEnv,
  numEnv,
  boolEnv,
  round4,
  computeOverheadUsdPerMinFromInputs,
  computeBilledSeconds,
  computeCostBreakdownFromUsage,
  computeCallCosts,
  getTelephonyUsdPerMinForNumber,
};


