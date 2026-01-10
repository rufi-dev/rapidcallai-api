const { getBillingConfig } = require("./config");

function billedMinutesFromDurationSec(durationSec) {
  const sec = Number(durationSec || 0);
  // Bill per-second (fractional minutes) instead of rounding up to whole minutes.
  // This matches "Retell-like" transparency and avoids big jumps for short calls.
  if (!Number.isFinite(sec) || sec <= 0) return 0;
  // durationSec is an integer (rounded in src/index.js), so minimum non-zero is 1 second.
  return round6(Math.max(1 / 60, sec / 60));
}

function round6(n) {
  return Math.round(Number(n || 0) * 1_000_000) / 1_000_000;
}

function getModelSurchargeUsdPerMin(llmModel, cfg) {
  const raw = String(llmModel || "").trim();
  const model = raw;
  if (!model) return 0;

  const def = String(cfg.defaultLlmModel || "").trim();
  if (def && model === def) return 0;

  const table = cfg.llmSurchargeUsdPerMinByModel || {};

  // Be forgiving about model naming differences (e.g. "gpt5.2" vs "gpt-5.2").
  const normalize = (s) =>
    String(s || "")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "")
      .replace(/[_/]/g, "-")
      .replace(/[^a-z0-9.\-]/g, "");

  const keys = Object.keys(table || {});
  const direct = table[model];
  const directLower = table[model.toLowerCase?.()];
  const normalized = normalize(model);
  const matchKey = keys.find((k) => normalize(k) === normalized) || null;

  const v = Number(direct ?? directLower ?? (matchKey ? table[matchKey] : 0) ?? 0);
  return Number.isFinite(v) && v > 0 ? v : 0;
}

function computeTokenOverage1k(totalTokens, billedMinutes, cfg) {
  const tokens = Number(totalTokens || 0);
  const mins = Number(billedMinutes || 0);
  const included = Math.max(0, Number(cfg.includedTokensPerMin || 0)) * Math.max(0, mins);
  const over = Math.max(0, (Number.isFinite(tokens) ? tokens : 0) - included);
  return round6(over / 1000);
}

function computeCallBillingQuantities(input) {
  const cfg = input?.config || getBillingConfig();
  const durationSec = Number(input?.durationSec || 0);
  const billedMinutes = billedMinutesFromDurationSec(durationSec);

  const llmModel = String(input?.llmModel || cfg.defaultLlmModel).trim() || cfg.defaultLlmModel;
  const modelSurchargeUsdPerMin = getModelSurchargeUsdPerMin(llmModel, cfg);
  const modelUpgradeMinutes = modelSurchargeUsdPerMin > 0 ? billedMinutes : 0;

  const totalTokens = Number(input?.totalTokens || 0);
  const tokenOverage1k = computeTokenOverage1k(totalTokens, billedMinutes, cfg);

  const source = String(input?.source || "unknown");
  const telephonyMinutes = source === "telephony" || source === "pstn" ? billedMinutes : 0;

  return {
    billedMinutes,
    llmModel,
    modelUpgradeMinutes,
    tokenOverage1k,
    telephonyMinutes,
  };
}

function computeTrialDebitUsd(input) {
  const cfg = input?.config || getBillingConfig();
  const q = computeCallBillingQuantities({ ...input, config: cfg });

  const baseUsd = Math.max(0, Number(cfg.basePriceUsdPerMin || 0)) * q.billedMinutes;
  const surchargeUsd = getModelSurchargeUsdPerMin(q.llmModel, cfg) * q.modelUpgradeMinutes;
  const tokenOverageUsd = Math.max(0, Number(cfg.tokenOverageUsdPer1K || 0)) * q.tokenOverage1k;

  // Trial explicitly excludes telephony.
  return round6(baseUsd + surchargeUsd + tokenOverageUsd);
}

module.exports = {
  billedMinutesFromDurationSec,
  computeCallBillingQuantities,
  computeTrialDebitUsd,
};


