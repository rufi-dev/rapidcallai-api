const { getBillingConfig } = require("./config");

function billedMinutesFromDurationSec(durationSec) {
  const sec = Number(durationSec || 0);
  if (!Number.isFinite(sec) || sec <= 0) return 1;
  return Math.max(1, Math.ceil(sec / 60));
}

function round6(n) {
  return Math.round(Number(n || 0) * 1_000_000) / 1_000_000;
}

function getModelSurchargeUsdPerMin(llmModel, cfg) {
  const model = String(llmModel || "").trim();
  if (!model) return 0;
  if (model === cfg.defaultLlmModel) return 0;
  const table = cfg.llmSurchargeUsdPerMinByModel || {};
  const v = Number(table[model] ?? 0);
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


