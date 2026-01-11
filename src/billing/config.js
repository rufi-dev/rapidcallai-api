function numEnv(name, def = null) {
  const raw = process.env[name];
  if (raw == null || raw === "") return def;
  const n = Number(raw);
  return Number.isFinite(n) ? n : def;
}

function boolEnv(name, def = false) {
  const raw = String(process.env[name] ?? "").trim().toLowerCase();
  if (!raw) return def;
  return raw === "1" || raw === "true" || raw === "yes" || raw === "y" || raw === "on";
}

function jsonEnv(name, def = null) {
  const raw = String(process.env[name] ?? "").trim();
  if (!raw) return def;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" ? v : def;
  } catch {
    return def;
  }
}

function getBillingConfig() {
  return {
    // Defaults should match your Stripe metered price amounts to avoid confusing UI/trial debits.
    // (Paid billing uses Stripe price IDs; these defaults matter mainly for trial + UI display.)
    basePriceUsdPerMin: numEnv("BASE_PRICE_USD_PER_MIN", 0.10),
    defaultLlmModel: String(process.env.DEFAULT_LLM_MODEL || "gpt-5-mini").trim() || "gpt-5-mini",
    includedTokensPerMin: numEnv("INCLUDED_TOKENS_PER_MIN", 2000),
    tokenOverageUsdPer1K: numEnv("TOKEN_OVERAGE_USD_PER_1K", 0.002),
    llmSurchargeUsdPerMinByModel: jsonEnv("LLM_SURCHARGE_JSON", {}) || {},
    // This is an informational number used in the UI; actual paid billing telephony charges are in Stripe.
    telephonyUsdPerMin: numEnv("TELEPHONY_USD_PER_MIN", 0.015),
    telephonyMarkupRate: numEnv("TELEPHONY_MARKUP_RATE", 0.2),
    phoneNumberMonthlyFeeUsd: numEnv("PHONE_NUMBER_MONTHLY_FEE_USD", 2.0),
    trialCreditUsd: numEnv("TRIAL_CREDIT_USD", 20),
    trialAllowPstn: boolEnv("TRIAL_ALLOW_PSTN", false),
    trialAllowNumberPurchase: boolEnv("TRIAL_ALLOW_NUMBER_PURCHASE", false),
  };
}

module.exports = { numEnv, boolEnv, jsonEnv, getBillingConfig };


