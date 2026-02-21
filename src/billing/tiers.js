"use strict";

/**
 * Map LLM provider/model to ai_tier (economy | standard | premium | realtime).
 * Keep configurable so tiers can change without code deploy.
 */
const AI_TIER_PATTERNS = [
  { pattern: /nano|lite|mini-lite|flash-lite|nano/i, tier: "economy" },
  { pattern: /realtime|streaming.*audio|audio.*stream/i, tier: "realtime" },
  { pattern: /mini|flash|haiku/i, tier: "standard" },
  { pattern: /sonnet|gpt-5\.|gpt-4\.1|gemini.*pro|full/i, tier: "premium" },
  { pattern: /.*/, tier: "standard" },
];

/**
 * Map TTS/voice provider/model to voice_tier (standard | premium | ultra).
 */
const VOICE_TIER_PATTERNS = [
  { pattern: /ultra|44\.1|pcm|best.*quality|high.*quality/i, tier: "ultra" },
  { pattern: /premium|v2|v3|multilingual/i, tier: "premium" },
  { pattern: /flash|low.*latency|low.*cost|standard/i, tier: "standard" },
  { pattern: /.*/, tier: "standard" },
];

function getAiTier(modelName) {
  if (!modelName || typeof modelName !== "string") return "standard";
  const m = modelName.trim().toLowerCase();
  for (const { pattern, tier } of AI_TIER_PATTERNS) {
    if (pattern.test(m)) return tier;
  }
  return "standard";
}

function getVoiceTier(modelName) {
  if (!modelName || typeof modelName !== "string") return "standard";
  const m = modelName.trim().toLowerCase();
  for (const { pattern, tier } of VOICE_TIER_PATTERNS) {
    if (pattern.test(m)) return tier;
  }
  return "standard";
}

module.exports = {
  getAiTier,
  getVoiceTier,
};
