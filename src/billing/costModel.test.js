// Simple sanity tests for cost model normalization and summation.
// Run via: `node src/billing/costModel.test.js`

const assert = require("assert");

process.env.LLM_INPUT_USD_PER_1K = "0.001"; // $1 / 1M
process.env.LLM_OUTPUT_USD_PER_1K = "0.002"; // $2 / 1M
process.env.STT_USD_PER_MIN = "0.006";
process.env.TTS_USD_PER_1K_CHARS = "0.0003";
process.env.TELEPHONY_USD_PER_MIN = "0.013";
process.env.LIVEKIT_USD_PER_PARTICIPANT_MIN = "0.0008";
process.env.DEFAULT_PARTICIPANTS_COUNT_AVG = "2";
process.env.OVERHEAD_BUFFER_RATE = "0.1";
process.env.SAFETY_BUFFER_RATE = "0.25";
process.env.TARGET_GROSS_MARGIN_RATE = "0.7";
process.env.RETAIL_USD_PER_CALL_MIN = "0.12";
process.env.BILLING_ROUND_UP_TO_SECONDS = "60";
process.env.BILLING_MINIMUM_BILLABLE_SECONDS = "60";

const { computeCallCosts, computeOverheadUsdPerMinFromInputs } = require("./costModel");

function approx(a, b, eps = 1e-6) {
  assert.ok(Math.abs(a - b) <= eps, `expected ${a} ~= ${b}`);
}

function round4(n) {
  return Math.round(Number(n || 0) * 10000) / 10000;
}

// Overhead allocation sanity
{
  const overhead = computeOverheadUsdPerMinFromInputs({
    allocatedMinutesPerMonth: 100000,
    budgetsUsdPerMonth: { computeUsdPerMonth: 1000, dbUsdPerMonth: 500, logsUsdPerMonth: 250 },
  });
  approx(overhead.computeUsdPerMin, 0.01);
  approx(overhead.dbUsdPerMin, 0.005);
  approx(overhead.logsUsdPerMin, 0.0025);
}

// Per-call and per-minute normalization sanity
{
  const durationSec = 61; // rounds up to 120s -> 2.0 min billed
  const usage = {
    llm_prompt_tokens: 1000,
    llm_prompt_cached_tokens: 0,
    llm_completion_tokens: 500,
    stt_audio_duration: 60,
    tts_characters_count: 1000,
  };
  const models = { llm: "any", stt: "any", tts: "any" };
  const overheadUsdPerMin = { computeUsdPerMin: 0.01, dbUsdPerMin: 0.005, logsUsdPerMin: 0.0025 };

  const out = computeCallCosts({ durationSec, usage, models, normalizedInput: { source: "telephony" }, recording: null, overheadUsdPerMin });

  // Billed minutes (round to 60s): 61s => 120s => 2 min
  approx(out.normalized.callMinutes, 2.0);
  approx(out.normalized.telephonyMinutes, 2.0);
  approx(out.normalized.participantMinutes, 4.0); // 2 participants avg

  // LLM cost: 1000*0.001/1000 + 500*0.002/1000 = 0.001 + 0.001 = 0.002
  approx(out.cogs.breakdownUsd.llm, 0.002);
  // STT: 60s => 1 min * 0.006
  approx(out.cogs.breakdownUsd.stt, 0.006);
  // TTS: 1000 chars => 1K * 0.0003
  approx(out.cogs.breakdownUsd.tts, 0.0003);
  // Telephony: 2 min * 0.013
  approx(out.cogs.breakdownUsd.telephony, 0.026);
  // LiveKit: 4 participant-min * 0.0008
  approx(out.cogs.breakdownUsd.livekit, 0.0032);

  // Per-minute normalization: per-call / minutes
  approx(out.cogs.breakdownUsdPerMin.llm, round4(out.cogs.breakdownUsd.llm / out.normalized.callMinutes));
  approx(out.cogs.breakdownUsdPerMin.stt, round4(out.cogs.breakdownUsd.stt / out.normalized.callMinutes));
  approx(out.cogs.breakdownUsdPerMin.tts, round4(out.cogs.breakdownUsd.tts / out.normalized.callMinutes));

  // Retail uses fixed per-minute pricing
  approx(out.retail.totalUsd, 0.12 * 2.0);
  approx(out.retail.totalUsdPerMin, 0.12);
}

console.log("costModel tests passed");


