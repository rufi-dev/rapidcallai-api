"use strict";

const { getAiTier, getVoiceTier } = require("./tiers");

const SHORT_CALL_DURATION_SEC = 20;

/**
 * Build Metronome ingest events for a single call. Use call id + suffix for idempotent transaction_id.
 * @param {{ callId: string, customerId: string, startedAt: number, metrics?: object, durationSec?: number }} params
 * @returns {Array<{ transaction_id: string, customer_id: string, timestamp: string, event_type: string, properties: Record<string, string> }>}
 */
function buildCallUsageEvents({ callId, customerId, startedAt, metrics = {}, durationSec = 0 }) {
  const ts = new Date(startedAt).toISOString();
  const events = [];

  const usage = metrics?.usage || {};
  const tokensIn = Number(usage.llm_prompt_tokens || 0);
  const tokensOut = Number(usage.llm_completion_tokens || 0);
  const totalTokens = tokensIn + tokensOut;
  const aiUnits = totalTokens / 1000;
  const llmModel = metrics?.models?.llm || usage.llm_model || "";
  const aiTier = getAiTier(llmModel);

  if (aiUnits > 0) {
    events.push({
      transaction_id: `${callId}-ai_usage`,
      customer_id: customerId,
      timestamp: ts,
      event_type: "ai_usage",
      properties: {
        units: String(aiUnits),
        ai_tier: aiTier,
      },
    });
  }

  const ttsMinutes = Number(usage.tts_audio_duration || 0) / 60;
  const ttsModel = metrics?.models?.tts || usage.tts_model || "";
  const voiceTier = getVoiceTier(ttsModel);
  if (ttsMinutes > 0) {
    events.push({
      transaction_id: `${callId}-voice_minutes`,
      customer_id: customerId,
      timestamp: ts,
      event_type: "voice_minutes",
      properties: {
        minutes: String(ttsMinutes),
        voice_tier: voiceTier,
      },
    });
  }

  const sttMinutes = Number(usage.stt_audio_duration || 0) / 60;
  if (sttMinutes > 0) {
    events.push({
      transaction_id: `${callId}-transcription`,
      customer_id: customerId,
      timestamp: ts,
      event_type: "transcription",
      properties: {
        minutes: String(sttMinutes),
      },
    });
  }

  const kbQueries = Number(metrics?.knowledge_base_queries ?? 0) || 0;
  if (kbQueries > 0) {
    events.push({
      transaction_id: `${callId}-knowledge_base`,
      customer_id: customerId,
      timestamp: ts,
      event_type: "knowledge_base",
      properties: {
        count: String(kbQueries),
      },
    });
  }

  if (durationSec > 0 && durationSec < SHORT_CALL_DURATION_SEC) {
    events.push({
      transaction_id: `${callId}-short_call_surcharge`,
      customer_id: customerId,
      timestamp: ts,
      event_type: "short_call_surcharge",
      properties: {
        count: "1",
      },
    });
  }

  return events;
}

/**
 * Compute cost breakdown for display (using plan rates). Not used for Metronome invoicing; Metronome rates.
 * @param {{ plan: 'starter'|'pro'|'scale', aiUnits: number, aiTier: string, voiceMinutes: number, voiceTier: string, transcriptionMinutes: number, kbQueries: number, shortCallSurcharge: boolean }}
 * @returns {{ breakdown: Record<string, number>, total: number }}
 */
function computeCostBreakdown({ plan, aiUnits = 0, aiTier, voiceMinutes = 0, voiceTier, transcriptionMinutes = 0, kbQueries = 0, shortCallSurcharge = false }) {
  const rates = getPlanRates(plan);
  const breakdown = {};

  if (aiUnits > 0 && rates.ai[aiTier] != null) {
    breakdown.ai_usage = Math.round(aiUnits * rates.ai[aiTier] * 1000000) / 1000000;
  }
  if (voiceMinutes > 0 && rates.voice[voiceTier] != null) {
    breakdown.voice_minutes = Math.round(voiceMinutes * rates.voice[voiceTier] * 1000000) / 1000000;
  }
  if (transcriptionMinutes > 0) {
    breakdown.transcription = Math.round(transcriptionMinutes * rates.transcription * 1000000) / 1000000;
  }
  if (kbQueries > 0) {
    breakdown.knowledge_base = Math.round(kbQueries * rates.knowledge_base * 1000000) / 1000000;
  }
  if (shortCallSurcharge) {
    breakdown.short_call_surcharge = rates.short_call_surcharge;
  }

  const total = Object.values(breakdown).reduce((a, b) => a + b, 0);
  return { breakdown, total: Math.round(total * 1000000) / 1000000 };
}

function getPlanRates(plan) {
  const RATES = {
    starter: {
      ai: { economy: 0.012, standard: 0.022, premium: 0.045, realtime: 0.09 },
      voice: { standard: 0.28, premium: 0.38, ultra: 0.55 },
      transcription: 0.05,
      knowledge_base: 0.008,
      short_call_surcharge: 0.07,
    },
    pro: {
      ai: { economy: 0.01, standard: 0.02, premium: 0.04, realtime: 0.08 },
      voice: { standard: 0.25, premium: 0.35, ultra: 0.5 },
      transcription: 0.04,
      knowledge_base: 0.006,
      short_call_surcharge: 0.06,
    },
    scale: {
      ai: { economy: 0.009, standard: 0.018, premium: 0.035, realtime: 0.07 },
      voice: { standard: 0.23, premium: 0.32, ultra: 0.45 },
      transcription: 0.035,
      knowledge_base: 0.005,
      short_call_surcharge: 0.05,
    },
  };
  return RATES[plan] || RATES.starter;
}

/**
 * After a call is ended and persisted: send usage to Metronome and compute cost for the call.
 * Returns patch to apply to call.metrics (costBreakdown, computedTotalCost) and sends events.
 * @param {object} call - Call record with id, workspaceId, startedAt, durationSec, metrics
 * @param {object} workspace - Workspace with metronomeCustomerId, billingPlan
 * @param {object} metronomeClient - { ingestEvents } from metronome/client
 * @returns {Promise<{ costBreakdown: object, computedTotalCost: number }|null>} - Metrics to merge into call, or null if skipped
 */
async function emitCallUsageAndComputeCost(call, workspace, metronomeClient) {
  if (!workspace?.metronomeCustomerId || !metronomeClient?.ingestEvents) return null;
  const plan = workspace.billingPlan || "starter";
  const events = buildCallUsageEvents({
    callId: call.id,
    customerId: workspace.metronomeCustomerId,
    startedAt: call.startedAt,
    metrics: call.metrics,
    durationSec: call.durationSec ?? 0,
  });
  if (events.length > 0) {
    try {
      await metronomeClient.ingestEvents(events);
    } catch (e) {
      // Log but do not fail the request; cost still computed locally
      if (typeof process !== "undefined" && process.emit) {
        process.emit("warning", new Error(`Metronome ingest failed: ${e?.message || e}`));
      }
    }
  }
  const usage = call.metrics?.usage || {};
  const tokensTotal = Number(usage.llm_prompt_tokens || 0) + Number(usage.llm_completion_tokens || 0);
  const aiUnits = tokensTotal / 1000;
  const { getAiTier, getVoiceTier } = require("./tiers");
  const aiTier = getAiTier(call.metrics?.models?.llm || usage.llm_model);
  const voiceTier = getVoiceTier(call.metrics?.models?.tts || usage.tts_model);
  const ttsMin = Number(usage.tts_audio_duration || 0) / 60;
  const sttMin = Number(usage.stt_audio_duration || 0) / 60;
  const kbQueries = Number(call.metrics?.knowledge_base_queries ?? 0) || 0;
  const shortCall = (call.durationSec ?? 0) > 0 && (call.durationSec ?? 0) < SHORT_CALL_DURATION_SEC;
  const { breakdown, total } = computeCostBreakdown({
    plan,
    aiUnits,
    aiTier,
    voiceMinutes: ttsMin,
    voiceTier,
    transcriptionMinutes: sttMin,
    kbQueries,
    shortCallSurcharge: shortCall,
  });
  return { costBreakdown: breakdown, computedTotalCost: total };
}

module.exports = {
  buildCallUsageEvents,
  computeCostBreakdown,
  emitCallUsageAndComputeCost,
  SHORT_CALL_DURATION_SEC,
};
