const { getBillingConfig } = require("./config");
const { computeCallBillingQuantities, computeTrialDebitUsd } = require("./pricing");
const { emitOpenMeterEvent } = require("./openmeter");
const { getMeteredPriceIdsFromEnv, recordMeterEventsForWorkspace } = require("./stripe");

function safeObj(x) {
  return x && typeof x === "object" ? x : {};
}

function callSourceFromRecord(call) {
  const metrics = safeObj(call?.metrics);
  const normalized = safeObj(metrics.normalized);
  const source = String(normalized.source || "").trim();
  if (source) return source;
  if (call?.to === "webtest") return "web";
  return "unknown";
}

function callTotalTokens(call) {
  const metrics = safeObj(call?.metrics);
  if (typeof metrics.tokensTotal === "number" && Number.isFinite(metrics.tokensTotal)) return metrics.tokensTotal;
  const usage = safeObj(metrics.usage);
  return Number(usage.llm_prompt_tokens || 0) + Number(usage.llm_completion_tokens || 0);
}

function callLlmModel(call, cfg) {
  const metrics = safeObj(call?.metrics);
  const models = safeObj(metrics.models);
  const usage = safeObj(metrics.usage);
  return String(models.llm || usage.llm_model || cfg.defaultLlmModel).trim() || cfg.defaultLlmModel;
}

async function finalizeBillingForCall({ store, call }) {
  if (!call || !call.id || !call.workspaceId) return null;
  if (call.endedAt == null || call.durationSec == null) return null;

  const cfg = getBillingConfig();
  const ws = await store.getWorkspace(call.workspaceId);
  if (!ws) return null;

  const source = callSourceFromRecord(call);
  const totalTokens = callTotalTokens(call);
  const llmModel = callLlmModel(call, cfg);

  const q = computeCallBillingQuantities({
    durationSec: call.durationSec,
    totalTokens,
    llmModel,
    source,
    config: cfg,
  });

  const metrics = safeObj(call.metrics);
  const billingPrev = safeObj(metrics.billing);
  const finalizeKey = `${call.id}:${Number(call.endedAt || 0)}`;
  if (billingPrev.finalizeKey === finalizeKey && billingPrev.finalizedAt) {
    return null;
  }
  if (billingPrev.finalizeKey !== finalizeKey) {
    await store.updateCall(call.id, {
      metrics: {
        ...metrics,
        billing: {
          ...billingPrev,
          finalizeKey,
          finalizeStartedAt: Date.now(),
        },
      },
    });
  }

  // --- Trial debit (WEB only) ---
  if (ws.isTrial && !ws.isPaid) {
    if ((source === "telephony" || source === "pstn") && !cfg.trialAllowPstn) return null;

    if (!billingPrev.trialDebitedAt) {
      const debitUsd = computeTrialDebitUsd({
        durationSec: call.durationSec,
        totalTokens,
        llmModel,
        source,
        config: cfg,
      });

      await store.debitTrialCreditUsd(ws.id, debitUsd);
      await store.updateCall(call.id, {
        metrics: {
          ...metrics,
          billing: {
            ...billingPrev,
            billedMinutes: q.billedMinutes,
            modelUpgradeMinutes: q.modelUpgradeMinutes,
            tokenOverage1k: q.tokenOverage1k,
            trialDebitedUsd: debitUsd,
            trialDebitedAt: Date.now(),
            finalizeKey,
            finalizedAt: Date.now(),
          },
        },
      });
    }

    return null;
  }

  // --- Paid: emit OpenMeter event (idempotent) ---
  if (ws.isPaid) {
    const nowIso = new Date().toISOString();
    const subject = String(ws.id);

    // Track per-event sending so we can retry partial failures safely.
    const prevEvents = safeObj(billingPrev.openmeterEvents);
    const nextEvents = { ...prevEvents };

    const prevStripe = safeObj(billingPrev.stripeUsage);
    const nextStripe = { ...prevStripe };

    async function sendIfNeeded({ type, data, required }) {
      const prev = safeObj(prevEvents[type]);
      if (prev.sentAt) {
        nextEvents[type] = { ...prev };
        return { ok: true, skipped: true };
      }

      const event = {
        id: `${call.id}:${type}`,
        type,
        subject,
        time: nowIso,
        data,
      };

      const omRes = await emitOpenMeterEvent({
        apiUrl: process.env.OPENMETER_API_URL,
        apiKey: process.env.OPENMETER_API_KEY,
        source: process.env.OPENMETER_SOURCE || "voice-platform",
        event,
      });

      nextEvents[type] = {
        id: event.id,
        sentAt: omRes?.ok ? Date.now() : null,
        error: omRes?.ok ? null : { status: omRes?.status ?? 0, text: String(omRes?.text || "") },
        required: Boolean(required),
      };

      return omRes;
    }

    // 1) Base voice minutes (always required)
    await sendIfNeeded({ type: "voice_base_minutes", required: true, data: { minutes: Number(q.billedMinutes || 0) } });

    // 2) Model upgrade minutes (only when > 0)
    if (Number(q.modelUpgradeMinutes || 0) > 0) {
      await sendIfNeeded({
        type: "voice_model_upgrade_minutes",
        required: true,
        data: { minutes: Number(q.modelUpgradeMinutes || 0) },
      });
    }

    // 3) Telephony minutes (only for PSTN / telephony)
    if (Number(q.telephonyMinutes || 0) > 0) {
      await sendIfNeeded({
        type: "telephony_minutes",
        required: true,
        data: { minutes: Number(q.telephonyMinutes || 0) },
      });
    }

    // 4) Token overage (1k tokens), must be in thousands
    if (Number(q.tokenOverage1k || 0) > 0) {
      await sendIfNeeded({
        type: "llm_token_overage_1k",
        required: true,
        data: { thousands: Number(q.tokenOverage1k || 0) },
      });
    }

    // --- Paid: ALSO record usage to Stripe via Billing Meter Events (so Stripe upcoming invoices show usage)
    // This is separate from OpenMeter and is safe as long as you do NOT also invoice via OpenMeter->Stripe sync.
    try {
      if (ws.stripeCustomerId) {
        const priceIds = getMeteredPriceIdsFromEnv();
        const usageByPriceId = {};

        // Stripe Billing Meter Events accept numeric values. We send fractional units so short calls
        // don't jump to whole minutes.
        const baseMin = Number(q.billedMinutes || 0);
        const upgradeMin = Number(q.modelUpgradeMinutes || 0);
        const telMin = Number(q.telephonyMinutes || 0);
        const tok1k = Number(q.tokenOverage1k || 0);

        if (baseMin > 0 && priceIds.baseMinutes) usageByPriceId[priceIds.baseMinutes] = baseMin;
        if (upgradeMin > 0 && priceIds.modelUpgradeMinutes) usageByPriceId[priceIds.modelUpgradeMinutes] = upgradeMin;
        if (telMin > 0 && priceIds.telephonyMinutes) usageByPriceId[priceIds.telephonyMinutes] = telMin;
        if (tok1k > 0 && priceIds.tokenOverage) usageByPriceId[priceIds.tokenOverage] = tok1k;

        // Idempotency per call+price. Only mark sentAt if at least one event succeeded.
        const alreadySent = Boolean(nextStripe?.sentAt);
        if (!alreadySent && Object.keys(usageByPriceId).length > 0) {
          const ts = Math.floor(Number(call.endedAt || Date.now()) / 1000);
          const r = await recordMeterEventsForWorkspace({
            customerId: ws.stripeCustomerId,
            usageByPriceId,
            timestampSec: ts,
            idempotencyKeyPrefix: `call:${call.id}`,
          });
          nextStripe.results = r;
          const anyOk = Object.values(r || {}).some((x) => Boolean(x?.ok));
          nextStripe.sentAt = anyOk ? Date.now() : null;
        }
      }
    } catch (e) {
      nextStripe.error = String(e?.message || e);
      nextStripe.sentAt = null;
    }

    const requiredTypes = Object.entries(nextEvents)
      .filter(([, v]) => Boolean(v?.required))
      .map(([k]) => k);
    const allRequiredSent = requiredTypes.every((t) => Boolean(nextEvents[t]?.sentAt));

    const shouldFinalize =
      allRequiredSent && (!ws.stripeCustomerId || Boolean(nextStripe?.sentAt));

    await store.updateCall(call.id, {
      metrics: {
        ...metrics,
        billing: {
          ...billingPrev,
          billedMinutes: q.billedMinutes,
          modelUpgradeMinutes: q.modelUpgradeMinutes,
          tokenOverage1k: q.tokenOverage1k,
          telephonyMinutes: q.telephonyMinutes,
          openmeterEvents: nextEvents,
          openmeterLastAttemptAt: Date.now(),
          openmeterSentAt: allRequiredSent ? Date.now() : null,
          stripeUsage: nextStripe,
          finalizeKey,
          finalizedAt: shouldFinalize ? Date.now() : null,
        },
      },
    });

    return null;
  }

  return null;
}

module.exports = { finalizeBillingForCall };


