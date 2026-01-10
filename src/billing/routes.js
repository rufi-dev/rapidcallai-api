const express = require("express");
const { getBillingConfig } = require("./config");
const { listOpenMeterCustomerEntitlements } = require("./openmeter");

function createBillingRouter({ store, stripeBilling }) {
  const r = express.Router();

  // Recovery endpoint: if a workspace is marked paid but missing its subscription, (re)create it.
  r.post("/ensure-subscription", async (req, res) => {
    if (!store) return res.status(400).json({ error: "Billing requires Postgres mode" });
    const ws = req.workspace;
    if (!ws?.id) return res.status(401).json({ error: "Unauthorized" });
    if (!ws.isPaid) return res.status(402).json({ error: "Upgrade required" });

    try {
      // Ensure customer exists
      const { customerId } = await stripeBilling.ensureStripeCustomerForWorkspace({
        ...ws,
        userEmail: req.user?.email,
      });
      if (!ws.stripeCustomerId) await store.updateWorkspace(ws.id, { stripeCustomerId: customerId });

      // Ensure subscription exists
      const latest = await store.getWorkspace(ws.id);
      if (!latest) return res.status(404).json({ error: "Workspace not found" });
      if (!latest.stripeSubscriptionId) {
        const phoneNumbers = await store.listPhoneNumbers(ws.id);
        const sub = await stripeBilling.createSubscriptionForWorkspace({
          workspaceId: ws.id,
          customerId: latest.stripeCustomerId || customerId,
          phoneNumbersCount: phoneNumbers.length,
        });
        await store.updateWorkspace(ws.id, {
          stripeSubscriptionId: sub.subscriptionId,
          stripePhoneNumbersItemId: sub.phoneNumbersItemId,
        });
      }

      const updated = await store.getWorkspace(ws.id);
      return res.json({
        ok: true,
        workspace: {
          id: updated?.id,
          stripeCustomerId: updated?.stripeCustomerId ?? null,
          stripeSubscriptionId: updated?.stripeSubscriptionId ?? null,
          stripePhoneNumbersItemId: updated?.stripePhoneNumbersItemId ?? null,
        },
      });
    } catch (e) {
      return res.status(400).json({ error: e instanceof Error ? e.message : "Failed to configure subscription" });
    }
  });

  r.get("/status", async (req, res) => {
    const cfg = getBillingConfig();
    const ws = req.workspace;

    const trialCreditUsd = typeof ws?.trialCreditUsd === "number" ? ws.trialCreditUsd : Number(ws?.trialCreditUsd || 0);
    const base = Math.max(0.000001, Number(cfg.basePriceUsdPerMin || 0.13));
    const approxMinutesRemaining = Math.max(0, Math.floor(Math.max(0, trialCreditUsd) / base));

    return res.json({
      workspaceId: ws.id,
      mode: ws.isPaid ? "paid" : "trial",
      isTrial: Boolean(ws.isTrial),
      isPaid: Boolean(ws.isPaid),
      hasPaymentMethod: Boolean(ws.hasPaymentMethod),
      telephonyEnabled: Boolean(ws.telephonyEnabled),
        stripe: {
          customerId: ws.stripeCustomerId ?? null,
          subscriptionId: ws.stripeSubscriptionId ?? null,
        },
      trial: {
        creditUsd: Math.max(0, Math.round(trialCreditUsd * 100) / 100),
        approxMinutesRemaining,
        allowPstn: Boolean(cfg.trialAllowPstn),
        allowNumberPurchase: Boolean(cfg.trialAllowNumberPurchase),
      },
      pricing: {
        baseUsdPerMin: Number(cfg.basePriceUsdPerMin || 0.13),
        defaultLlmModel: cfg.defaultLlmModel,
        includedTokensPerMin: Number(cfg.includedTokensPerMin || 0),
        tokenOverageUsdPer1K: Number(cfg.tokenOverageUsdPer1K || 0),
        llmSurchargeUsdPerMinByModel: cfg.llmSurchargeUsdPerMinByModel || {},
        telephonyUsdPerMin: Number(cfg.telephonyUsdPerMin || 0),
        telephonyMarkupRate: Number(cfg.telephonyMarkupRate || 0),
        phoneNumberMonthlyFeeUsd: Number(cfg.phoneNumberMonthlyFeeUsd || 0),
      },
    });
  });

  r.post("/upgrade", async (req, res) => {
    if (!store) return res.status(400).json({ error: "Billing upgrade requires Postgres mode" });
    const ws = req.workspace;
    if (ws.isPaid && ws.hasPaymentMethod) return res.json({ ok: true, alreadyPaid: true });

    try {
      const { customerId } = await stripeBilling.ensureStripeCustomerForWorkspace({
        ...ws,
        userEmail: req.user?.email,
      });
      if (!ws.stripeCustomerId) await store.updateWorkspace(ws.id, { stripeCustomerId: customerId });
      const session = await stripeBilling.createUpgradeCheckoutSession({ customerId, workspaceId: ws.id });
      return res.json({ ok: true, url: session.url });
    } catch (e) {
      return res.status(400).json({ error: e instanceof Error ? e.message : "Upgrade failed" });
    }
  });

  r.get("/upcoming-invoice", async (req, res) => {
    if (!store) return res.status(400).json({ error: "Billing requires Postgres mode" });
    const ws = req.workspace;
    if (!ws.isPaid) return res.status(402).json({ error: "Upgrade required" });
    if (!ws.stripeCustomerId || !ws.stripeSubscriptionId) return res.status(400).json({ error: "Stripe subscription not configured" });

    try {
      const inv = await stripeBilling.getUpcomingInvoice({ customerId: ws.stripeCustomerId, subscriptionId: ws.stripeSubscriptionId });
      const currency = String(inv.currency || "usd").toUpperCase();
      const totalCents = Number(inv.total || 0);
      const lines = (inv.lines?.data || []).map((l) => ({
        id: l.id,
        description: l.description || l.price?.nickname || l.price?.id || "Line item",
        amountCents: Number(l.amount || 0),
        quantity: l.quantity == null ? null : Number(l.quantity),
        unitAmountCents: l.price?.unit_amount == null ? null : Number(l.price.unit_amount),
        priceId: l.price?.id ?? null,
        proration: Boolean(l.proration),
        periodStart: l.period?.start ? Number(l.period.start) * 1000 : null,
        periodEnd: l.period?.end ? Number(l.period.end) * 1000 : null,
      }));

      const sumCents = lines.reduce((a, x) => a + Number(x.amountCents || 0), 0);
      const dueNowCents = lines.filter((l) => l.proration).reduce((a, x) => a + Number(x.amountCents || 0), 0);
      const nextInvoiceCents = totalCents;
      return res.json({
        currency,
        totalCents,
        totalUsd: Math.round((totalCents / 100) * 100) / 100,
        dueNowCents,
        dueNowUsd: Math.round((dueNowCents / 100) * 100) / 100,
        nextInvoiceCents,
        nextInvoiceUsd: Math.round((nextInvoiceCents / 100) * 100) / 100,
        lines,
        sums: { linesCents: sumCents, matchesTotal: sumCents === totalCents },
      });
    } catch (e) {
      return res.status(400).json({ error: e instanceof Error ? e.message : "Failed to load upcoming invoice" });
    }
  });

  // Retell-style: show "this month so far" usage directly from OpenMeter (Stripe upcoming invoice previews are confusing).
  r.get("/usage-summary", async (req, res) => {
    const ws = req.workspace;
    if (!ws?.id) return res.status(401).json({ error: "Unauthorized" });

    try {
      const customerKey = String(ws.openmeterCustomerId || ws.id);
      const ent = await listOpenMeterCustomerEntitlements({
        apiUrl: process.env.OPENMETER_API_URL,
        apiKey: process.env.OPENMETER_API_KEY,
        customerIdOrKey: customerKey,
      });

      if (ent?.skipped) {
        return res.json({
          ok: true,
          skipped: true,
          reason: ent.reason,
          periodStartMs: null,
          periodEndMs: null,
          totalCents: 0,
          totalUsd: 0,
          lines: [],
        });
      }

      if (!ent?.ok) {
        return res.status(400).json({
          error: "Failed to load OpenMeter usage",
          details: { status: ent.status, text: ent.text, endpoint: ent.endpoint },
        });
      }

      const wanted = {
        voice_base_minutes: { label: "Base voice minutes", unit: "min", stripePriceEnv: "STRIPE_PRICE_ID_BASE_MINUTES" },
        voice_model_upgrade_minutes: {
          label: "Model upgrade minutes",
          unit: "min",
          stripePriceEnv: "STRIPE_PRICE_ID_MODEL_UPGRADE_MINUTES",
        },
        telephony_minutes: { label: "Telephony minutes", unit: "min", stripePriceEnv: "STRIPE_PRICE_ID_TELEPHONY_MINUTES" },
        llm_token_overage_1k: { label: "LLM token overage", unit: "1k tokens", stripePriceEnv: "STRIPE_PRICE_ID_TOKEN_OVERAGE" },
      };

      const usageByKey = {};
      for (const e of ent.entitlements || []) {
        const key =
          String(
            e?.featureKey ??
              e?.feature?.key ??
              e?.feature?.id ??
              e?.feature ??
              e?.key ??
              e?.id ??
              ""
          ) || "";
        if (!key || !wanted[key]) continue;
        const usage = Number(e?.usage ?? e?.currentUsage ?? e?.current_usage ?? 0) || 0;
        usageByKey[key] = usage;
      }

      const s = stripeBilling?.getStripe?.() || null;
      const priceCache = new Map();
      async function getUnitAmountCents(priceId) {
        const id = String(priceId || "").trim();
        if (!id) return null;
        if (priceCache.has(id)) return priceCache.get(id);
        if (!s) return null;
        const p = await s.prices.retrieve(id);
        const cents = p?.unit_amount == null ? null : Number(p.unit_amount);
        priceCache.set(id, cents);
        return cents;
      }

      const lines = [];
      for (const [k, meta] of Object.entries(wanted)) {
        const quantity = Math.max(0, Number(usageByKey[k] || 0));
        const priceId = String(process.env[meta.stripePriceEnv] || "").trim();
        const unitAmountCents = await getUnitAmountCents(priceId);
        const amountCents = unitAmountCents == null ? null : Math.round(quantity * unitAmountCents);
        lines.push({
          key: k,
          description: meta.label,
          unit: meta.unit,
          quantity,
          unitAmountCents,
          amountCents,
          priceId: priceId || null,
        });
      }

      const totalCents = lines.reduce((a, l) => a + Number(l.amountCents || 0), 0);
      return res.json({
        ok: true,
        periodStartMs: ent.period?.start ?? null,
        periodEndMs: ent.period?.end ?? null,
        totalCents,
        totalUsd: Math.round((totalCents / 100) * 100) / 100,
        lines,
      });
    } catch (e) {
      return res.status(400).json({ error: e instanceof Error ? e.message : "Failed to load usage summary" });
    }
  });

  return r;
}

module.exports = { createBillingRouter };


