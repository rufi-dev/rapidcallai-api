const express = require("express");
const { getBillingConfig } = require("./config");
const { getOpenMeterCustomerUpcomingInvoice, listOpenMeterCustomerEntitlements } = require("./openmeter");

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
      const debug = String(req.query?.debug || "").trim() === "1";

      // We create OpenMeter customers with key = workspace.id and usage subject = workspace.id.
      // Some OpenMeter endpoints accept either id or key; to avoid mismatch we try both.
      const attemptIds = Array.from(
        new Set([String(ws.id), String(ws.openmeterCustomerId || "")].filter((x) => x && x.trim().length > 0))
      );

      let ent = null;
      let usedCustomerId = null;
      for (const cid of attemptIds) {
        const r1 = await listOpenMeterCustomerEntitlements({
          apiUrl: process.env.OPENMETER_API_URL,
          apiKey: process.env.OPENMETER_API_KEY,
          customerIdOrKey: cid,
        });
        if (r1?.ok) {
          ent = r1;
          usedCustomerId = cid;
          break;
        }
        // preserve "skipped" early if OpenMeter isn't configured
        if (r1?.skipped) {
          ent = r1;
          usedCustomerId = cid;
          break;
        }
      }

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
          ...(debug ? { debug: { usedCustomerId, attempted: attemptIds } } : {}),
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

      function extractUsageNumber(e) {
        // Support multiple response shapes across OpenMeter versions.
        const candidates = [
          e?.usage,
          e?.currentUsage,
          e?.current_usage,
          e?.currentPeriod?.usage,
          e?.current_period?.usage,
          e?.currentPeriod?.consumed,
          e?.current_period?.consumed,
          e?.measurements?.usage,
          e?.metered?.usage,
        ];
        for (const v of candidates) {
          const n = Number(v);
          if (Number.isFinite(n)) return n;
        }
        // Sometimes usage is nested as { value: number }
        const nested =
          e?.usage?.value ??
          e?.currentUsage?.value ??
          e?.current_usage?.value ??
          e?.currentPeriod?.usage?.value ??
          e?.current_period?.usage?.value;
        const n = Number(nested);
        return Number.isFinite(n) ? n : 0;
      }

      const usageByKey = {};
      const seenKeys = [];
      const sampleByKey = {};
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
        if (key) seenKeys.push(key);
        if (!key || !wanted[key]) continue;
        const usage = extractUsageNumber(e);
        usageByKey[key] = usage;

        // Capture a small sample of the raw entitlement shape for debugging (to fix parsing differences).
        if (debug && !sampleByKey[key]) {
          sampleByKey[key] = {
            featureKey: e?.featureKey ?? null,
            feature: e?.feature ?? null,
            key: e?.key ?? null,
            id: e?.id ?? null,
            usage: e?.usage ?? null,
            currentUsage: e?.currentUsage ?? null,
            current_usage: e?.current_usage ?? null,
            currentPeriod: e?.currentPeriod ?? null,
            current_period: e?.current_period ?? null,
            measurements: e?.measurements ?? null,
            metered: e?.metered ?? null,
            balance: e?.balance ?? null,
            overage: e?.overage ?? null,
            access: e?.access ?? null,
          };
        }
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

      // If entitlements endpoint doesn't include usage fields (common in some OpenMeter versions),
      // fall back to OpenMeter billing upcoming-invoice preview (matches OpenMeter UI "Invoicing" tab).
      const noUsageData = Object.keys(wanted).every((k) => !Number(usageByKey[k] || 0));
      let invoiceFallback = null;
      let invoiceAttemptDebug = null;
      if (noUsageData) {
        // Try both identifiers (key vs id) like above.
        for (const cid of attemptIds) {
          const inv = await getOpenMeterCustomerUpcomingInvoice({
            apiUrl: process.env.OPENMETER_API_URL,
            apiKey: process.env.OPENMETER_API_KEY,
            customerIdOrKey: cid,
          });
          if (inv?.ok) {
            invoiceFallback = { ...inv, usedCustomerId: cid };
            break;
          }
          if (inv?.skipped) {
            invoiceFallback = { ...inv, usedCustomerId: cid };
            break;
          }
          if (debug && inv && !inv.ok) {
            invoiceAttemptDebug = invoiceAttemptDebug || [];
            invoiceAttemptDebug.push({
              customerIdOrKey: cid,
              status: inv.status ?? null,
              endpoint: inv.endpoint ?? null,
              attemptResults: inv.attemptResults ?? null,
            });
          }
        }
      }

      if (invoiceFallback?.ok) {
        const omLines = [];
        for (const raw of invoiceFallback.lines || []) {
          const key = String(raw?.featureKey ?? raw?.key ?? raw?.id ?? raw?.meterKey ?? raw?.meter?.key ?? raw?.meter?.slug ?? "").trim();
          const amountCents =
            (raw?.amountCents != null ? Number(raw.amountCents) : null) ??
            (raw?.amount_cents != null ? Number(raw.amount_cents) : null) ??
            (raw?.amount != null ? Math.round(Number(raw.amount) * 100) : null) ??
            (raw?.total != null ? Math.round(Number(raw.total) * 100) : null) ??
            null;
          // Try to extract quantity if present, but don't depend on it.
          const quantityRaw = raw?.quantity ?? raw?.usage ?? raw?.units ?? raw?.consumed ?? raw?.value ?? null;
          const quantity = quantityRaw == null ? null : Number(quantityRaw);
          const desc = String(
            raw?.name ??
              raw?.description ??
              raw?.title ??
              raw?.featureName ??
              raw?.feature?.name ??
              (key || "Line item")
          );
          omLines.push({
            key: key || null,
            description: desc,
            unit: "—",
            quantity: Number.isFinite(quantity) ? quantity : null,
            unitAmountCents: null,
            amountCents: Number.isFinite(amountCents) ? amountCents : null,
            priceId: null,
            source: "openmeter_invoice",
          });
        }
        const totalCents =
          Number.isFinite(Number(invoiceFallback.totalCents)) && invoiceFallback.totalCents != null
            ? Number(invoiceFallback.totalCents)
            : omLines.reduce((a, l) => a + Number(l.amountCents || 0), 0);

        return res.json({
          ok: true,
          periodStartMs: ent.period?.start ?? null,
          periodEndMs: ent.period?.end ?? null,
          totalCents,
          totalUsd: Math.round((totalCents / 100) * 100) / 100,
          lines: omLines,
          ...(debug
            ? {
                debug: {
                  usedCustomerId: invoiceFallback.usedCustomerId ?? usedCustomerId,
                  attempted: attemptIds,
                  openmeterEntitlementsEndpoint: ent.endpoint ?? null,
                  openmeterInvoiceEndpoint: invoiceFallback.endpoint ?? null,
                  entitlementsCount: (ent.entitlements || []).length,
                  seenKeys: Array.from(new Set(seenKeys)).slice(0, 50),
                  stripeConfigured: Boolean(s),
                  sampleByKey,
                },
              }
            : {}),
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
        ...(debug
          ? {
              debug: {
                usedCustomerId,
                attempted: attemptIds,
                entitlementsCount: (ent.entitlements || []).length,
                seenKeys: Array.from(new Set(seenKeys)).slice(0, 50),
                openmeterEndpoint: ent.endpoint ?? null,
                stripeConfigured: Boolean(s),
                sampleByKey,
                openmeterInvoiceAttemptDebug: invoiceAttemptDebug,
              },
            }
          : {}),
      });
    } catch (e) {
      return res.status(400).json({ error: e instanceof Error ? e.message : "Failed to load usage summary" });
    }
  });

  return r;
}

module.exports = { createBillingRouter };


