const Stripe = require("stripe");
const https = require("https");
const querystring = require("querystring");

let stripe = null;

function getStripe() {
  const key = String(process.env.STRIPE_SECRET_KEY || "").trim();
  if (!key) return null;
  if (!stripe) stripe = new Stripe(key, { apiVersion: "2023-10-16" });
  return stripe;
}

function stripeRequestJson({ method, path, apiKey, body, timeoutMs = 10000 }) {
  return new Promise((resolve, reject) => {
    const key = String(apiKey || "").trim();
    if (!key) return reject(new Error("Stripe not configured (STRIPE_SECRET_KEY missing)"));

    const payload = body ? querystring.stringify(body) : "";
    const req = https.request(
      {
        hostname: "api.stripe.com",
        path,
        method: String(method || "GET").toUpperCase(),
        headers: {
          authorization: `Bearer ${key}`,
          ...(payload
            ? {
                "content-type": "application/x-www-form-urlencoded",
                "content-length": Buffer.byteLength(payload),
              }
            : {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode || 0, text, json });
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    if (payload) req.write(payload);
    req.end();
  });
}

async function retrieveStripePrice(priceId) {
  const s = getStripe();
  if (!s) throw new Error("Stripe not configured (STRIPE_SECRET_KEY missing)");
  return await s.prices.retrieve(String(priceId));
}

async function retrieveStripeMeter(meterId) {
  const key = String(process.env.STRIPE_SECRET_KEY || "").trim();
  const id = String(meterId || "").trim();
  if (!id) throw new Error("meterId missing");
  const res = await stripeRequestJson({ method: "GET", path: `/v1/billing/meters/${encodeURIComponent(id)}`, apiKey: key });
  if (res.status >= 200 && res.status < 300) return { ok: true, meter: res.json || null };
  return { ok: false, status: res.status, error: res.json?.error?.message || res.text };
}

async function createStripeMeterEvent({ customerId, meterId, value, timestampSec }) {
  const key = String(process.env.STRIPE_SECRET_KEY || "").trim();
  const meter = String(meterId || "").trim();
  const customer = String(customerId || "").trim();
  if (!meter) throw new Error("meterId missing");
  if (!customer) throw new Error("customerId missing");

  // Stripe Billing Meter Events API (new metering system).
  // This API expects event_name + payload[...] (NOT meter/customer/value at top-level).
  const meterRes = await retrieveStripeMeter(meter);
  if (!meterRes?.ok) return { ok: false, status: meterRes.status ?? 0, error: meterRes.error || "Failed to retrieve meter" };

  const eventName = String(meterRes?.meter?.event_name || meterRes?.meter?.eventName || "").trim();
  if (!eventName) return { ok: false, status: 400, error: "Stripe meter is missing event_name" };

  const body = {
    event_name: eventName,
    // Stripe expects the customer to be passed in the payload under a specific key.
    // Error seen: "pass the customer ID in the event payload with key \"stripe_customer_id\"."
    "payload[stripe_customer_id]": customer,
    // Keep the generic key as well (harmless if ignored) for forward/backward compatibility.
    "payload[customer]": customer,
    "payload[value]": String(value),
    ...(timestampSec ? { timestamp: String(timestampSec) } : {}),
  };

  const res = await stripeRequestJson({
    method: "POST",
    path: "/v1/billing/meter_events",
    apiKey: key,
    body,
  });

  if (res.status >= 200 && res.status < 300) return { ok: true, data: res.json || null };
  return { ok: false, status: res.status, error: res.json?.error?.message || res.text };
}

function getFirstClientOrigin() {
  const raw = String(process.env.CLIENT_ORIGIN || "").trim();
  if (!raw) return "http://localhost:5173";
  return raw.split(",")[0].trim() || "http://localhost:5173";
}

async function findExistingStripeCustomerForWorkspace({ stripe, workspaceId }) {
  const s = stripe;
  const wsid = String(workspaceId || "").trim();
  if (!s || !wsid) return null;
  try {
    // Fast + precise: uses Stripe Search API.
    // https://docs.stripe.com/search
    const q = `metadata['workspace_id']:'${wsid.replace(/'/g, "\\'")}'`;
    const r = await s.customers.search({ query: q, limit: 1 });
    const c = (r?.data || [])[0] || null;
    return c?.id ? c : null;
  } catch {
    // If search is unavailable, fall back to list+filter (slower, but safe for small accounts).
    try {
      const r = await s.customers.list({ limit: 100 });
      const c = (r?.data || []).find((x) => String(x?.metadata?.workspace_id || "") === wsid) || null;
      return c?.id ? c : null;
    } catch {
      return null;
    }
  }
}

async function ensureStripeCustomerForWorkspace(ws) {
  const s = getStripe();
  if (!s) throw new Error("Stripe not configured (STRIPE_SECRET_KEY missing)");
  const email = String(ws?.userEmail || "").trim();

  // If customer already exists, best-effort ensure email is set (helps user find it in Stripe UI).
  if (ws.stripeCustomerId) {
    if (email) {
      try {
        const existing = await s.customers.retrieve(ws.stripeCustomerId);
        if (existing && !("deleted" in existing && existing.deleted) && !existing.email) {
          await s.customers.update(ws.stripeCustomerId, { email });
        }
      } catch {
        // best-effort only
      }
    }
    return { customerId: ws.stripeCustomerId, created: false };
  }

  // Avoid duplicate customers if provisioning is triggered by multiple concurrent requests.
  const found = await findExistingStripeCustomerForWorkspace({ stripe: s, workspaceId: ws.id });
  if (found?.id) {
    if (email && !found.email) {
      try {
        await s.customers.update(found.id, { email });
      } catch {
        // best-effort
      }
    }
    return { customerId: found.id, created: false };
  }

  const customer = await s.customers.create({
    name: ws.name || ws.id,
    ...(email ? { email } : {}),
    metadata: { workspace_id: ws.id },
  }, { idempotencyKey: `workspace:${String(ws.id)}:stripe_customer` });
  return { customerId: customer.id, created: true };
}

async function createUpgradeCheckoutSession({ customerId, workspaceId }) {
  const s = getStripe();
  if (!s) throw new Error("Stripe not configured (STRIPE_SECRET_KEY missing)");

  const base = getFirstClientOrigin();
  const successUrl = `${base}/app/billing?upgrade=success`;
  const cancelUrl = `${base}/app/billing?upgrade=cancel`;

  const session = await s.checkout.sessions.create({
    mode: "setup",
    customer: customerId,
    success_url: successUrl,
    cancel_url: cancelUrl,
    payment_method_types: ["card"],
    metadata: { workspace_id: workspaceId },
    setup_intent_data: { metadata: { workspace_id: workspaceId } },
  });

  return { id: session.id, url: session.url };
}

function getMeteredPriceIdsFromEnv() {
  return {
    baseMinutes: String(process.env.STRIPE_PRICE_ID_BASE_MINUTES || "").trim(),
    modelUpgradeMinutes: String(process.env.STRIPE_PRICE_ID_MODEL_UPGRADE_MINUTES || "").trim(),
    tokenOverage: String(process.env.STRIPE_PRICE_ID_TOKEN_OVERAGE || "").trim(),
    telephonyMinutes: String(process.env.STRIPE_PRICE_ID_TELEPHONY_MINUTES || "").trim(),
    phoneNumberMonthly: String(process.env.STRIPE_PRICE_ID_PHONE_NUMBER_MONTHLY || "").trim(),
  };
}

function assertStripePriceIds(ids) {
  const missing = Object.entries(ids)
    .filter(([, v]) => !v)
    .map(([k]) => k);
  if (missing.length) throw new Error(`Missing Stripe price ids: ${missing.join(", ")}`);
}

async function createSubscriptionForWorkspace({ workspaceId, customerId, phoneNumbersCount }) {
  const s = getStripe();
  if (!s) throw new Error("Stripe not configured (STRIPE_SECRET_KEY missing)");

  const ids = getMeteredPriceIdsFromEnv();
  assertStripePriceIds(ids);

  let sub = null;
  try {
    sub = await s.subscriptions.create({
      customer: customerId,
      collection_method: "charge_automatically",
      items: [
        { price: ids.baseMinutes },
        { price: ids.modelUpgradeMinutes },
        { price: ids.tokenOverage },
        { price: ids.telephonyMinutes },
        { price: ids.phoneNumberMonthly, quantity: Math.max(0, Number(phoneNumbersCount || 0)) },
      ],
      metadata: { workspace_id: String(workspaceId || "") },
    });
  } catch (e) {
    const msg = String(e?.message || "");
    if (msg.includes("No such price")) {
      const key = String(process.env.STRIPE_SECRET_KEY || "").trim();
      const mode = key.startsWith("sk_live_") ? "LIVE" : key.startsWith("sk_test_") ? "TEST" : "UNKNOWN";
      throw new Error(
        [
          msg,
          "",
          `Hint: your API is using a ${mode} Stripe secret key, but the price ID you configured may belong to a different Stripe mode/account.`,
          `Fix: copy the price IDs from the same Stripe dashboard mode (Test vs Live) as your STRIPE_SECRET_KEY, then restart the API container.`,
        ].join("\n")
      );
    }
    throw e;
  }

  const phoneItem = (sub.items?.data || []).find((it) => it.price?.id === ids.phoneNumberMonthly) || null;

  return { subscriptionId: sub.id, phoneNumbersItemId: phoneItem?.id ?? null };
}

async function updatePhoneNumbersQuantity({ subscriptionId, phoneNumbersItemId, quantity }) {
  const s = getStripe();
  if (!s) throw new Error("Stripe not configured (STRIPE_SECRET_KEY missing)");
  if (!subscriptionId || !phoneNumbersItemId) return;
  await s.subscriptionItems.update(phoneNumbersItemId, { quantity: Math.max(0, Number(quantity || 0)) });
}

async function getUpcomingInvoice({ customerId, subscriptionId }) {
  const s = getStripe();
  if (!s) throw new Error("Stripe not configured (STRIPE_SECRET_KEY missing)");
  const inv = await s.invoices.retrieveUpcoming({
    customer: customerId,
    subscription: subscriptionId || undefined,
  });
  return inv;
}

async function getSubscriptionItemIdByPriceId({ subscriptionId, priceId }) {
  const s = getStripe();
  if (!s) throw new Error("Stripe not configured (STRIPE_SECRET_KEY missing)");
  if (!subscriptionId || !priceId) return null;

  const sub = await s.subscriptions.retrieve(subscriptionId, { expand: ["items.data.price"] });
  const item = (sub.items?.data || []).find((it) => it.price?.id === priceId) || null;
  return item?.id ?? null;
}

async function recordUsageForSubscription({ subscriptionId, usageByPriceId, timestampSec, idempotencyKeyPrefix }) {
  const s = getStripe();
  if (!s) throw new Error("Stripe not configured (STRIPE_SECRET_KEY missing)");
  if (!subscriptionId) throw new Error("subscriptionId missing");

  const results = {};
  const ts = Number.isFinite(Number(timestampSec)) ? Number(timestampSec) : Math.floor(Date.now() / 1000);

  for (const [priceId, qtyRaw] of Object.entries(usageByPriceId || {})) {
    const quantity = Math.max(0, Math.floor(Number(qtyRaw || 0)));
    if (!priceId || quantity <= 0) continue;

    const itemId = await getSubscriptionItemIdByPriceId({ subscriptionId, priceId });
    if (!itemId) {
      results[priceId] = { ok: false, error: "subscription item not found for price" };
      continue;
    }

    try {
      const idempotencyKey = `${String(idempotencyKeyPrefix || "usage")}:${subscriptionId}:${priceId}`;
      const r = await s.subscriptionItems.createUsageRecord(
        itemId,
        { quantity, timestamp: ts, action: "increment" },
        { idempotencyKey }
      );
      results[priceId] = { ok: true, usageRecordId: r?.id ?? null, quantity };
    } catch (e) {
      results[priceId] = { ok: false, error: String(e?.message || e) };
    }
  }

  return results;
}

async function recordMeterEventsForWorkspace({ customerId, usageByPriceId, timestampSec, idempotencyKeyPrefix }) {
  const results = {};
  const ts = Number.isFinite(Number(timestampSec)) ? Number(timestampSec) : Math.floor(Date.now() / 1000);

  for (const [priceId, qtyRaw] of Object.entries(usageByPriceId || {})) {
    const q = Number(qtyRaw || 0);
    const quantity = Number.isFinite(q) ? Math.max(0, q) : 0;
    if (!priceId || quantity <= 0) continue;

    let meterId = null;
    try {
      const price = await retrieveStripePrice(priceId);
      meterId = price?.recurring?.meter ?? null;
      if (!meterId) {
        results[priceId] = { ok: false, error: "Price is not a metered (meter-based) price" };
        continue;
      }
    } catch (e) {
      results[priceId] = { ok: false, error: String(e?.message || e) };
      continue;
    }

    // Idempotency is handled at our call level; meter events are append-only.
    const r = await createStripeMeterEvent({
      customerId,
      meterId,
      value: quantity,
      timestampSec: ts,
    });
    results[priceId] = { ...r, meterId, quantity };
  }

  return results;
}

module.exports = {
  getStripe,
  ensureStripeCustomerForWorkspace,
  createUpgradeCheckoutSession,
  createSubscriptionForWorkspace,
  updatePhoneNumbersQuantity,
  getUpcomingInvoice,
  getMeteredPriceIdsFromEnv,
  recordUsageForSubscription,
  recordMeterEventsForWorkspace,
};


