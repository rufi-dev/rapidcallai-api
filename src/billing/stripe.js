const Stripe = require("stripe");

let stripe = null;

function getStripe() {
  const key = String(process.env.STRIPE_SECRET_KEY || "").trim();
  if (!key) return null;
  if (!stripe) stripe = new Stripe(key, { apiVersion: "2023-10-16" });
  return stripe;
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

module.exports = {
  getStripe,
  ensureStripeCustomerForWorkspace,
  createUpgradeCheckoutSession,
  createSubscriptionForWorkspace,
  updatePhoneNumbersQuantity,
  getUpcomingInvoice,
};


