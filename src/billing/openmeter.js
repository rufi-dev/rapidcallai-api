const https = require("https");
const { URL } = require("url");

function requestJson(urlStr, { method, headers, body, timeoutMs = 8000 }) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const hasBody = body !== undefined;
    const payload = hasBody ? Buffer.from(JSON.stringify(body)) : null;
    const req = https.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === "https:" ? 443 : 80),
        path: `${u.pathname}${u.search}`,
        method: String(method || "GET").toUpperCase(),
        headers: {
          "content-type": "application/json",
          ...(payload ? { "content-length": String(payload.length) } : {}),
          ...(headers || {}),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({ status: res.statusCode || 0, text, headers: res.headers || {} });
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error("timeout"));
    });
    if (payload) req.write(payload);
    req.end();
  });
}

function normalizeBaseUrl(apiUrl) {
  return String(apiUrl || "").trim().replace(/\/+$/, "");
}

function normalizeAuth(apiKey) {
  const key = String(apiKey || "").trim();
  return key ? { authorization: `Bearer ${key}` } : null;
}

function normalizeSource(source) {
  // CloudEvents 'source' should be a URI-reference; if user provides a short string, coerce to urn:*
  const s = String(source || "").trim() || "urn:voice-platform";
  return s.includes(":") ? s : `urn:${s}`;
}

function safeJsonParse(text) {
  try {
    return JSON.parse(String(text || ""));
  } catch {
    return null;
  }
}

function normalizeEntitlementsPayload(payload) {
  // Support multiple shapes depending on OpenMeter deployment/version
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.entitlements)) return payload.entitlements;
  return [];
}

function parseTimeToMs(v) {
  if (v == null) return null;
  if (typeof v === "number") {
    // heuristics: seconds vs ms
    if (v > 10_000_000_000) return v; // ms
    return v * 1000; // seconds
  }
  const s = String(v).trim();
  if (!s) return null;
  const asNum = Number(s);
  if (!Number.isNaN(asNum)) return parseTimeToMs(asNum);
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? null : ms;
}

function extractCurrentPeriodMs(entitlements) {
  for (const e of entitlements || []) {
    const cp = e?.currentPeriod || e?.period || e?.current_period || null;
    if (cp) {
      const start = parseTimeToMs(cp.start ?? cp.from ?? cp.begin ?? cp.startsAt ?? cp.starts_at);
      const end = parseTimeToMs(cp.end ?? cp.to ?? cp.finish ?? cp.endsAt ?? cp.ends_at);
      if (start || end) return { start, end };
    }
    // fallbacks
    const start = parseTimeToMs(e?.currentPeriodStart ?? e?.current_period_start);
    const end = parseTimeToMs(e?.currentPeriodEnd ?? e?.current_period_end);
    if (start || end) return { start, end };
  }
  return { start: null, end: null };
}

async function emitOpenMeterEvent({ apiUrl, apiKey, source, event }) {
  const base = String(apiUrl || "").trim().replace(/\/+$/, "");
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };

  // OpenMeter accepts CloudEvents JSON. Endpoint can vary by deployment; we standardize on /api/v1/events by default.
  const endpoint = `${base}/api/v1/events`;
  const normalizedSource = normalizeSource(source);

  const body = {
    specversion: "1.0",
    id: event.id,
    type: event.type,
    source: normalizedSource,
    subject: event.subject,
    time: event.time,
    datacontenttype: "application/json",
    data: event.data,
  };

  const maxRetries = 3;
  for (let attempt = 0; attempt < maxRetries; attempt += 1) {
    try {
      const { status, text } = await requestJson(endpoint, {
        method: "POST",
        headers: auth,
        body,
      });
      if (status >= 200 && status < 300) return { ok: true };
      if (status < 500) return { ok: false, status, text };
    } catch (e) {
      if (attempt >= maxRetries - 1) {
        return { ok: false, status: 0, text: String(e?.message || e) };
      }
    }
    await new Promise((r) => setTimeout(r, 500 * (2 ** attempt)));
  }
  return { ok: false, status: 0, text: "OpenMeter request failed after retries" };
}

async function getOpenMeterCustomer({ apiUrl, apiKey, customerIdOrKey }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };

  const endpoint = `${base}/api/v1/customers/${encodeURIComponent(String(customerIdOrKey || ""))}`;
  const { status, text } = await requestJson(endpoint, { method: "GET", headers: auth });
  if (status >= 200 && status < 300) return { ok: true, customer: safeJsonParse(text) };
  if (status === 404) return { ok: false, notFound: true };
  return { ok: false, status, text };
}

async function ensureOpenMeterCustomerForWorkspace({ apiUrl, apiKey, workspace, stripeCustomerId, userEmail }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };
  if (!workspace?.id) return { ok: false, reason: "workspace.id missing" };

  // Recommended: use workspace ID as OpenMeter customer key, and also as the usage subject key.
  const key = String(workspace.id);

  const existing = await getOpenMeterCustomer({ apiUrl, apiKey, customerIdOrKey: key });
  if (existing?.ok && existing.customer) return { ok: true, created: false, customer: existing.customer };

  const endpoint = `${base}/api/v1/customers`;
  const body = {
    key,
    name: String(workspace.name || workspace.id),
    metadata: {
      workspace_id: String(workspace.id),
      ...(stripeCustomerId ? { stripe_customer_id: String(stripeCustomerId) } : {}),
    },
    usageAttribution: { subjectKeys: [key] },
    ...(userEmail ? { primaryEmail: String(userEmail) } : {}),
    currency: "USD",
  };

  const { status, text } = await requestJson(endpoint, { method: "POST", headers: auth, body });
  if (status >= 200 && status < 300) return { ok: true, created: true, customer: safeJsonParse(text) };

  // If customer already exists (race), fall back to GET.
  if (status === 409) {
    const again = await getOpenMeterCustomer({ apiUrl, apiKey, customerIdOrKey: key });
    if (again?.ok) return { ok: true, created: false, customer: again.customer };
  }

  return { ok: false, status, text };
}

async function linkStripeCustomerToOpenMeterCustomer({ apiUrl, apiKey, customerIdOrKey, stripeCustomerId, stripeDefaultPaymentMethodId }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };
  if (!customerIdOrKey) return { ok: false, reason: "customerIdOrKey missing" };
  if (!stripeCustomerId) return { ok: false, reason: "stripeCustomerId missing" };

  const endpoint = `${base}/api/v1/customers/${encodeURIComponent(String(customerIdOrKey))}/stripe`;
  const body = {
    stripeCustomerId: String(stripeCustomerId),
    ...(stripeDefaultPaymentMethodId ? { stripeDefaultPaymentMethodId: String(stripeDefaultPaymentMethodId) } : {}),
  };
  const { status, text } = await requestJson(endpoint, { method: "PUT", headers: auth, body });
  if (status >= 200 && status < 300) return { ok: true, data: safeJsonParse(text) };
  return { ok: false, status, text };
}

async function grantOpenMeterEntitlement({ apiUrl, apiKey, customerIdOrKey, entitlementIdOrFeatureKey, amount, metadata }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };
  if (!customerIdOrKey) return { ok: false, reason: "customerIdOrKey missing" };
  if (!entitlementIdOrFeatureKey) return { ok: false, reason: "entitlementIdOrFeatureKey missing" };

  const endpoint =
    `${base}/api/v2/customers/${encodeURIComponent(String(customerIdOrKey))}` +
    `/entitlements/${encodeURIComponent(String(entitlementIdOrFeatureKey))}/grants`;
  const body = {
    amount: Math.max(0, Math.round(Number(amount || 0))),
    priority: 1,
    effectiveAt: new Date().toISOString(),
    ...(metadata ? { metadata } : {}),
  };
  const { status, text } = await requestJson(endpoint, { method: "POST", headers: auth, body });
  if (status >= 200 && status < 300) return { ok: true, grant: safeJsonParse(text) };
  return { ok: false, status, text };
}

async function listOpenMeterCustomerEntitlements({ apiUrl, apiKey, customerIdOrKey }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };
  if (!customerIdOrKey) return { ok: false, reason: "customerIdOrKey missing" };

  // OpenMeter has had a few API shapes across versions; try a couple of likely endpoints.
  const attempts = [
    `${base}/api/v2/customers/${encodeURIComponent(String(customerIdOrKey))}/entitlements`,
    `${base}/api/v1/billing/customers/${encodeURIComponent(String(customerIdOrKey))}/entitlements`,
    `${base}/api/v1/customers/${encodeURIComponent(String(customerIdOrKey))}/entitlements`,
  ];

  let last = null;
  for (const endpoint of attempts) {
    const { status, text } = await requestJson(endpoint, { method: "GET", headers: auth });
    if (status >= 200 && status < 300) {
      const payload = safeJsonParse(text);
      const entitlements = normalizeEntitlementsPayload(payload);
      const period = extractCurrentPeriodMs(entitlements);
      return { ok: true, entitlements, period, endpoint };
    }
    last = { status, text, endpoint };
  }

  return { ok: false, status: last?.status || 0, text: last?.text || "Failed to load entitlements", endpoint: last?.endpoint };
}

function normalizeInvoiceLines(payload) {
  if (!payload) return [];
  const candidates = [
    payload?.lines,
    payload?.lineItems,
    payload?.items,
    payload?.invoice?.lines,
    payload?.invoice?.lines,
    payload?.invoice?.lineItems,
    payload?.invoice?.items,
    payload?.data?.lines,
    payload?.data?.lineItems,
    payload?.data?.items,
  ];
  for (const c of candidates) {
    if (Array.isArray(c)) return c;
    if (Array.isArray(c?.data)) return c.data;
    if (Array.isArray(c?.items)) return c.items;
  }
  return [];
}

function normalizeMoneyToCents(v) {
  if (v == null) return null;
  if (typeof v === "number") {
    // Heuristic: if it's already integer cents, keep it; if it's a small float, assume dollars.
    if (Number.isInteger(v)) return v;
    return Math.round(v * 100);
  }
  const s = String(v).trim();
  if (!s) return null;
  // OpenMeter often returns decimal strings (e.g., "0.30").
  const n = Number(s);
  if (!Number.isFinite(n)) return null;
  if (Number.isInteger(n)) return n;
  return Math.round(n * 100);
}

function extractInvoiceTotalCents(payload) {
  const candidates = [
    payload?.totalCents,
    payload?.total_cents,
    payload?.total?.cents,
    payload?.total?.amountCents,
    payload?.total?.amount_cents,
    payload?.total?.amount,
    payload?.totalAmountCents,
    payload?.total_amount_cents,
    payload?.totalAmount,
    payload?.total_amount,
    payload?.invoice?.totalCents,
    payload?.invoice?.total_cents,
    payload?.invoice?.total?.amount,
    payload?.invoice?.total?.amountCents,
    payload?.invoice?.totalAmount,
    payload?.totals?.total,
    payload?.totals?.amount,
    payload?.totals?.chargesTotal,
    payload?.totals?.charges_total,
  ];
  for (const v of candidates) {
    const cents = normalizeMoneyToCents(v);
    if (cents != null) return cents;
  }
  return null;
}

async function getOpenMeterCustomerUpcomingInvoice({ apiUrl, apiKey, customerIdOrKey }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };
  if (!customerIdOrKey) return { ok: false, reason: "customerIdOrKey missing" };

  // Try a few endpoints (OpenMeter has multiple variants across versions/deployments).
  const cidRaw = String(customerIdOrKey);
  const cid = encodeURIComponent(cidRaw);

  // IMPORTANT: On OpenMeter Cloud, the "Invoicing" tab is driven by listing invoices,
  // not a dedicated "upcoming invoice" endpoint.
  const listInvoicesQs = new URLSearchParams({
    customers: cidRaw,
    expand: "lines",
    // "gathering" is the current in-progress invoice (what the UI shows as Upcoming Charges)
    statuses: "gathering",
    page: "1",
    pageSize: "1",
    order: "DESC",
    orderBy: "createdAt",
  }).toString();

  const attempts = [
    // Open-source & Cloud: list invoices (preferred)
    `${base}/api/v1/billing/invoices?${listInvoicesQs}`,

    // Older/other variants (kept as fallback)
    `${base}/api/v1/billing/customers/${cid}/invoices/upcoming`,
    `${base}/api/v1/billing/customers/${cid}/invoices/preview`,
    `${base}/api/v1/billing/customers/${cid}/upcoming-invoice`,
    `${base}/api/v1/billing/customers/${cid}/upcoming`,
  ];

  const attemptResults = [];
  let last = null;
  for (const endpoint of attempts) {
    const { status, text } = await requestJson(endpoint, { method: "GET", headers: auth });
    if (status >= 200 && status < 300) {
      const payload = safeJsonParse(text) || {};

      // If this is a list response, pick the first invoice item.
      const invoice =
        (Array.isArray(payload?.items) && payload.items[0]) ||
        (Array.isArray(payload?.data?.items) && payload.data.items[0]) ||
        payload?.invoice ||
        payload;

      const lines = normalizeInvoiceLines(invoice);
      const totalCents = extractInvoiceTotalCents(invoice) ?? extractInvoiceTotalCents(payload);
      return { ok: true, invoice, lines, totalCents, endpoint, attemptResults };
    }
    attemptResults.push({ endpoint, status, text: String(text || "").slice(0, 400) });
    last = { status, text, endpoint };
  }

  return {
    ok: false,
    status: last?.status || 0,
    text: last?.text || "Failed to load upcoming invoice",
    endpoint: last?.endpoint,
    attemptResults,
  };
}

function isUlid(str) {
  const s = String(str || "").trim();
  // Matches OpenMeter error regex: ^[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}$
  return /^[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}$/.test(s);
}

function parseDecimalToCents(v) {
  const cents = normalizeMoneyToCents(v);
  return cents == null ? 0 : cents;
}

function parseInvoiceSummary(inv) {
  if (!inv) return null;
  const id = String(inv.id || "").trim() || null;
  const number = inv.number ?? inv.invoiceNumber ?? null;
  const status = inv.status ?? null;
  const currency = String(inv.currency || "USD").toUpperCase();
  const createdAtMs = parseTimeToMs(inv.createdAt) ?? null;
  const issuedAtMs = parseTimeToMs(inv.issuedAt) ?? null;
  const periodFromMs = parseTimeToMs(inv.period?.from ?? inv.period?.start) ?? null;
  const periodToMs = parseTimeToMs(inv.period?.to ?? inv.period?.end) ?? null;
  const totalCents = extractInvoiceTotalCents(inv);
  const url = inv.url ?? inv.pdfUrl ?? inv.hostedInvoiceUrl ?? null;
  const externalIds = inv.externalIds ?? inv.external_ids ?? null;
  const validationIssues = inv.validationIssues ?? inv.validation_issues ?? null;
  const statusDetails = inv.statusDetails ?? inv.status_details ?? null;
  const workflow = inv.workflow ?? null;
  return {
    id,
    number,
    status,
    currency,
    createdAtMs,
    issuedAtMs,
    periodFromMs,
    periodToMs,
    totalCents: totalCents == null ? null : Number(totalCents),
    totalUsd: totalCents == null ? null : Math.round((Number(totalCents) / 100) * 100) / 100,
    url: url ? String(url) : null,
    // Debugging + Stripe sync visibility:
    externalIds,
    statusDetails,
    validationIssues,
    workflow,
  };
}

function parseInvoiceLines(inv) {
  const lines = normalizeInvoiceLines(inv) || [];
  return lines.map((l) => {
    const name = String(l?.name ?? l?.description ?? l?.title ?? "Line item");
    const quantityRaw = l?.quantity ?? l?.meteredQuantity ?? l?.metered_quantity ?? l?.units ?? null;
    const quantity = quantityRaw == null ? null : Number(quantityRaw);
    const amountCents = extractInvoiceTotalCents(l) ?? normalizeMoneyToCents(l?.amount) ?? normalizeMoneyToCents(l?.total) ?? null;
    const details =
      l?.rateCard?.featureKey
        ? { featureKey: String(l.rateCard.featureKey) }
        : l?.subscription?.item?.id
          ? { subscriptionItemId: String(l.subscription.item.id) }
          : null;
    return {
      id: String(l?.id || "").trim() || null,
      name,
      quantity: Number.isFinite(quantity) ? quantity : null,
      amountCents: amountCents == null ? null : parseDecimalToCents(amountCents),
      amountUsd: amountCents == null ? null : Math.round((parseDecimalToCents(amountCents) / 100) * 100) / 100,
      details,
      externalIds: l?.externalIds ?? l?.external_ids ?? null,
    };
  });
}

async function listOpenMeterInvoices({ apiUrl, apiKey, customerId, statuses = ["gathering", "issued"], pageSize = 50 }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };
  if (!customerId) return { ok: false, reason: "customerId missing" };

  // IMPORTANT: OpenMeter expects `statuses` as a repeated query parameter (array),
  // not a comma-separated string. (Comma-separated causes 400 validation errors.)
  const qs = new URLSearchParams();
  qs.set("customers", String(customerId));
  qs.set("expand", "lines");
  const statusList = Array.isArray(statuses) ? statuses : String(statuses).split(",").map((s) => s.trim()).filter(Boolean);
  for (const st of statusList) qs.append("statuses", st);
  qs.set("page", "1");
  qs.set("pageSize", String(pageSize));
  qs.set("order", "DESC");
  qs.set("orderBy", "createdAt");

  const endpoint = `${base}/api/v1/billing/invoices?${qs.toString()}`;
  const { status, text } = await requestJson(endpoint, { method: "GET", headers: auth });
  if (!(status >= 200 && status < 300)) return { ok: false, status, text, endpoint };

  const payload = safeJsonParse(text) || {};
  const items = Array.isArray(payload?.items) ? payload.items : Array.isArray(payload?.data?.items) ? payload.data.items : [];
  const invoices = items
    .map((inv) => {
      const summary = parseInvoiceSummary(inv);
      if (!summary?.id) return null;
      return { ...summary, lines: parseInvoiceLines(inv) };
    })
    .filter(Boolean);

  return { ok: true, invoices, endpoint };
}

async function getOpenMeterInvoiceById({ apiUrl, apiKey, invoiceId }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };
  if (!invoiceId) return { ok: false, reason: "invoiceId missing" };

  const endpoint = `${base}/api/v1/billing/invoices/${encodeURIComponent(String(invoiceId))}?expand=lines`;
  const { status, text } = await requestJson(endpoint, { method: "GET", headers: auth });
  if (!(status >= 200 && status < 300)) return { ok: false, status, text, endpoint };

  const invoice = safeJsonParse(text) || {};
  const summary = parseInvoiceSummary(invoice);
  if (!summary?.id) return { ok: false, status: 500, text: "Invalid invoice payload", endpoint };
  return { ok: true, invoice: { ...summary, lines: parseInvoiceLines(invoice) }, endpoint };
}

async function invokeOpenMeterInvoiceAction({ apiUrl, apiKey, invoiceId, action }) {
  const base = normalizeBaseUrl(apiUrl);
  if (!base) return { skipped: true, reason: "OPENMETER_API_URL not set" };
  const auth = normalizeAuth(apiKey);
  if (!auth) return { skipped: true, reason: "OPENMETER_API_KEY not set" };
  if (!invoiceId) return { ok: false, reason: "invoiceId missing" };

  const act = String(action || "invoice").trim() || "invoice";
  const id = encodeURIComponent(String(invoiceId));

  // OpenMeter action endpoints vary slightly between versions.
  // Cloud UI shows `statusDetails.availableActions.invoice`, which typically maps to an "actions" endpoint.
  const attempts = [
    // Most likely: POST actions with body specifying action.
    `${base}/api/v1/billing/invoices/${id}/actions`,

    // Other variants we keep for completeness.
    `${base}/api/v1/billing/invoices/${id}/${encodeURIComponent(act)}`,
    `${base}/api/v1/billing/invoices/${id}/actions/${encodeURIComponent(act)}`,
    `${base}/api/v1/billing/invoices/${id}:$${encodeURIComponent(act)}`,
    `${base}/api/v1/billing/invoices/${id}:${encodeURIComponent(act)}`,
    `${base}/api/v1/billing/invoices/${id}/actions:${encodeURIComponent(act)}`,
  ];

  const attemptResults = [];
  let last = null;
  for (const endpoint of attempts) {
    // Some deployments use POST, some PUT; some reject bodies.
    const bodiesToTry = endpoint.endsWith("/actions")
      ? [
          { action: act },
          { type: act },
          { name: act },
          { operation: act },
          { action: { type: act } },
          {},
          undefined,
        ]
      : [{}, undefined];

    for (const method of ["POST", "PUT", "PATCH"]) {
      for (const body of bodiesToTry) {
        const { status, text } = await requestJson(endpoint, { method, headers: auth, body });
        if (status >= 200 && status < 300) {
          const payload = safeJsonParse(text) || {};
          return { ok: true, endpoint, method, payload, attemptResults };
        }
        attemptResults.push({
          endpoint,
          method,
          body: body === undefined ? "(no body)" : JSON.stringify(body),
          status,
          text: String(text || "").slice(0, 400),
        });
        last = { status, text, endpoint, method };

        // If endpoint exists but doesn't allow this method, continue trying other methods/bodies.
        // (405 is very common here.)
      }
    }
  }
  return { ok: false, status: last?.status || 0, text: last?.text || "Failed to invoke invoice action", endpoint: last?.endpoint, attemptResults };
}

module.exports = {
  emitOpenMeterEvent,
  isUlid,
  ensureOpenMeterCustomerForWorkspace,
  getOpenMeterCustomer,
  linkStripeCustomerToOpenMeterCustomer,
  grantOpenMeterEntitlement,
  listOpenMeterCustomerEntitlements,
  getOpenMeterCustomerUpcomingInvoice,
  listOpenMeterInvoices,
  getOpenMeterInvoiceById,
  invokeOpenMeterInvoiceAction,
};


