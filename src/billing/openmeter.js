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

  const { status, text } = await requestJson(endpoint, {
    method: "POST",
    headers: auth,
    body,
  });

  if (status >= 200 && status < 300) return { ok: true };
  return { ok: false, status, text };
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

module.exports = {
  emitOpenMeterEvent,
  ensureOpenMeterCustomerForWorkspace,
  linkStripeCustomerToOpenMeterCustomer,
  grantOpenMeterEntitlement,
};


