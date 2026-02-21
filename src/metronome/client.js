"use strict";

const METRONOME_API_BASE = "https://api.metronome.com";

function getToken() {
  const t = process.env.METRONOME_BEARER_TOKEN;
  if (!t || typeof t !== "string" || !t.trim()) return null;
  return t.trim();
}

async function metronomeFetch(path, options = {}) {
  const token = getToken();
  if (!token) {
    throw new Error("METRONOME_BEARER_TOKEN is not set");
  }
  const url = `${METRONOME_API_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!res.ok) {
    const err = new Error(body?.message || `Metronome API ${res.status}: ${text.slice(0, 200)}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

/**
 * Create a Metronome customer with optional Stripe billing config.
 * @param {{ name: string, ingestAliases?: string[], stripeCustomerId?: string }}
 * @returns {Promise<{ id: string }>}
 */
async function createCustomer({ name, ingestAliases = [], stripeCustomerId }) {
  const payload = {
    name: name || "Customer",
    ingest_aliases: Array.isArray(ingestAliases) && ingestAliases.length > 0 ? ingestAliases : [name || "customer"],
  };
  if (stripeCustomerId) {
    payload.customer_billing_provider_configurations = [
      {
        billing_provider: "stripe",
        delivery_method: "direct_to_billing_provider",
        configuration: {
          stripe_customer_id: stripeCustomerId,
          stripe_collection_method: "charge_automatically",
        },
      },
    ];
  }
  const data = await metronomeFetch("/v1/customers", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return { id: data?.data?.id ?? data?.id };
}

/**
 * Create a contract for a customer: rate card + optional billing config.
 * @param {{ customerId: string, rateCardId: string, startingAt: string, name?: string, stripeCustomerId?: string }}
 * @returns {Promise<{ id: string }>}
 */
async function createContract({ customerId, rateCardId, startingAt, name, stripeCustomerId }) {
  const payload = {
    customer_id: customerId,
    rate_card_id: rateCardId,
    starting_at: startingAt,
    ...(name ? { name } : {}),
  };
  if (stripeCustomerId) {
    payload.billing_provider_configuration = {
      billing_provider: "stripe",
      delivery_method: "direct_to_billing_provider",
      configuration: {
        stripe_customer_id: stripeCustomerId,
      },
    };
  }
  const data = await metronomeFetch("/v1/contracts/create", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return { id: data?.data?.id ?? data?.id };
}

/**
 * End a contract at a given time (exclusive).
 * @param {{ customerId: string, contractId: string, endingBefore: string }}
 */
async function updateContractEndDate({ customerId, contractId, endingBefore }) {
  await metronomeFetch("/v1/contracts/updateEndDate", {
    method: "POST",
    body: JSON.stringify({
      customer_id: customerId,
      contract_id: contractId,
      ending_before: endingBefore,
    }),
  });
}

/**
 * Ingest usage events. Events: { transaction_id, customer_id, timestamp (RFC3339), event_type, properties (all string values) }
 * @param {Array<{ transaction_id: string, customer_id: string, timestamp: string, event_type: string, properties?: Record<string, string> }>} events
 */
async function ingestEvents(events) {
  if (!events || events.length === 0) return;
  const batch = events.map((e) => ({
    transaction_id: e.transaction_id,
    customer_id: e.customer_id,
    timestamp: e.timestamp,
    event_type: e.event_type,
    properties: e.properties ? Object.fromEntries(Object.entries(e.properties).map(([k, v]) => [k, String(v)])) : {},
  }));
  await metronomeFetch("/v1/ingest", {
    method: "POST",
    body: JSON.stringify(batch),
  });
}

/**
 * List rate cards (to resolve ID by name if not in env).
 * @returns {Promise<Array<{ id: string, name?: string }>>}
 */
async function listRateCards() {
  const data = await metronomeFetch("/v1/rateCards?limit=100");
  const list = data?.data ?? data ?? [];
  return Array.isArray(list) ? list.map((r) => ({ id: r.id, name: r.name ?? null })) : [];
}

module.exports = {
  getToken,
  createCustomer,
  createContract,
  updateContractEndDate,
  ingestEvents,
  listRateCards,
};
