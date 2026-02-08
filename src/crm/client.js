// HTTP client for CRM service
// Used by main API to call CRM service instead of direct DB access

const API_BASE = process.env.CRM_SERVICE_URL || "http://localhost:8788";

async function crmRequest(path, options = {}) {
  const token = options.token;
  if (!token) {
    throw new Error("CRM request requires auth token");
  }

  const url = `${API_BASE}${path}`;
  const headers = {
    "authorization": `Bearer ${token}`,
    "content-type": "application/json",
    ...options.headers,
  };

  const res = await fetch(url, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!res.ok) {
    const error = await res.text().catch(() => `${res.status} ${res.statusText}`);
    throw new Error(`CRM request failed: ${error}`);
  }

  return res.json();
}

module.exports = {
  upsertContactFromCall: async (token, workspaceId, phoneE164, name, source) => {
    const result = await crmRequest("/api/crm/contacts/upsert-from-call", {
      method: "POST",
      body: { workspaceId, phoneE164, name, source },
      token,
    });
    return result.contact;
  },
};
