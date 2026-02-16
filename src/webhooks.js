/**
 * Agent-level webhooks: POST call events to the agent's webhook_url.
 * Payload shape follows Retell-style docs (see API_REFERENCE.md).
 * Timeout 10s, retry up to 3 times on non-2xx.
 */

const https = require("https");
const http = require("http");
const { logger } = require("./logger");

const WEBHOOK_TIMEOUT_MS = 10_000;
const WEBHOOK_RETRIES = 3;

/**
 * Map our call outcome to disconnection_reason (Retell-style).
 * @see https://docs.retellai.com/features/webhook-overview
 */
function toDisconnectionReason(outcome, direction) {
  const o = String(outcome || "").toLowerCase();
  if (o === "user_hangup" || o === "agent_hangup") return o;
  if (o === "dial_failed" || o === "dial_no_answer" || o === "dial_busy" || o === "dial_timeout") return o;
  if (o === "stale_timeout" || o === "timeout") return "timeout";
  if (o === "completed" || o === "ended" || o === "in_progress") return "user_hangup"; // default
  return o || "user_hangup";
}

/**
 * Build call object for webhook payload (shared fields).
 */
function buildCallPayload(call, agent, options = {}) {
  const direction = call.to === "webtest" ? "inbound" : (call.metrics?.normalized?.source === "outbound" ? "outbound" : "inbound");
  const callType = call.to === "webtest" ? "webtest" : "phone_call";
  const fromNumber =
    direction === "inbound"
      ? (call.metrics?.telephony?.from || "")
      : (call.metrics?.outbound?.from_number || "");
  const toNumber = call.to || "";
  const rapidcallVars =
    call.rapidcall_llm_dynamic_variables ||
    call.metrics?.outbound?.rapidcall_llm_dynamic_variables ||
    {};

  const base = {
    call_type: callType,
    from_number: fromNumber || (callType === "webtest" ? "webtest" : ""),
    to_number: toNumber,
    direction,
    call_id: call.id,
    agent_id: call.agentId || "",
    agent_name: call.agentName || "",
    call_status: options.status || (call.endedAt ? "ended" : "registered"),
    metadata: call.metadata || {},
    rapidcall_llm_dynamic_variables: rapidcallVars,
    start_timestamp: call.startedAt,
  };

  if (call.endedAt != null) {
    base.end_timestamp = call.endedAt;
    base.duration_ms = Math.max(0, Math.round((call.endedAt - call.startedAt)));
    base.disconnection_reason = toDisconnectionReason(call.outcome, direction);
  }

  const transcript = Array.isArray(call.transcript) ? call.transcript : [];
  const transcriptText = transcript
    .map((t) => `${t.role === "agent" ? "Agent" : "User"}: ${String(t.text || "").trim()}`)
    .filter(Boolean)
    .join("\n");
  base.transcript = transcriptText;
  base.transcript_object = transcript.map((t) => ({
    role: t.role,
    content: t.text || "",
    words: [],
  }));
  base.transcript_with_tool_calls = base.transcript_object;

  if (options.includeRecordingUrl && call.recording?.url) {
    base.recording_url = call.recording.url;
  }

  return base;
}

/**
 * call_started payload (no end_timestamp, no transcript).
 */
function buildCallStartedPayload(call, agent) {
  const payload = buildCallPayload(call, agent, { status: "registered" });
  delete payload.end_timestamp;
  delete payload.duration_ms;
  delete payload.disconnection_reason;
  delete payload.transcript;
  delete payload.transcript_object;
  delete payload.transcript_with_tool_calls;
  return payload;
}

/**
 * call_ended payload (full call except call_analysis).
 */
function buildCallEndedPayload(call, agent) {
  return buildCallPayload(call, agent, { status: "ended" });
}

/**
 * call_analyzed payload (full call + call_analysis).
 */
function buildCallAnalyzedPayload(call, agent) {
  const payload = buildCallPayload(call, agent, { status: "ended", includeRecordingUrl: true });
  payload.agent_version = 1;
  const preset = call.metrics?.preset_analysis && typeof call.metrics.preset_analysis === "object" ? call.metrics.preset_analysis : null;
  payload.call_analysis = {
    call_summary: preset?.call_summary ?? "",
    in_voicemail: Boolean(preset?.in_voicemail),
    user_sentiment: preset?.user_sentiment ?? null,
    call_successful: preset?.call_successful ?? ((call.outcome || "").toLowerCase() === "completed" || (call.outcome || "").toLowerCase() === "ended"),
    custom_analysis_data: {},
  };
  if (Array.isArray(call.postCallExtractionResults) && call.postCallExtractionResults.length > 0) {
    for (const r of call.postCallExtractionResults) {
      payload.call_analysis.custom_analysis_data[r.name] = r.value;
      if (r.name === "call_summary" && (r.value !== undefined && r.value !== null && String(r.value).trim())) {
        payload.call_analysis.call_summary = String(r.value).trim().slice(0, 2000);
      }
    }
  }
  if (call.analysisStatus) {
    payload.call_analysis.call_successful = call.analysisStatus === "completed";
  }
  return payload;
}

function postJson(url, body) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === "https:";
    const bodyStr = JSON.stringify(body);
    const req = (isHttps ? https : http).request(
      {
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(bodyStr),
        },
        timeout: WEBHOOK_TIMEOUT_MS,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
          } else {
            reject(new Error(`Webhook ${res.statusCode}: ${data.slice(0, 200)}`));
          }
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Webhook timeout"));
    });
    req.write(bodyStr);
    req.end();
  });
}

/**
 * Send webhook event. Retries up to WEBHOOK_RETRIES on failure. Non-blocking (fire-and-forget).
 * @param {string} webhookUrl - Agent's webhook URL
 * @param {string} event - "call_started" | "call_ended" | "call_analyzed"
 * @param {object} callPayload - The call object for the payload
 */
async function sendWebhook(webhookUrl, event, callPayload) {
  if (!webhookUrl || typeof webhookUrl !== "string" || !webhookUrl.trim()) return;
  const url = webhookUrl.trim();
  const body = { event, call: callPayload };
  let lastErr;
  for (let attempt = 1; attempt <= WEBHOOK_RETRIES; attempt++) {
    try {
      await postJson(url, body);
      logger.info({ event, callId: callPayload?.call_id }, "Webhook delivered");
      return;
    } catch (e) {
      lastErr = e;
      logger.warn({ event, callId: callPayload?.call_id, attempt, err: String(e?.message || e) }, "Webhook delivery failed");
      if (attempt < WEBHOOK_RETRIES) {
        await new Promise((r) => setTimeout(r, 1000 * attempt));
      }
    }
  }
  logger.warn({ event, callId: callPayload?.call_id, err: String(lastErr?.message || lastErr) }, "Webhook delivery failed after retries");
}

/**
 * Send agent-level webhook: build payload from (agent, event, call) and POST.
 * @param {object} agent - Agent with webhookUrl
 * @param {string} event - "call_started" | "call_ended" | "call_analyzed"
 * @param {object} call - Call record
 */
function sendAgentWebhook(agent, event, call) {
  if (!agent || !agent.webhookUrl || typeof agent.webhookUrl !== "string" || !agent.webhookUrl.trim()) return;
  let payload;
  switch (event) {
    case "call_started":
      payload = buildCallStartedPayload(call, agent);
      break;
    case "call_ended":
      payload = buildCallEndedPayload(call, agent);
      break;
    case "call_analyzed":
      payload = buildCallAnalyzedPayload(call, agent);
      break;
    default:
      return;
  }
  sendWebhook(agent.webhookUrl.trim(), event, payload).catch(() => {});
}

module.exports = {
  sendWebhook,
  sendAgentWebhook,
  buildCallStartedPayload,
  buildCallEndedPayload,
  buildCallAnalyzedPayload,
};
