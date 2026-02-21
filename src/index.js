// Ensure `server/.env` is always used (even if Windows/global env vars exist but are empty).
require("dotenv").config({
  path: require("path").join(__dirname, "..", ".env"),
  override: true,
});

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const https = require("https");
const bcrypt = require("bcryptjs");
const { nanoid } = require("./id");
const { z } = require("zod");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const pdfParse = require("pdf-parse");
const promClient = require("prom-client");
const { WebhookReceiver } = require("livekit-server-sdk");
const twilio = require("twilio");
const { logger, requestLogger } = require("./logger");
const { sendAlert } = require("./alerting");

// Upload helpers (must be defined BEFORE any routes that reference them).
const kbUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
});

const {
  readAgents,
  writeAgents,
  readCalls,
  writeCalls,
  readWorkspaces,
  writeWorkspaces,
  readPhoneNumbers,
  writePhoneNumbers,
} = require("./storage");
const { getPool, initSchema } = require("./db");
const store = require("./store_pg");
const { roomService, agentDispatchService, createParticipantToken, sipClient, addNumberToInboundTrunk, addNumberToOutboundTrunk, removeNumberFromInboundTrunk, removeNumberFromOutboundTrunk, createInboundTrunkForWorkspace, createOutboundTrunkForWorkspace, createOutboundTrunkForSipImport, ensureOutboundTrunkUsesTls, ensureOutboundTrunkTransport, ensureOutboundTrunkAddress, deleteOutboundTrunk, getOutboundTrunkInfo, isTrunkNotFoundError, parseConflictingInboundTrunkId } = require("./livekit");
const outboundWorker = require("./outbound_worker");
const { substituteDynamicVariables } = require("./promptSubstitute");
const { startCallEgress, stopEgress, getEgressInfo } = require("./egress");
const { getObject, headObject } = require("./s3");
const tw = require("./twilio");
const { sendAgentWebhook } = require("./webhooks");
const { createCrmRouter } = require("./crm/routes");

const DEFAULT_LLM_MODEL = String(process.env.DEFAULT_LLM_MODEL || "gpt-4.1-mini").trim() || "gpt-4.1-mini";
const contactStore = require("./crm/store");

// LiveKit webhooks receiver (verified with LIVEKIT_API_KEY/SECRET).
// NOTE: WebhookReceiver needs the *raw* body string, so we use express.raw on that route.
function livekitWebhookReceiver() {
  const apiKey = String(process.env.LIVEKIT_API_KEY || "").trim();
  const apiSecret = String(process.env.LIVEKIT_API_SECRET || "").trim();
  if (!apiKey || !apiSecret) return null;
  return new WebhookReceiver(apiKey, apiSecret);
}

// --- Metrics (Prometheus) ---
// LiveKit Cloud has its own observability; this endpoint is for *your* infra + app-level metrics.
// Enable by setting METRICS_BEARER_TOKEN.
const metricsRegister = new promClient.Registry();
promClient.collectDefaultMetrics({ register: metricsRegister });

const httpRequestDurationMs = new promClient.Histogram({
  name: "rapidcall_http_request_duration_ms",
  help: "HTTP request duration in ms",
  labelNames: ["method", "route", "status"],
  buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
});
metricsRegister.registerMetric(httpRequestDurationMs);

const callsStartedTotal = new promClient.Counter({
  name: "rapidcall_calls_started_total",
  help: "Number of calls started",
  labelNames: ["source"],
});
metricsRegister.registerMetric(callsStartedTotal);

const callsEndedTotal = new promClient.Counter({
  name: "rapidcall_calls_ended_total",
  help: "Number of calls ended",
  labelNames: ["source", "outcome"],
});
metricsRegister.registerMetric(callsEndedTotal);

const callDurationSeconds = new promClient.Histogram({
  name: "rapidcall_call_duration_seconds",
  help: "Call duration in seconds (ended calls)",
  labelNames: ["source", "outcome"],
  buckets: [1, 5, 10, 20, 30, 60, 120, 300, 600, 1200, 3600],
});
metricsRegister.registerMetric(callDurationSeconds);

const callMetricsPostedTotal = new promClient.Counter({
  name: "rapidcall_call_metrics_posted_total",
  help: "Number of times the agent posted /api/calls/:id/metrics",
  labelNames: ["hasUsage"],
});
metricsRegister.registerMetric(callMetricsPostedTotal);

const outboundJobsQueuedTotal = new promClient.Counter({
  name: "rapidcall_outbound_jobs_queued_total",
  help: "Number of outbound jobs queued",
});
metricsRegister.registerMetric(outboundJobsQueuedTotal);

const outboundJobsDialedTotal = new promClient.Counter({
  name: "rapidcall_outbound_jobs_dialed_total",
  help: "Number of outbound jobs dialed",
});
metricsRegister.registerMetric(outboundJobsDialedTotal);

const outboundJobsFailedTotal = new promClient.Counter({
  name: "rapidcall_outbound_jobs_failed_total",
  help: "Number of outbound jobs failed",
  labelNames: ["reason"],
});
metricsRegister.registerMetric(outboundJobsFailedTotal);

const outboundCallsAnsweredTotal = new promClient.Counter({
  name: "rapidcall_outbound_calls_answered_total",
  help: "Number of outbound calls answered",
});
metricsRegister.registerMetric(outboundCallsAnsweredTotal);

const outboundTimeToAnswerSeconds = new promClient.Histogram({
  name: "rapidcall_outbound_time_to_answer_seconds",
  help: "Time from dial to answered (seconds)",
  buckets: [1, 3, 5, 10, 15, 20, 30, 45, 60],
});
metricsRegister.registerMetric(outboundTimeToAnswerSeconds);

// Best-effort in-process gauge (accurate per instance only).
let inProgressCallsGaugeValue = 0;
const inProgressCallsGauge = new promClient.Gauge({
  name: "rapidcall_calls_in_progress",
  help: "In-progress calls (per API instance; best-effort)",
  collect() {
    this.set(inProgressCallsGaugeValue);
  },
});
metricsRegister.registerMetric(inProgressCallsGauge);

function numEnv(name) {
  const v = process.env[name];
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function parseJsonEnv(name) {
  const raw = String(process.env[name] || "").trim();
  if (!raw) return null;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" ? v : null;
  } catch {
    return null;
  }
}

function round4(n) {
  return Math.round(Number(n || 0) * 10000) / 10000;
}

function normalizeDurationSec({ durationSecStored, startedAtMs, endedAtMs }) {
  const started = Number(startedAtMs || 0);
  const ended = Number(endedAtMs || 0);
  const derived = started > 0 && ended > 0 && ended >= started ? Math.max(0, Math.round((ended - started) / 1000)) : 0;

  const storedRaw = Number(durationSecStored);
  const storedOk = Number.isFinite(storedRaw) && storedRaw >= 0;
  const stored = storedOk ? Math.round(storedRaw) : null;

  // Guard rails: if stored is wildly different from derived, trust derived.
  // Common bug: milliseconds saved into duration_sec (e.g. 20000 instead of 20).
  // Common bug: seconds saved as milliseconds (rare) -> stored << derived.
  const MAX_REASONABLE_SEC = 6 * 60 * 60; // 6h
  let use = stored != null ? stored : derived;
  let source = stored != null ? "stored" : "derived";
  const flags = [];

  if (stored != null) {
    if (stored > MAX_REASONABLE_SEC && derived > 0 && derived <= MAX_REASONABLE_SEC) {
      flags.push("stored_too_large_using_derived");
      use = derived;
      source = "derived";
    } else if (derived > 0) {
      const ratio = stored / Math.max(1, derived);
      if (ratio >= 10 || ratio <= 0.1) {
        flags.push("stored_mismatch_using_derived");
        use = derived;
        source = "derived";
      }
    } else if (stored > MAX_REASONABLE_SEC) {
      flags.push("stored_too_large_no_derived");
      // keep stored, but mark
    }
  }

  if (!Number.isFinite(use) || use < 0) {
    use = 0;
    source = "derived";
    flags.push("invalid_duration_clamped");
  }

  // If duration is still implausibly large, mark invalid for billing.
  // We do NOT silently clamp because cost/min math would still be distorted with a forced minimum billable time.
  const validForBilling = use <= MAX_REASONABLE_SEC;
  if (!validForBilling) flags.push("invalid_duration_too_large");

  return {
    durationSec: use,
    derivedSec: derived,
    storedSec: stored,
    source,
    flags,
    validForBilling,
  };
}

async function computeOverheadUsdPerMinForWorkspace(workspaceId) {
  // Billing/COGS reset: overhead allocation is removed from customer-visible billing.
  // Internal profitability accounting may be reintroduced later as admin-only.
  void workspaceId;
  return null;
}

const app = express();
// When running behind a reverse proxy (Render/Fly/Nginx), this ensures req.protocol reflects X-Forwarded-Proto.
app.set("trust proxy", 1);

// Attach a request id for tracing across logs.
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader("X-Request-Id", req.requestId);
  return next();
});

// Request logging (structured JSON when pino is installed)
app.use(requestLogger());

// Simple in-memory rate limiter (per instance).
const rateLimitBuckets = new Map();
function rateLimit({ windowMs, max, keyPrefix }) {
  return (req, res, next) => {
    const ip = String(req.headers["x-forwarded-for"] || req.ip || "unknown").split(",")[0].trim();
    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();
    const bucket = rateLimitBuckets.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + windowMs;
    }
    bucket.count += 1;
    rateLimitBuckets.set(key, bucket);
    if (bucket.count > max) {
      const retryAfterSec = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      res.setHeader("Retry-After", String(retryAfterSec));
      return res.status(429).json({ error: "Too many requests. Please try again later." });
    }
    return next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateLimitBuckets.entries()) {
    if (!bucket || now > bucket.resetAt) rateLimitBuckets.delete(key);
  }
}, 10 * 60 * 1000);

// --- LiveKit Webhooks (for billed participant-minutes) ---
// Must be registered BEFORE express.json middleware so we can access raw body bytes.
app.post("/api/livekit/webhook", express.raw({ type: "application/webhook+json" }), async (req, res) => {
  const receiver = livekitWebhookReceiver();
  if (!receiver) return res.status(503).send("LiveKit not configured");

  try {
    const bodyStr = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : String(req.body || "");
    const auth = req.get("Authorization") || req.get("Authorize") || "";
    if (!auth) {
      // eslint-disable-next-line no-console
      logger.warn({ requestId: req.requestId }, "[livekit.webhook] missing Authorization header");
      return res.status(401).send("Missing Authorization header");
    }
    const ev = await receiver.receive(bodyStr, auth);

    const roomName = String(ev?.room?.name || "").trim();
    if (!roomName) return res.status(200).json({ ok: true });

    // Map LiveKit room -> call record by room_name.
    let call = await findCallByRoomName(roomName);
    // Inbound phone: room is created by LiveKit when Twilio dials SIP; we have no call yet. When SIP participant
    // joins, set room metadata (enabledTools, toolConfigs) so the agent sees the same config as webtest.
    const eventName = String(ev?.event || "").trim();
    const identity = String(ev?.participant?.identity || "").trim();
    if (!call && eventName === "participant_joined" && identity.startsWith("sip-")) {
      const attrs = ev.participant?.attributes && typeof ev.participant.attributes === "object" ? ev.participant.attributes : {};
      const to = (attrs["sip.trunkPhoneNumber"] || attrs["sip_trunkPhoneNumber"] || "").trim();
      const fromNum = (attrs["sip.phoneNumber"] || attrs["sip_phoneNumber"] || "").trim();
      if (to) {
        try {
          const result = await doInboundStart({ roomName, to, from: fromNum, twilioCallSid: "" });
          if (result.status === 201) {
            call = await findCallByRoomName(roomName);
            logger.info({ roomName, to, from: fromNum || "(empty)", callId: call?.id }, "[livekit.webhook] inbound: doInboundStart set room metadata (tools/toolConfigs)");
          }
        } catch (e) {
          logger.warn({ err: String(e?.message || e), roomName, to }, "[livekit.webhook] inbound doInboundStart failed");
        }
      }
    }
    if (!call) return res.status(200).json({ ok: true });

    const nowMs = Date.now();
    const tsMs = Number(ev?.createdAt) > 0 ? Number(ev.createdAt) : nowMs;

    const prev = (call.metrics && typeof call.metrics === "object" ? call.metrics : {}) || {};
    const lk = prev.livekit && typeof prev.livekit === "object" ? prev.livekit : {};
    const participants = lk.participants && typeof lk.participants === "object" ? lk.participants : {};

    function roundUpToMinuteSeconds(sec) {
      const s = Number(sec || 0);
      if (!Number.isFinite(s) || s <= 0) return 0;
      return Math.max(60, Math.ceil(s / 60) * 60);
    }

    // Totals we maintain in metrics (seconds, not minutes)
    let billedSecondsTotal = Number(lk.participantBilledSecondsTotal || 0);
    let rawSecondsTotal = Number(lk.participantRawSecondsTotal || 0);

    if ((eventName === "participant_joined" || eventName === "room_started") && identity) {
      const p = participants[identity] && typeof participants[identity] === "object" ? participants[identity] : {};
      if (!p.joinedAtMs) {
        participants[identity] = { ...p, joinedAtMs: tsMs, lastSeenAtMs: tsMs };
      } else {
        participants[identity] = { ...p, lastSeenAtMs: tsMs };
      }
      // Phone calls: send call_started only after the call is answered (when SIP participant joins).
      if (eventName === "participant_joined" && String(identity).startsWith("sip-") && call.to !== "webtest" && !call.endedAt) {
        const metrics = call.metrics && typeof call.metrics === "object" ? call.metrics : {};
        if (!metrics.call_started_webhook_sent) {
          try {
            await store.updateCall(call.id, { metrics: { ...metrics, call_started_webhook_sent: true }, updatedAt: nowMs });
            const updated = await store.getCallById(call.id);
            if (updated?.agentId && updated.workspaceId) {
              const agent = await store.getAgent(updated.workspaceId, updated.agentId);
              if (agent?.webhookUrl) sendAgentWebhook(agent, "call_started", updated);
            }
          } catch (e) {
            logger.warn({ callId: call.id, err: String(e?.message || e) }, "[livekit.webhook] call_started failed");
          }
        }
      }
    }

    if ((eventName === "participant_left" || eventName === "participant_connection_aborted") && identity) {
      const p = participants[identity] && typeof participants[identity] === "object" ? participants[identity] : {};
      const joinedAtMs = Number(p.joinedAtMs || 0);
      if (joinedAtMs > 0) {
        const rawSec = Math.max(0, Math.round((tsMs - joinedAtMs) / 1000));
        const billedSec = roundUpToMinuteSeconds(rawSec);
        rawSecondsTotal += rawSec;
        billedSecondsTotal += billedSec;
      }
      participants[identity] = { ...(participants[identity] || {}), joinedAtMs: null, lastSeenAtMs: tsMs };

      // User hung up: SIP participant left — end call and send webhooks immediately
      if (USE_DB && String(identity).startsWith("sip-") && call.to !== "webtest" && !call.endedAt) {
        logger.info({ callId: call.id, roomName, identity }, "[livekit.webhook] SIP participant left, ending call");
        endTelephonyCallFromWebhook(call, "user_hangup").catch((e2) => {
          logger.warn({ err: String(e2?.message || e2), callId: call.id }, "[livekit.webhook] end call on SIP left failed");
        });
      }
    }

    if (eventName === "room_finished") {
      logger.info({ roomName, callId: call?.id, callTo: call?.to, endedAt: call?.endedAt }, "[livekit.webhook] room_finished received");

      // Close any still-joined participants at room end.
      for (const pid of Object.keys(participants)) {
        const p = participants[pid] && typeof participants[pid] === "object" ? participants[pid] : {};
        const joinedAtMs = Number(p.joinedAtMs || 0);
        if (joinedAtMs > 0) {
          const rawSec = Math.max(0, Math.round((tsMs - joinedAtMs) / 1000));
          const billedSec = roundUpToMinuteSeconds(rawSec);
          rawSecondsTotal += rawSec;
          billedSecondsTotal += billedSec;
          participants[pid] = { ...p, joinedAtMs: null, lastSeenAtMs: tsMs };
        }
      }

      // Mark outbound job as completed when the room ends
      if (USE_DB && roomName && roomName.startsWith("out-")) {
        try {
          const workspaces = await store.listWorkspaces();
          for (const ws of workspaces) {
            const jobs = await store.listOutboundJobs(ws.id, { limit: 1000 });
            const job = jobs.find((j) => j.roomName === roomName && (j.status === "in_call" || j.status === "dialing"));
            if (job) {
              await store.updateOutboundJob(ws.id, job.id, { status: "completed", lastError: "" });
              await store.addOutboundJobLog(ws.id, job.id, { level: "info", message: "Call completed (room finished)" });
              logger.info({ jobId: job.id, roomName }, "[outbound] job completed via room_finished");
              break;
            }
          }
        } catch (e2) {
          logger.warn({ err: String(e2?.message || e2), roomName }, "[outbound] failed to complete job on room_finished");
        }
      }

      // End telephony call when room ended (fallback if participant_left didn’t fire or call wasn’t ended yet)
      if (USE_DB && !call.endedAt) {
        logger.info({ callId: call.id, roomName, to: call.to }, "[livekit.webhook] ending call (room_finished)");
        endTelephonyCallFromWebhook(call, "user_hangup").catch((e2) => {
          logger.warn({ err: String(e2?.message || e2), callId: call.id, roomName }, "[livekit.webhook] end telephony call on room_finished failed");
        });
      }
    }

    const participantMinutesBilled = round4(billedSecondsTotal / 60);
    const livekitPatch = {
      livekit: {
        ...(lk || {}),
        roomName,
        lastEventAtMs: tsMs,
        participants,
        participantRawSecondsTotal: round4(rawSecondsTotal),
        participantBilledSecondsTotal: round4(billedSecondsTotal),
        participantMinutesBilled,
      },
      normalized: {
        ...(prev.normalized && typeof prev.normalized === "object" ? prev.normalized : {}),
        participantMinutes: participantMinutesBilled,
      },
    };

    // Best-effort: persist without blocking webhooks too long.
    await updateCallMetricsById(call.id, livekitPatch);
    return res.status(200).json({ ok: true });
  } catch (e) {
    // eslint-disable-next-line no-console
      logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[livekit.webhook] failed");
    return res.status(400).send("Invalid webhook");
  }
});

// Stripe webhook (raw body required for signature verification). Must be before express.json.
app.post(
  "/api/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const stripeWebhooks = require("./stripe/webhooks");
    const rawBody = Buffer.isBuffer(req.body) ? req.body : (req.body && typeof req.body === "string" ? Buffer.from(req.body, "utf8") : null);
    const sig = req.get("stripe-signature") || "";
    try {
      await stripeWebhooks.handleWebhook(rawBody, sig);
      return res.json({ received: true });
    } catch (e) {
      if (e.type === "StripeSignatureVerificationError") return res.status(400).send("Invalid signature");
      logger.warn({ err: String(e?.message || e), requestId: req.requestId }, "[stripe.webhook] error");
      return res.status(500).json({ error: "Webhook handler failed" });
    }
  }
);

const USE_DB = Boolean(process.env.DATABASE_URL);
const DEFAULT_WORKSPACE_ID = "rapidcallai";

// Allow larger prompts (still bounded to protect the server).
app.use(express.json({ limit: "10mb" }));
// Twilio webhooks POST as application/x-www-form-urlencoded by default.
app.use(express.urlencoded({ extended: false }));

// HTTP metrics middleware (use route templates when available to avoid high-cardinality metrics).
app.use((req, res, next) => {
  const end = httpRequestDurationMs.startTimer({ method: req.method });
  res.on("finish", () => {
    const route = req.route?.path ? `${req.baseUrl || ""}${req.route.path}` : req.path || "unknown";
    end({ route, status: String(res.statusCode) });
  });
  next();
});

// Prometheus metrics endpoint (disabled unless METRICS_BEARER_TOKEN is set).
app.get("/metrics", async (req, res) => {
  const token = String(process.env.METRICS_BEARER_TOKEN || "").trim();
  if (!token) return res.status(404).send("Not found");
  const auth = String(req.headers.authorization || "");
  if (auth !== `Bearer ${token}`) return res.status(401).send("Unauthorized");
  res.set("Content-Type", metricsRegister.contentType);
  return res.send(await metricsRegister.metrics());
});
const PROMPT_MAX = 200000;
const WELCOME_TEXT_MAX = 400;

const WelcomeConfigSchema = z
  .object({
    mode: z.enum(["ai", "user"]).optional(), // ai speaks first / user speaks first
    aiMessageMode: z.enum(["dynamic", "custom"]).optional(),
    aiMessageText: z.string().max(WELCOME_TEXT_MAX).optional(),
    aiDelaySeconds: z.number().min(0).max(10).optional(),
  })
  .optional();

const BackgroundAudioConfigSchema = z
  .object({
    preset: z.enum(["none", "office", "keyboard", "office1", "office2"]).optional(),
    ambientVolume: z.number().min(0).max(1).optional(),
    thinkingVolume: z.number().min(0).max(1).optional(),
  })
  .optional();

const VoiceConfigSchema = z
  .object({
    provider: z.enum(["elevenlabs", "cartesia"]).optional(),
    model: z.string().min(1).max(120).optional(),
    voiceId: z.string().min(1).max(120).optional(),
  })
  .optional();

// Allow omission, and treat empty strings as "unset" (so the server can fall back to defaults).
const LlmModelSchema = z
  .preprocess((v) => {
    if (typeof v === "string" && v.trim().length === 0) return undefined;
    return v;
  }, z.string().min(1).max(120))
  .optional();
const MaxCallSecondsSchema = z.number().int().min(0).max(24 * 60 * 60).optional(); // up to 24h
const KnowledgeFolderIdsSchema = z.array(z.string().min(1).max(40)).max(50).optional();

const CallSettingsSchema = z
  .object({
    voicemailDetectionEnabled: z.boolean().optional(),
    voicemailResponse: z.enum(["hang_up", "leave_message"]).optional(),
    voicemailMessageType: z.enum(["prompt", "static"]).optional(),
    voicemailPrompt: z.string().max(8000).optional(),
    voicemailStaticMessage: z.string().max(8000).optional(),
  })
  .optional();

const FallbackVoiceSchema = z
  .object({
    provider: z.enum(["elevenlabs", "cartesia"]).optional(),
    voiceId: z.string().min(1).max(120).optional(),
    model: z.string().max(120).optional(),
  })
  .nullable()
  .optional();

const PostCallExtractionItemSchema = z.object({
  type: z.enum(["text", "selector", "boolean", "number"]),
  name: z.string().min(1).max(120),
  description: z.string().max(2000).optional(),
  optional: z.boolean().optional(),
  formatExample: z.string().max(500).optional(),
  options: z.array(z.string().max(200)).max(50).optional(),
});
const PostCallDataExtractionSchema = z.array(PostCallExtractionItemSchema).max(50).optional();
const PostCallExtractionModelSchema = z.string().max(120).optional();

// Allow one or many origins. Use comma-separated list in CLIENT_ORIGIN, e.g.:
// CLIENT_ORIGIN=https://dashboard.rapidcall.ai,http://localhost:5173
// Use "*" to allow any origin (not recommended for production).
const clientOrigins = String(process.env.CLIENT_ORIGIN || "http://localhost:5173")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function isAuthPath(pathname) {
  return pathname === "/api/auth/login" || pathname === "/api/auth/register";
}

function isWebhookPath(pathname) {
  return (
    pathname === "/api/livekit/webhook" ||
    pathname === "/api/stripe/webhook" ||
    pathname === "/api/twilio/inbound"
  );
}

// Internal routes use x-agent-secret; no browser Origin (e.g. agent or curl).
function isInternalAgentPath(pathname) {
  return pathname.startsWith("/api/internal/");
}

function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (clientOrigins.includes("*")) return true;
  return clientOrigins.includes(origin);
}

app.use((req, res, next) => {
  const origin = String(req.headers.origin || "").trim();
  const allowAll = clientOrigins.includes("*");
  const allowOrigin =
    !origin ? true : allowAll || isAllowedOrigin(origin) || (isAuthPath(req.path) && origin);
  return cors({
    origin: allowOrigin ? (origin || true) : false,
    credentials: true,
    // Explicitly allow auth header; without this, browsers can block the GET after a successful preflight.
    allowedHeaders: ["authorization", "content-type", "x-agent-secret"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    exposedHeaders: ["content-range", "accept-ranges", "content-length"],
    optionsSuccessStatus: 204,
  })(req, res, next);
});

// Enforce Origin check for state-changing requests (browser CSRF protection).
// Skip origin check when the request uses an API key (Bearer rck_...) or x-agent-secret
// (LiveKit agent server-to-server); those clients don't send Origin.
app.use((req, res, next) => {
  if (!isUnsafeMethod(req.method)) return next();
  if (req.method === "OPTIONS") return next();
  if (isAuthPath(req.path) || isWebhookPath(req.path) || isInternalAgentPath(req.path)) return next();

  const agentSecret = String(req.headers["x-agent-secret"] || "").trim();
  if (agentSecret) return next(); // Agent internal request; no origin required

  const authHeader = String(req.headers.authorization || "").trim();
  if (authHeader.toLowerCase().startsWith("bearer ") && authHeader.slice(7).startsWith("rck_")) {
    return next(); // API key auth; no origin required
  }

  const origin = String(req.headers.origin || "").trim();
  const referer = String(req.headers.referer || "").trim();
  const derivedOrigin = origin || extractOriginFromReferer(referer);
  if (!derivedOrigin || !isAllowedOrigin(derivedOrigin)) {
    return res.status(403).json({ error: "Origin not allowed. Add it to CLIENT_ORIGIN." });
  }

  return next();
});

app.get("/health", (_req, res) => res.json({ ok: true }));

async function findCallByRoomName(roomName) {
  const rn = String(roomName || "").trim();
  if (!rn) return null;
  if (USE_DB) {
    const p = getPool();
    if (!p) return null;
    const { rows } = await p.query(
      `
      SELECT *
      FROM calls
      WHERE room_name=$1
      ORDER BY started_at DESC
      LIMIT 1
    `,
      [rn]
    );
    return rows?.[0] ? await store.getCallById(rows[0].id) : null;
  }
  const calls = readCalls();
  return calls.find((c) => c.roomName === rn) ?? null;
}

async function updateCallMetricsById(callId, patchMetrics) {
  if (!callId) return null;
  if (USE_DB) {
    const cur = await store.getCallById(callId);
    if (!cur) return null;
    const nextMetrics = { ...(cur.metrics && typeof cur.metrics === "object" ? cur.metrics : {}), ...(patchMetrics || {}) };
    return await store.updateCall(callId, { metrics: nextMetrics });
  }
  const calls = readCalls();
  const idx = calls.findIndex((c) => c.id === callId);
  if (idx === -1) return null;
  const cur = calls[idx];
  const nextMetrics = { ...(cur.metrics && typeof cur.metrics === "object" ? cur.metrics : {}), ...(patchMetrics || {}) };
  calls[idx] = { ...cur, metrics: nextMetrics, updatedAt: Date.now() };
  writeCalls(calls);
  return calls[idx];
}

/**
 * Disconnect the SIP participant for a telephony call so the phone actually hangs up.
 * Outbound: remove participant by identity sip-{phoneE164} from job. Inbound: list participants and remove first sip-*.
 */
async function disconnectSipParticipantForCall(call) {
  if (!call?.roomName || call.to === "webtest") return;
  const roomName = String(call.roomName).trim();
  const workspaceId = call.workspaceId;
  try {
    const rs = roomService();
    const isOutbound = call.metrics?.normalized?.source === "outbound";
    if (isOutbound && workspaceId && typeof store.getOutboundJobByRoomName === "function") {
      const job = await store.getOutboundJobByRoomName(workspaceId, roomName);
      if (job?.phoneE164) {
        const identity = `sip-${job.phoneE164}`;
        await rs.removeParticipant(roomName, identity);
        logger.info({ callId: call.id, roomName, identity }, "[internal.calls.end] SIP participant removed (outbound)");
        return;
      }
    }
    const participants = await rs.listParticipants(roomName);
    const sipParticipant = participants.find((p) => p.identity && String(p.identity).startsWith("sip-"));
    if (sipParticipant?.identity) {
      await rs.removeParticipant(roomName, sipParticipant.identity);
      logger.info({ callId: call.id, roomName, identity: sipParticipant.identity }, "[internal.calls.end] SIP participant removed (inbound)");
    }
  } catch (e) {
    logger.warn({ callId: call?.id, roomName, err: String(e?.message || e) }, "[internal.calls.end] disconnect SIP failed");
  }
}

/**
 * End a telephony call from LiveKit webhook (room_finished or participant_left when SIP user hung up).
 * Idempotent: if call already has endedAt, no-op. Updates call, runs extraction, sends webhooks.
 */
async function endTelephonyCallFromWebhook(call, outcome) {
  if (!USE_DB || !call?.id) return;
  const current = await store.getCallById(call.id);
  if (!current || current.endedAt) return;
  const now = Date.now();
  const endedAt = now;
  const durationSec = Math.max(0, Math.round((endedAt - current.startedAt) / 1000));
  const transcriptToStore = current.transcript && current.transcript.length > 0 ? current.transcript : [];
  const patch = { endedAt, durationSec, outcome, transcript: transcriptToStore };

  if (current.agentId && current.workspaceId && transcriptToStore.length > 0) {
    const transcriptText = transcriptToTextForAnalysis(transcriptToStore);
    const apiKey = String(process.env.OPENAI_API_KEY || "").trim();
    const modelDefault = String(process.env.OPENAI_EVAL_MODEL || process.env.OPENAI_GENERATE_MODEL || "gpt-4.1-mini").trim();
    if (apiKey) {
      try {
        const presetResult = await runPresetAnalysis({ apiKey, model: modelDefault, transcriptText, outcome });
        patch.metrics = { ...(current.metrics && typeof current.metrics === "object" ? current.metrics : {}), preset_analysis: presetResult };
      } catch (ePre) {
        logger.warn({ callId: call.id, err: String(ePre?.message || ePre) }, "[livekit.webhook] preset analysis failed");
      }
      try {
        const agent = await store.getAgent(current.workspaceId, current.agentId);
        const items = Array.isArray(agent?.postCallDataExtraction) ? agent.postCallDataExtraction : [];
        if (items.length > 0) {
          const model =
            String(agent?.postCallExtractionModel || "").trim() || modelDefault;
          const results = await runPostCallExtraction({
            apiKey,
            model,
            transcriptText,
            extractionItems: items.map((it) => ({
              name: it.name || "",
              type: it.type,
              description: it.description || it.name,
              options: it.options,
            })),
          });
          patch.analysisStatus = "completed";
          patch.postCallExtractionResults = results;
        }
      } catch (eExt) {
        logger.warn({ callId: call.id, err: String(eExt?.message || eExt) }, "[livekit.webhook] extraction failed");
      }
    }
  }

  const updated = await store.updateCall(call.id, patch);
  try {
    callsEndedTotal.inc({ source: "telephony", outcome: String(outcome || "user_hangup") });
    callDurationSeconds.observe({ source: "telephony", outcome: String(outcome || "user_hangup") }, Number(durationSec || 0));
    inProgressCallsGaugeValue = Math.max(0, inProgressCallsGaugeValue - 1);
  } catch {
    // ignore
  }
  const c = await store.getCallById(call.id);
  if (c?.recording?.kind === "egress_s3" && c.recording.egressId) {
    const egressId = c.recording.egressId;
    await store.updateCall(call.id, { recording: { ...c.recording, status: "stopping" } });
    // Stop egress immediately so recording length matches call end (no 20+ sec tail).
    try {
      await stopEgress(egressId);
    } catch (eStop) {
      logger.warn({ callId: call.id, egressId, err: String(eStop?.message || eStop) }, "[livekit.webhook] stopEgress failed");
    }
    setTimeout(async () => {
      const started = Date.now();
      const maxMs = 90_000;
      const intervalMs = 2000;
      while (Date.now() - started < maxMs) {
        try {
          const info = await getEgressInfo(egressId);
          const status = info?.status;
          if (status === 3) {
            const c2 = await store.getCallById(call.id);
            if (c2?.recording?.kind === "egress_s3") {
              let sizeBytes = c2.recording.sizeBytes ?? null;
              try {
                const h = await headObject({ bucket: c2.recording.bucket, key: c2.recording.key });
                if (typeof h?.ContentLength === "number" && Number.isFinite(h.ContentLength)) sizeBytes = h.ContentLength;
              } catch {
                // ignore
              }
              let durationSec = c2.durationSec;
              const recordingDurationSec = egressDiffToDurationSec(info?.startedAt ?? info?.started_at, info?.endedAt ?? info?.ended_at);
              if (recordingDurationSec != null) durationSec = recordingDurationSec;
              await store.updateCall(call.id, {
                recording: {
                  ...c2.recording,
                  status: "ready",
                  sizeBytes,
                  ...(recordingDurationSec != null ? { durationSec: recordingDurationSec } : {}),
                },
                ...(durationSec != null ? { durationSec } : {}),
              });
            }
            return;
          }
          if (status === 4 || status === 5) {
            const c2 = await store.getCallById(call.id);
            if (c2?.recording?.kind === "egress_s3") await store.updateCall(call.id, { recording: { ...c2.recording, status: "failed" } });
            return;
          }
        } catch {
          // ignore and keep polling
        }
        await new Promise((r) => setTimeout(r, intervalMs));
      }
    }, 0);
  }
  if (updated.agentId && updated.workspaceId) {
    try {
      const agent = await store.getAgent(updated.workspaceId, updated.agentId);
      if (agent) {
        sendAgentWebhook(agent, "call_ended", updated);
        if (updated.metrics?.preset_analysis || updated.analysisStatus || (updated.postCallExtractionResults && updated.postCallExtractionResults.length > 0)) {
          sendAgentWebhook(agent, "call_analyzed", updated);
        }
      }
    } catch (eWh) {
      logger.warn({ callId: call.id, err: String(eWh?.message || eWh) }, "[livekit.webhook] webhooks failed");
    }
  }
  try {
    if (updated.to && updated.to !== "webtest" && /^\+?[1-9]\d{6,14}$/.test(updated.to)) {
      const phone = updated.to.startsWith("+") ? updated.to : `+${updated.to}`;
      const source = updated.metrics?.normalized?.source === "outbound" ? "outbound" : "inbound";
      await contactStore.upsertContactFromCall(updated.workspaceId, phone, "", source);
    }
  } catch {
    // ignore
  }
  logger.info({ callId: call.id, outcome }, "[livekit.webhook] telephony call ended");
}

/** Convert egress startedAt/endedAt diff to seconds (LiveKit may return seconds or milliseconds). */
function egressDiffToDurationSec(startedAt, endedAt) {
  const s = Number(startedAt ?? 0);
  const e = Number(endedAt ?? 0);
  if (s <= 0 || e < s) return null;
  const diff = e - s;
  if (diff < 7200) return Math.max(0, Math.round(diff));
  if (diff < 1e12) return Math.max(0, Math.round(diff / 1000));
  return Math.max(0, Math.round(diff / 1e9));
}

function getPublicApiBaseUrl(req) {
  const explicit = String(process.env.PUBLIC_API_BASE_URL || "").trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const proto = req.headers["x-forwarded-proto"] ? String(req.headers["x-forwarded-proto"]).split(",")[0].trim() : req.protocol;
  const host = req.headers["x-forwarded-host"] ? String(req.headers["x-forwarded-host"]).split(",")[0].trim() : req.get("host");
  return `${proto}://${host}`.replace(/\/+$/, "");
}

function getRecordingPlaybackSecret() {
  // Dedicated secret preferred. Fall back to AGENT_SHARED_SECRET to avoid breaking existing deployments.
  const s =
    String(process.env.RECORDING_PLAYBACK_SECRET || "").trim() ||
    String(process.env.AGENT_SHARED_SECRET || "").trim();
  return s || null;
}

function wavFromPcmS16le(pcmBuf, sampleRate) {
  const numChannels = 1;
  const bitsPerSample = 16;
  const byteRate = sampleRate * numChannels * (bitsPerSample / 8);
  const blockAlign = numChannels * (bitsPerSample / 8);

  const dataSize = pcmBuf.length;
  const riffSize = 36 + dataSize;
  const header = Buffer.alloc(44);

  header.write("RIFF", 0);
  header.writeUInt32LE(riffSize, 4);
  header.write("WAVE", 8);
  header.write("fmt ", 12);
  header.writeUInt32LE(16, 16); // PCM fmt chunk size
  header.writeUInt16LE(1, 20); // PCM format
  header.writeUInt16LE(numChannels, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(byteRate, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(bitsPerSample, 34);
  header.write("data", 36);
  header.writeUInt32LE(dataSize, 40);

  return Buffer.concat([header, pcmBuf]);
}

function signRecordingPlaybackToken({ callId, expMs }) {
  const secret = getRecordingPlaybackSecret();
  if (!secret) return null;
  const msg = `${callId}.${expMs}`;
  const sig = crypto.createHmac("sha256", secret).update(msg).digest("base64url");
  return `${expMs}.${sig}`;
}

function verifyRecordingPlaybackToken({ callId, token }) {
  const secret = getRecordingPlaybackSecret();
  if (!secret) return { ok: false, reason: "missing_secret" };
  const parts = String(token || "").split(".");
  if (parts.length !== 2) return { ok: false, reason: "bad_format" };
  const [expStr, sig] = parts;
  const expMs = Number(expStr);
  if (!Number.isFinite(expMs) || expMs <= 0) return { ok: false, reason: "bad_exp" };
  if (Date.now() > expMs) return { ok: false, reason: "expired" };

  const msg = `${callId}.${expMs}`;
  const expected = crypto.createHmac("sha256", secret).update(msg).digest("base64url");
  try {
    const a = Buffer.from(expected);
    const b = Buffer.from(String(sig));
    if (a.length !== b.length) return { ok: false, reason: "bad_sig" };
    if (!crypto.timingSafeEqual(a, b)) return { ok: false, reason: "bad_sig" };
  } catch {
    return { ok: false, reason: "bad_sig" };
  }

  return { ok: true };
}

async function ensureDefaultWorkspace() {
  if (USE_DB) {
    return await store.ensureDefaultWorkspace();
  }
  const rows = readWorkspaces();
  const found = rows[0];
  if (found) return found;
  const now = Date.now();
  const ws = {
    id: DEFAULT_WORKSPACE_ID,
    name: DEFAULT_WORKSPACE_ID,
    twilioSubaccountSid: null,
    createdAt: now,
    updatedAt: now,
  };
  writeWorkspaces([ws]);
  return ws;
}

function makeSessionToken() {
  // 48-char hex token (cryptographically strong)
  return crypto.randomBytes(24).toString("hex");
}

function parseCookies(req) {
  const raw = String(req.headers.cookie || "").trim();
  if (!raw) return {};
  const out = {};
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function getCookie(req, name) {
  const cookies = parseCookies(req);
  return cookies[name] || null;
}

function authCookieOptions(req) {
  const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "").toLowerCase();
  const secure = proto.includes("https");
  return {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  };
}

function csrfCookieOptions(req) {
  const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "").toLowerCase();
  const secure = proto.includes("https");
  return {
    httpOnly: false,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  };
}

function setAuthCookie(req, res, token) {
  res.cookie("auth_token", token, authCookieOptions(req));
}

function clearAuthCookie(req, res) {
  res.clearCookie("auth_token", { ...authCookieOptions(req), maxAge: 0 });
}

function setCsrfCookie(req, res) {
  const token = crypto.randomBytes(24).toString("hex");
  res.cookie("csrf_token", token, csrfCookieOptions(req));
  return token;
}

function clearCsrfCookie(req, res) {
  res.clearCookie("csrf_token", { ...csrfCookieOptions(req), maxAge: 0 });
}

function getBearerToken(req) {
  const h = String(req.headers.authorization || "").trim();
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  return m[1].trim();
}

function getAuthToken(req) {
  return getBearerToken(req) || getCookie(req, "auth_token");
}

function isUnsafeMethod(method) {
  const m = String(method || "").toUpperCase();
  return m === "POST" || m === "PUT" || m === "PATCH" || m === "DELETE";
}


function extractOriginFromReferer(referer) {
  try {
    const u = new URL(referer);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function getPublicBaseUrl(req) {
  const envBase = String(process.env.PUBLIC_API_BASE_URL || "").trim();
  if (envBase) return envBase.replace(/\/$/, "");
  const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "https").split(",")[0].trim();
  const host = String(req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
  if (!host) return "";
  return `${proto}://${host}`;
}

async function requireAuth(req, res, next) {
  // Local JSON mode stays "demo" for now.
  if (!USE_DB) {
    req.user = null;
    req.workspace = await ensureDefaultWorkspace();
    return next();
  }

  const token = getAuthToken(req);
  if (!token) return res.status(401).json({ error: "Missing auth token" });

  // API key auth: token must start with rck_
  if (token.startsWith("rck_")) {
    const key = await store.getApiKeyByRawKey(token);
    if (key) {
      const workspace = await store.getWorkspace(key.workspaceId);
      if (!workspace) return res.status(401).json({ error: "Workspace not found" });
      req.user = null;
      req.workspace = workspace;
      req.apiKey = key;
      req.sessionToken = null;
      try {
        await store.touchApiKeyLastUsed(key.id);
      } catch (e) {
        logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[auth] touchApiKeyLastUsed failed");
      }
      return next();
    }
    return res.status(401).json({ error: "Invalid API key" });
  }

  const session = await store.getSession(token);
  if (!session) return res.status(401).json({ error: "Invalid session" });
  if (session.expiresAt && session.expiresAt < Date.now()) {
    await store.deleteSession(token);
    return res.status(401).json({ error: "Session expired" });
  }

  const user = await store.getUserById(session.userId);
  if (!user) return res.status(401).json({ error: "User not found" });

  const workspace = await store.ensureWorkspaceForUser({
    user,
    nameHint: `${user.name || user.email} workspace`,
  });

  req.user = user;
  req.workspace = await store.getWorkspace(workspace.id);
  req.sessionToken = token;
  return next();
}

function requireAgentSecret(req, res, next) {
  const expected = String(process.env.AGENT_SHARED_SECRET || "").trim();
  if (!expected) {
    return res.status(500).json({ error: "AGENT_SHARED_SECRET is not set on the server" });
  }
  const got = String(req.headers["x-agent-secret"] || "").trim();
  if (!got || got !== expected) {
    return res.status(401).json({ error: "Invalid agent secret" });
  }
  return next();
}

// --- Auth (real auth when using Postgres) ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  keyPrefix: "auth",
  message: { error: "Too many attempts. Please wait a few minutes and try again." },
});

app.post("/api/auth/register", authLimiter, async (req, res) => {
  const schema = z.object({
    name: z.string().min(1).max(80),
    email: z.string().email().max(200),
    password: z.string().min(6).max(200),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

  try {
    if (!USE_DB) {
      const token = `token:${parsed.data.email}:${Date.now()}`;
      const workspace = await ensureDefaultWorkspace();
      return res.status(201).json({
        token,
        user: { id: "demo", email: parsed.data.email, name: parsed.data.name },
        workspace,
      });
    }

    const existing = await store.getUserByEmail(parsed.data.email);
    if (existing) return res.status(400).json({ error: "Email already registered" });

    const passwordHash = await bcrypt.hash(parsed.data.password, 10);
    const user = await store.createUser({ email: parsed.data.email, name: parsed.data.name, passwordHash });
    const token = makeSessionToken();
    await store.createSession({ userId: user.id, token });
    setAuthCookie(req, res, token);
    setCsrfCookie(req, res);
    const workspace = await store.ensureWorkspaceForUser({ user, nameHint: `${user.name || user.email} workspace` });

    return res.status(201).json({ token, user, workspace });
  } catch (e) {
    logger.error({ requestId: req.requestId, err: String(e?.message || e) }, "[auth.register] failed");
    if (String(e?.code || "") === "23505") {
      return res.status(400).json({ error: "Email already registered" });
    }
    return res.status(500).json({ error: "Registration failed. Check server logs for details." });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const schema = z.object({
    email: z.string().email().max(200),
    password: z.string().min(1).max(200),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

  try {
    if (!USE_DB) {
      const token = `token:${parsed.data.email}:${Date.now()}`;
      const workspace = await ensureDefaultWorkspace();
      return res.json({ token, user: { id: "demo", email: parsed.data.email, name: parsed.data.email }, workspace });
    }

    const u = await store.getUserByEmail(parsed.data.email);
    if (!u) return res.status(401).json({ error: "Invalid email or password" });
    const ok = await bcrypt.compare(parsed.data.password, u.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });

    const user = { id: u.id, email: u.email, name: u.name, createdAt: u.createdAt, updatedAt: u.updatedAt };
    const token = makeSessionToken();
    await store.createSession({ userId: user.id, token });
    setAuthCookie(req, res, token);
    setCsrfCookie(req, res);
    const workspace = await store.ensureWorkspaceForUser({ user, nameHint: `${user.name || user.email} workspace` });
    return res.json({ token, user, workspace });
  } catch (e) {
    logger.error({ requestId: req.requestId, err: String(e?.message || e) }, "[auth.login] failed");
    return res.status(500).json({ error: "Login failed. Check server logs for details." });
  }
});

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  if (USE_DB && req.sessionToken) await store.deleteSession(req.sessionToken);
  clearAuthCookie(req, res);
  clearCsrfCookie(req, res);
  return res.json({ ok: true });
});

app.get("/api/me", requireAuth, async (req, res) => {
  return res.json({ user: req.user, workspace: req.workspace });
});

// --- Billing (Stripe + Metronome) ---
const billingConfig = require("./billing/config");
app.get("/api/billing/summary", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Billing requires Postgres mode" });
  const ws = await store.getWorkspace(req.workspace.id);
  if (!ws) return res.status(404).json({ error: "Workspace not found" });
  let plan = ws.billingPlan || null;
  // If we have a Stripe subscription but no stored plan (e.g. webhook order), derive from Stripe.
  if (!plan && ws.stripeSubscriptionId) {
    try {
      const stripeWebhooks = require("./stripe/webhooks");
      const stripe = stripeWebhooks.getStripe();
      if (stripe) {
        const sub = await stripe.subscriptions.retrieve(ws.stripeSubscriptionId, { expand: ["items.data.price"] });
        const priceId = sub?.items?.data?.[0]?.price?.id;
        plan = billingConfig.planFromStripePriceId(priceId) || null;
        if (plan) await store.updateWorkspace(ws.id, { billingPlan: plan });
      }
    } catch (e) {
      // keep plan null
    }
  }
  const platformFees = { starter: 79, pro: 249, scale: 699 };
  const platformFee = plan ? platformFees[plan] ?? null : null;
  const now = new Date();
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
  const { rows } = await getPool().query(
    `SELECT COALESCE(SUM((metrics->>'computedTotalCost')::double precision), 0) AS mtd
     FROM calls WHERE workspace_id=$1 AND ended_at IS NOT NULL AND metrics IS NOT NULL AND (metrics->>'computedTotalCost') IS NOT NULL
     AND ended_at >= $2`,
    [req.workspace.id, startOfMonth]
  );
  const monthToDateTotal = rows[0]?.mtd != null ? Number(rows[0].mtd) : 0;
  return res.json({
    plan,
    platformFee,
    monthToDateTotal: Math.round(monthToDateTotal * 100) / 100,
    nextInvoiceDate: null,
    stripeCustomerId: ws.stripeCustomerId ?? null,
    hasActiveSubscription: Boolean(ws.stripeSubscriptionId),
  });
});

app.get("/api/billing/checkout-url", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Billing requires Postgres mode" });
  const plan = (req.query.plan || "").toLowerCase();
  if (!billingConfig.PLANS.includes(plan)) return res.status(400).json({ error: "Invalid plan. Use starter, pro, or scale." });
  const priceIds = billingConfig.getStripePriceIds();
  const priceId = priceIds[plan];
  if (!priceId) return res.status(503).json({ error: "Stripe price not configured for this plan." });
  if (!String(priceId).startsWith("price_")) {
    return res.status(400).json({
      error: "STRIPE_PRICE_* must be a Stripe Price ID (e.g. price_1ABC...), not the dollar amount. Create a Product and Price in Stripe Dashboard, then set the Price ID in .env.",
    });
  }
  const stripeWebhooks = require("./stripe/webhooks");
  const stripe = stripeWebhooks.getStripe();
  if (!stripe) return res.status(503).json({ error: "Stripe not configured." });
  const ws = await store.getWorkspace(req.workspace.id);
  // Redirect after Stripe Checkout must go to the dashboard (frontend), not the API host.
  const clientOrigin = (process.env.CLIENT_ORIGIN || "").split(",").map((o) => o.trim()).filter(Boolean)[0] || null;
  const appUrl = clientOrigin ? clientOrigin.replace(/\/$/, "") : null;
  const fallbackUrl = (req.get("x-forwarded-proto") === "https" ? "https" : req.protocol) + "://" + (req.get("x-forwarded-host") || req.get("host") || "localhost");
  const baseUrl = appUrl || fallbackUrl;
  const sessionConfig = {
    mode: "subscription",
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${baseUrl}/app/billing?success=1`,
    cancel_url: `${baseUrl}/app/billing?cancel=1`,
    client_reference_id: req.workspace.id,
    metadata: { workspace_id: req.workspace.id },
  };
  if (ws?.stripeCustomerId) sessionConfig.customer = ws.stripeCustomerId;
  else if (req.user?.email) sessionConfig.customer_email = req.user.email;
  const session = await stripe.checkout.sessions.create(sessionConfig);
  return res.json({ url: session.url });
});

// --- API Keys (workspace-scoped; auth via session or API key) ---
app.get("/api/api-keys", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "API keys require Postgres mode" });
  const keys = await store.listApiKeys(req.workspace.id);
  return res.json({ apiKeys: keys });
});

app.post("/api/api-keys", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "API keys require Postgres mode" });
  const schema = z.object({ name: z.string().min(1).max(80) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const created = await store.createApiKey(req.workspace.id, parsed.data.name);
  return res.status(201).json({ apiKey: created });
});

app.delete("/api/api-keys/:id", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "API keys require Postgres mode" });
  const id = String(req.params.id || "").trim();
  const revoked = await store.revokeApiKey(req.workspace.id, id);
  if (!revoked) return res.status(404).json({ error: "API key not found" });
  return res.json({ ok: true });
});

// --- Knowledge Base (folders + docs) ---
app.get("/api/kb/folders", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const folders = await store.listKbFolders(req.workspace.id);
  return res.json({ folders });
});

app.post("/api/kb/folders", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const schema = z.object({
    name: z.string().min(1).max(120),
    parentId: z.string().min(1).max(40).nullable().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const folder = await store.createKbFolder(req.workspace.id, { name: parsed.data.name, parentId: parsed.data.parentId ?? null });
  return res.status(201).json({ folder });
});

app.put("/api/kb/folders/:id", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const folderId = String(req.params.id || "").trim();
  const schema = z.object({
    name: z.string().min(1).max(120).optional(),
    parentId: z.string().min(1).max(40).nullable().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const folder = await store.updateKbFolder(req.workspace.id, folderId, parsed.data);
  if (!folder) return res.status(404).json({ error: "Folder not found" });
  return res.json({ folder });
});

app.delete("/api/kb/folders/:id", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const folderId = String(req.params.id || "").trim();
  await store.deleteKbFolder(req.workspace.id, folderId);
  return res.json({ ok: true });
});

app.get("/api/kb/folders/:id/docs", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const folderId = String(req.params.id || "").trim();
  const docs = await store.listKbDocs(req.workspace.id, folderId);
  return res.json({ docs });
});

app.post("/api/kb/folders/:id/text", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const folderId = String(req.params.id || "").trim();
  const schema = z.object({
    title: z.string().max(200).optional(),
    contentText: z.string().min(1).max(2_000_000),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const doc = await store.createKbTextDoc(req.workspace.id, { folderId, title: parsed.data.title ?? "", contentText: parsed.data.contentText });
  return res.status(201).json({ doc });
});

app.post("/api/kb/folders/:id/pdf", requireAuth, kbUpload.single("file"), async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const folderId = String(req.params.id || "").trim();
  if (!req.file) return res.status(400).json({ error: "Missing file" });

  const mime = String(req.file.mimetype || "");
  if (!mime.includes("pdf")) return res.status(400).json({ error: "Only PDF files are supported right now" });

  let extracted = "";
  try {
    const r = await pdfParse(req.file.buffer);
    extracted = String(r?.text || "");
  } catch (e) {
    return res.status(400).json({ error: "Failed to parse PDF", details: String(e?.message || e) });
  }

  // Keep DB payload bounded.
  const contentText = extracted.replace(/\u0000/g, "").trim().slice(0, 2_000_000);
  if (!contentText) return res.status(400).json({ error: "PDF contains no extractable text" });

  const title = String(req.body?.title || req.file.originalname || "Document").trim().slice(0, 200);
  const doc = await store.createKbPdfDoc(req.workspace.id, {
    folderId,
    title,
    contentText,
    sourceFilename: req.file.originalname || null,
    mime: req.file.mimetype || null,
    sizeBytes: Number(req.file.size || 0) || null,
  });
  return res.status(201).json({ doc });
});

app.delete("/api/kb/docs/:id", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const docId = String(req.params.id || "").trim();
  await store.deleteKbDoc(req.workspace.id, docId);
  return res.json({ ok: true });
});

app.post("/api/kb/search", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Knowledge Base requires Postgres mode" });
  const schema = z.object({
    folderIds: z.array(z.string().min(1).max(40)).min(1).max(50),
    query: z.string().min(1).max(500),
    limit: z.number().int().min(1).max(10).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

  const q = parsed.data.query.toLowerCase();
  const limit = parsed.data.limit ?? 5;
  const results = [];

  // Naive search: load docs in those folders and rank by substring matches.
  for (const folderId of parsed.data.folderIds) {
    const docs = await store.listKbDocs(req.workspace.id, folderId);
    for (const d of docs) {
      const text = String(d.contentText || "");
      const hay = text.toLowerCase();
      const idx = hay.indexOf(q);
      if (idx === -1) continue;
      const start = Math.max(0, idx - 180);
      const end = Math.min(text.length, idx + q.length + 180);
      const excerpt = text.slice(start, end).replace(/\s+/g, " ").trim();
      results.push({
        docId: d.id,
        folderId: d.folderId,
        title: d.title || d.sourceFilename || "Document",
        kind: d.kind,
        excerpt,
        score: 1,
      });
    }
  }

  results.sort((a, b) => b.score - a.score);
  return res.json({ results: results.slice(0, limit) });
});

// CRM API routes (Contacts / Leads)
app.use("/api/crm", requireAuth, createCrmRouter({ store: USE_DB ? store : null, USE_DB }));

// --- Internal (used by the LiveKit agent to create/update call records) ---
/**
 * Run inbound/start logic: create call record and set room metadata (enabledTools, toolConfigs, etc.)
 * so the agent sees the same config as webtest. Used by POST inbound/start and by LiveKit webhook
 * when a SIP participant joins and no call exists yet (inbound phone flow).
 * @returns {{ status: number, data?: object, error?: string }}
 */
async function doInboundStart({ roomName, to, from, twilioCallSid = "" }) {
  if (!USE_DB) return { status: 400, error: "Internal endpoints require Postgres mode" };
  const fromStr = String(from || "").trim();
  const toStr = String(to || "").trim();
  const roomNameStr = String(roomName || "").trim();
  if (!roomNameStr || toStr.length < 3) return { status: 400, error: "roomName and to (E.164) required" };

  const phoneRow = await store.getPhoneNumberByE164(toStr);
  if (!phoneRow) {
    console.log("[doInboundStart] phone number not found", { to: toStr });
    return { status: 404, error: "Phone number not found" };
  }
  const ws = await store.getWorkspace(phoneRow.workspaceId);
  if (!ws) return { status: 404, error: "Workspace not found" };

  const agentId = phoneRow.inboundAgentId;
  const callId = `call_${nanoid(12)}`;
  const now = Date.now();

  if (!agentId) {
    console.warn("[doInboundStart] Inbound agent not configured", { to: toStr, from: fromStr, roomName: roomNameStr });
    const fallbackPrompt = "You are a voice assistant. The number you were called on does not have an inbound agent configured. Say exactly once: This number is not configured for inbound calls. Please set the Inbound agent for this phone number in the dashboard.";
    const callRecord = {
      id: callId,
      workspaceId: phoneRow.workspaceId,
      agentId: null,
      agentName: "System",
      to: fromStr || "unknown",
      roomName: roomNameStr,
      startedAt: now,
      endedAt: null,
      durationSec: null,
      outcome: "in_progress",
      costUsd: null,
      transcript: [],
      recording: null,
      metrics: {
        normalized: { source: "telephony", fallback: true },
        telephony: { trunkNumber: toStr, callerNumber: fromStr || "", twilioCallSid: twilioCallSid || undefined },
      },
      createdAt: now,
      updatedAt: now,
    };
    await store.createCall(callRecord);
    const metadata = {
      call: { id: callId, to: fromStr || "unknown", direction: "inbound" },
      agent: {
        id: null,
        workspaceId: phoneRow.workspaceId,
        name: "System",
        prompt: fallbackPrompt,
        voice: {},
        enabledTools: ["end_call"],
        toolConfigs: {},
        backchannelEnabled: false,
        backgroundAudio: {},
        llmModel: "",
        maxCallSeconds: 60,
        knowledgeFolderIds: [],
        defaultDynamicVariables: {},
        callSettings: {},
        fallbackVoice: null,
        postCallDataExtraction: [],
        postCallExtractionModel: "",
      },
      welcome: {},
    };
    try {
      await roomService().updateRoomMetadata(roomNameStr, JSON.stringify(metadata));
    } catch (metaErr) {
      logger.warn({ err: String(metaErr?.message || metaErr), roomName: roomNameStr }, "[doInboundStart] failed to update room metadata");
    }
    return {
      status: 201,
      data: {
        callId,
        agent: { id: null, name: "System" },
        prompt: fallbackPrompt,
        welcome: {},
        voice: {},
        llmModel: "",
        maxCallSeconds: 60,
        knowledgeFolderIds: [],
        phoneNumber: { id: phoneRow.id, e164: phoneRow.e164 },
      },
    };
  }

  const agent = await store.getAgent(phoneRow.workspaceId, agentId);
  if (!agent) {
    console.log("[doInboundStart] inbound agent not found", { agentId, workspaceId: phoneRow.workspaceId });
    return { status: 404, error: "Inbound agent not found" };
  }
  const promptDraft = agent.promptDraft ?? "";
  const promptPublished = agent.promptPublished ?? "";
  const promptUsed = (promptDraft && String(promptDraft).trim()) ? promptDraft : promptPublished;
  if (!promptUsed || String(promptUsed).trim().length === 0) {
    return { status: 400, error: "Agent prompt is empty" };
  }

  callsStartedTotal.inc({ source: "telephony" });
  inProgressCallsGaugeValue += 1;
  const callRecord = {
    id: callId,
    workspaceId: phoneRow.workspaceId,
    agentId: agent.id,
    agentName: agent.name,
    to: fromStr || "unknown",
    roomName: roomNameStr,
    startedAt: now,
    endedAt: null,
    durationSec: null,
    outcome: "in_progress",
    costUsd: null,
    transcript: [],
    recording: null,
    metrics: {
      normalized: { source: "telephony" },
      telephony: { trunkNumber: toStr, callerNumber: fromStr || "", twilioCallSid: twilioCallSid || undefined },
    },
    createdAt: now,
    updatedAt: now,
  };
  await store.createCall(callRecord);
  console.log("[doInboundStart] call created, room metadata will be updated", { callId, roomName: roomNameStr, to: toStr, from: fromStr, agentId: agent.id });

  const enabledTools = Array.isArray(agent.enabledTools) ? agent.enabledTools : ["end_call"];
  const toolConfigs = agent.toolConfigs && typeof agent.toolConfigs === "object" ? agent.toolConfigs : {};
  const inboundMetadata = {
    call: { id: callId, to: fromStr || "unknown", direction: "inbound" },
    agent: {
      id: agent.id,
      workspaceId: phoneRow.workspaceId,
      name: agent.name,
      prompt: promptUsed,
      voice: agent.voice ?? {},
      enabledTools,
      toolConfigs,
      backchannelEnabled: Boolean(agent.backchannelEnabled),
      backgroundAudio: agent.backgroundAudio ?? {},
      llmModel: String(agent.llmModel || "").trim(),
      maxCallSeconds: Number(agent.maxCallSeconds || 0),
      knowledgeFolderIds: Array.isArray(agent.knowledgeFolderIds) ? agent.knowledgeFolderIds : [],
      defaultDynamicVariables: agent.defaultDynamicVariables ?? {},
      callSettings: agent.callSettings ?? {},
      fallbackVoice: agent.fallbackVoice ?? null,
      postCallDataExtraction: Array.isArray(agent.postCallDataExtraction) ? agent.postCallDataExtraction : [],
      postCallExtractionModel: agent.postCallExtractionModel ?? "",
    },
    welcome: agent.welcome ?? {},
  };
  try {
    await roomService().updateRoomMetadata(roomNameStr, JSON.stringify(inboundMetadata));
    console.log("[doInboundStart] room metadata updated for agent config (enabledTools, toolConfigs)", { roomName: roomNameStr, toolConfigKeys: Object.keys(toolConfigs) });
  } catch (metaErr) {
    logger.warn({ err: String(metaErr?.message || metaErr), roomName: roomNameStr }, "[doInboundStart] failed to update room metadata");
  }
  try {
    const e = await startCallEgress({ roomName: callRecord.roomName, callId });
    if (e && e.enabled) {
      await store.updateCall(callId, {
        recording: {
          kind: "egress_s3",
          egressId: e.egressId,
          bucket: e.bucket,
          key: e.key,
          status: "recording",
          url: `/api/calls/${encodeURIComponent(callId)}/recording`,
        },
      });
    }
  } catch (e) {
    logger.warn({ err: String(e?.message || e) }, "[doInboundStart] failed to start egress");
  }

  return {
    status: 201,
    data: {
      callId,
      workspaceId: phoneRow.workspaceId,
      agent: { id: agent.id, name: agent.name, workspaceId: phoneRow.workspaceId },
      prompt: promptUsed,
      welcome: agent.welcome ?? {},
      voice: { ...(agent.voice ?? {}), backgroundAudio: agent.backgroundAudio ?? {} },
      backgroundAudio: agent.backgroundAudio ?? {},
      llmModel: String(agent.llmModel || ""),
      maxCallSeconds: Number(agent.maxCallSeconds || 0),
      knowledgeFolderIds: Array.isArray(agent.knowledgeFolderIds) ? agent.knowledgeFolderIds : [],
      enabledTools,
      toolConfigs,
      callSettings: agent.callSettings ?? {},
      backchannelEnabled: Boolean(agent.backchannelEnabled),
      fallbackVoice: agent.fallbackVoice ?? null,
      postCallDataExtraction: Array.isArray(agent.postCallDataExtraction) ? agent.postCallDataExtraction : [],
      postCallExtractionModel: agent.postCallExtractionModel ?? "",
      phoneNumber: { id: phoneRow.id, e164: phoneRow.e164 },
    },
  };
}

app.post(
  "/api/internal/telephony/inbound/start",
  (req, _res, next) => {
    console.log("[internal.telephony.inbound.start] request received", {
      hasSecret: Boolean(req.headers["x-agent-secret"]),
      bodyKeys: req.body && typeof req.body === "object" ? Object.keys(req.body) : [],
    });
    next();
  },
  requireAgentSecret,
  async (req, res) => {
    const schema = z.object({
      roomName: z.string().min(1).max(200),
      to: z.string().min(3).max(32),
      from: z.string().min(0).max(32).optional(),
      twilioCallSid: z.string().min(0).max(64).optional(),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
    const to = parsed.data.to.trim();
    const from = String(parsed.data.from || "").trim();
    const twilioCallSid = String(parsed.data.twilioCallSid || "").trim();
    console.log("[internal.telephony.inbound.start]", { roomName: parsed.data.roomName, to, from });
    const result = await doInboundStart({
      roomName: parsed.data.roomName,
      to,
      from,
      twilioCallSid,
    });
    if (result.error && result.status !== 201) {
      return res.status(result.status).json({ error: result.error });
    }
    return res.status(result.status).json(result.data);
  }
);

// Outbound telephony: agent joins room "out-<jobId>" with no SIP (to/from); look up call by room name and return agent config.
app.post(
  "/api/internal/telephony/outbound/start",
  (req, _res, next) => {
    console.log("[internal.telephony.outbound.start] request received", {
      hasSecret: Boolean(req.headers["x-agent-secret"]),
      bodyKeys: req.body && typeof req.body === "object" ? Object.keys(req.body) : [],
    });
    next();
  },
  requireAgentSecret,
  async (req, res) => {
    const schema = z.object({
      roomName: z.string().min(1).max(200),
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
    if (!USE_DB) return res.status(400).json({ error: "Internal endpoints require Postgres mode" });

    const roomName = parsed.data.roomName.trim();
    if (!roomName.startsWith("out-")) {
      return res.status(400).json({ error: "Outbound start requires room name starting with out-" });
    }

    const call = await store.getCallByRoomName(roomName);
    if (!call) {
      console.log("[internal.telephony.outbound.start] call not found for room", { roomName });
      return res.status(404).json({ error: "Call not found for this room" });
    }
    if (!call.agentId || !call.workspaceId) {
      return res.status(404).json({ error: "Call has no agent" });
    }

    const agent = await store.getAgent(call.workspaceId, call.agentId);
    if (!agent) {
      console.log("[internal.telephony.outbound.start] agent not found", { agentId: call.agentId, workspaceId: call.workspaceId });
      return res.status(404).json({ error: "Agent not found" });
    }

    const promptDraft = agent.promptDraft ?? "";
    const promptPublished = agent.promptPublished ?? "";
    let promptUsed = (promptDraft && String(promptDraft).trim()) ? promptDraft : promptPublished;
    if (!promptUsed || String(promptUsed).trim().length === 0) {
      return res.status(400).json({ error: "Agent prompt is empty" });
    }
    // Substitute {{Forename}}, {{Job Titles}}, etc. from outbound job metadata (rapidcall_llm_dynamic_variables).
    const job = await store.getOutboundJobByRoomName(call.workspaceId, roomName);
    if (job && job.metadata && typeof job.metadata === "object") {
      const defaults = agent.defaultDynamicVariables && typeof agent.defaultDynamicVariables === "object" ? agent.defaultDynamicVariables : {};
      const overrides = job.metadata;
      const vars = { ...defaults };
      for (const [k, v] of Object.entries(overrides)) {
        if (typeof v === "string" || (v != null && typeof v === "number") || typeof v === "boolean") vars[k] = String(v);
      }
      promptUsed = substituteDynamicVariables(promptUsed, vars);
    }

    const enabledTools = Array.isArray(agent.enabledTools) ? agent.enabledTools : ["end_call"];
    const toolConfigs = agent.toolConfigs && typeof agent.toolConfigs === "object" ? agent.toolConfigs : {};

    // Update LiveKit room metadata with agent.id and toolConfigs so the agent (and tools) see config even if response is missed.
    const outboundMetadata = {
      call: { id: call.id, to: call.to || "unknown", direction: "outbound" },
      agent: {
        id: agent.id,
        workspaceId: call.workspaceId,
        name: agent.name,
        prompt: promptUsed,
        voice: agent.voice ?? {},
        enabledTools,
        toolConfigs,
        backchannelEnabled: Boolean(agent.backchannelEnabled),
        backgroundAudio: agent.backgroundAudio ?? {},
        llmModel: String(agent.llmModel || "").trim(),
        maxCallSeconds: Number(agent.maxCallSeconds || 0),
        knowledgeFolderIds: Array.isArray(agent.knowledgeFolderIds) ? agent.knowledgeFolderIds : [],
        defaultDynamicVariables: agent.defaultDynamicVariables ?? {},
        callSettings: agent.callSettings ?? {},
        fallbackVoice: agent.fallbackVoice ?? null,
        postCallDataExtraction: Array.isArray(agent.postCallDataExtraction) ? agent.postCallDataExtraction : [],
        postCallExtractionModel: agent.postCallExtractionModel ?? "",
      },
      welcome: agent.welcome ?? {},
    };
    try {
      const rs = roomService();
      await rs.updateRoomMetadata(roomName, JSON.stringify(outboundMetadata));
      console.log("[internal.telephony.outbound.start] room metadata updated (agent.id, toolConfigs)");
    } catch (metaErr) {
      logger.warn({ err: String(metaErr?.message || metaErr), roomName }, "[internal.telephony.outbound.start] failed to update room metadata");
    }

    console.log("[internal.telephony.outbound.start] returning config for outbound call", { callId: call.id, roomName, agentId: agent.id });

    return res.status(200).json({
      callId: call.id,
      workspaceId: call.workspaceId,
      agent: { id: agent.id, name: agent.name, workspaceId: call.workspaceId, to: call.to || "" },
      prompt: promptUsed,
      welcome: agent.welcome ?? {},
      voice: { ...(agent.voice ?? {}), backgroundAudio: agent.backgroundAudio ?? {} },
      backgroundAudio: agent.backgroundAudio ?? {},
      llmModel: String(agent.llmModel || ""),
      maxCallSeconds: Number(agent.maxCallSeconds || 0),
      knowledgeFolderIds: Array.isArray(agent.knowledgeFolderIds) ? agent.knowledgeFolderIds : [],
      enabledTools,
      toolConfigs,
      callSettings: agent.callSettings ?? {},
      backchannelEnabled: Boolean(agent.backchannelEnabled),
      fallbackVoice: agent.fallbackVoice ?? null,
      postCallDataExtraction: Array.isArray(agent.postCallDataExtraction) ? agent.postCallDataExtraction : [],
      postCallExtractionModel: agent.postCallExtractionModel ?? "",
    });
  }
);

app.post("/api/internal/calls/:id/end", requireAgentSecret, async (req, res) => {
  const { id } = req.params;
  const schema = z.object({
    outcome: z.string().min(1).max(80).optional(),
    transcript: z.array(TranscriptItemSchema).max(500).optional(),
    analysisStatus: z.string().max(120).optional(),
    postCallExtractionResults: z.array(z.object({
      name: z.string(),
      value: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
      description: z.string().optional(),
    })).max(100).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  if (!USE_DB) return res.status(400).json({ error: "Internal endpoints require Postgres mode" });

  const current = await store.getCallById(id);
  if (!current) return res.status(404).json({ error: "Call not found" });

  const now = Date.now();
  const endedAt = current.endedAt ?? now;
  const durationSec = Math.max(0, Math.round((endedAt - current.startedAt) / 1000));

  let outcomeToStore = parsed.data.outcome ?? (current.outcome === "in_progress" ? "agent_hangup" : current.outcome);
  if (outcomeToStore === "ended" || outcomeToStore === "completed") outcomeToStore = "agent_hangup";
  const transcriptToStore = parsed.data.transcript ? parsed.data.transcript : current.transcript;
  const patch = {
    endedAt,
    durationSec,
    outcome: outcomeToStore,
    transcript: transcriptToStore,
  };
  if (parsed.data.analysisStatus !== undefined) patch.analysisStatus = parsed.data.analysisStatus;
  if (parsed.data.postCallExtractionResults !== undefined) patch.postCallExtractionResults = parsed.data.postCallExtractionResults;

  // Preset analysis (call_summary, in_voicemail, user_sentiment, call_successful) for every call with transcript
  if (transcriptToStore && transcriptToStore.length > 0) {
    const apiKey = String(process.env.OPENAI_API_KEY || "").trim();
    if (apiKey) {
      try {
        const transcriptText = transcriptToTextForAnalysis(transcriptToStore);
        const modelDefault = String(process.env.OPENAI_EVAL_MODEL || process.env.OPENAI_GENERATE_MODEL || "gpt-4.1-mini").trim();
        const presetResult = await runPresetAnalysis({ apiKey, model: modelDefault, transcriptText, outcome: outcomeToStore });
        patch.metrics = { ...(current.metrics && typeof current.metrics === "object" ? current.metrics : {}), preset_analysis: presetResult };
      } catch (ePre) {
        logger.warn({ requestId: req.requestId, err: String(ePre?.message || ePre) }, "[internal.calls.end] preset analysis failed");
      }
    }
  }

  // Post-call extraction (agent-configured items) when we have transcript
  if (
    current.agentId &&
    current.workspaceId &&
    transcriptToStore &&
    transcriptToStore.length > 0 &&
    patch.analysisStatus === undefined &&
    patch.postCallExtractionResults === undefined
  ) {
    try {
      const agent = await store.getAgent(current.workspaceId, current.agentId);
      const items = Array.isArray(agent?.postCallDataExtraction) ? agent.postCallDataExtraction : [];
      if (items.length > 0) {
        const apiKey = String(process.env.OPENAI_API_KEY || "").trim();
        if (apiKey) {
          const model =
            String(agent?.postCallExtractionModel || "").trim() ||
            String(process.env.OPENAI_EVAL_MODEL || process.env.OPENAI_GENERATE_MODEL || "gpt-4.1-mini").trim();
          const transcriptText = transcriptToTextForAnalysis(transcriptToStore);
          const results = await runPostCallExtraction({
            apiKey,
            model,
            transcriptText,
            extractionItems: items.map((it) => ({
              name: it.name || "",
              type: it.type,
              description: it.description || it.name,
              options: it.options,
            })),
          });
          patch.analysisStatus = "completed";
          patch.postCallExtractionResults = results;
        }
      }
    } catch (e) {
      logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[internal.calls.end] post-call extraction failed");
      patch.analysisStatus = "failed";
      patch.postCallExtractionResults = [];
    }
  }

  let updated = await store.updateCall(id, patch);

  // Billing: emit usage to Metronome and attach cost to call
  if (updated?.workspaceId) {
    try {
      const workspace = await store.getWorkspace(updated.workspaceId);
      const metronomeClient = require("./metronome/client");
      const billingUsage = require("./billing/usage");
      const costResult = await billingUsage.emitCallUsageAndComputeCost(updated, workspace, metronomeClient);
      if (costResult) {
        const withCost = await store.updateCall(id, {
          metrics: { ...(updated.metrics || {}), costBreakdown: costResult.costBreakdown, computedTotalCost: costResult.computedTotalCost },
        });
        if (withCost) updated = withCost;
      }
    } catch (eBilling) {
      logger.warn({ requestId: req.requestId, err: String(eBilling?.message || eBilling), callId: id }, "[internal.calls.end] billing usage/cost failed");
    }
  }

  // Hang up the phone leg so the carrier actually disconnects (agent said goodbye / end_call tool)
  await disconnectSipParticipantForCall(updated);

  // Metrics: telephony end
  try {
    callsEndedTotal.inc({ source: "telephony", outcome: String(outcomeToStore || "completed") });
    callDurationSeconds.observe({ source: "telephony", outcome: String(outcomeToStore || "completed") }, Number(durationSec || 0));
    inProgressCallsGaugeValue = Math.max(0, inProgressCallsGaugeValue - 1);
  } catch {
    // ignore
  }

  // Stop/finalize egress for telephony calls (same behavior as public /api/calls/:id/end).
  try {
    const c = await store.getCallById(id);
    if (c?.recording?.kind === "egress_s3" && c.recording.egressId) {
      const egressId = c.recording.egressId;
      await store.updateCall(id, { recording: { ...c.recording, status: "stopping" } });
      try {
        await stopEgress(egressId);
      } catch (eStop) {
        logger.warn({ callId: id, egressId, err: String(eStop?.message || eStop) }, "[internal.calls.end] stopEgress failed");
      }
      setTimeout(async () => {
        const started = Date.now();
        const maxMs = 90_000;
        const intervalMs = 2000;
        while (Date.now() - started < maxMs) {
          try {
            const info = await getEgressInfo(egressId);
            const status = info?.status;
            if (status === 3) {
              const c2 = await store.getCallById(id);
              if (c2?.recording?.kind === "egress_s3") {
                let sizeBytes = c2.recording.sizeBytes ?? null;
                try {
                  const h = await headObject({ bucket: c2.recording.bucket, key: c2.recording.key });
                  if (typeof h?.ContentLength === "number" && Number.isFinite(h.ContentLength)) sizeBytes = h.ContentLength;
                } catch {
                  // ignore
                }
                let durationSec = c2.durationSec;
                const recordingDurationSec = egressDiffToDurationSec(info?.startedAt ?? info?.started_at, info?.endedAt ?? info?.ended_at);
                if (recordingDurationSec != null) durationSec = recordingDurationSec;
                await store.updateCall(id, {
                  recording: {
                    ...c2.recording,
                    status: "ready",
                    sizeBytes,
                    ...(recordingDurationSec != null ? { durationSec: recordingDurationSec } : {}),
                  },
                  ...(durationSec != null ? { durationSec } : {}),
                });
              }
              return;
            }
            if (status === 4 || status === 5) {
              const c2 = await store.getCallById(id);
              if (c2?.recording?.kind === "egress_s3") {
                await store.updateCall(id, { recording: { ...c2.recording, status: "failed" } });
              }
              return;
            }
          } catch {
            // ignore and keep polling
          }
          await new Promise((r) => setTimeout(r, intervalMs));
        }
      }, 0);
    }
  } catch {
    // ignore; call end should not fail because of egress
  }

  // Auto-create/update contact from call (best-effort)
  try {
    if (updated.to && updated.to !== "webtest" && /^\+?[1-9]\d{6,14}$/.test(updated.to)) {
      const phone = updated.to.startsWith("+") ? updated.to : `+${updated.to}`;
      const source = updated.metrics?.normalized?.source === "outbound" ? "outbound" : "inbound";
      await contactStore.upsertContactFromCall(updated.workspaceId, phone, "", source);
    }
  } catch (e) {
    logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[internal.calls.end] contact auto-create failed");
  }

  if (updated.agentId && updated.workspaceId && USE_DB) {
    try {
      const agent = await store.getAgent(updated.workspaceId, updated.agentId);
      if (agent) {
        sendAgentWebhook(agent, "call_ended", updated);
        if (updated.metrics?.preset_analysis || updated.analysisStatus || (updated.postCallExtractionResults && updated.postCallExtractionResults.length > 0)) {
          sendAgentWebhook(agent, "call_analyzed", updated);
        }
      }
    } catch (e) {
      logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[internal.calls.end] webhook send failed");
    }
  }

  return res.json({ call: updated });
});

// Transcript item: utterance (speaker/role/text) or tool_invocation / tool_result (Retell-style). Zod 4: z.record(key, value).
const transcriptRecordSchema = z.record(z.string(), z.unknown());
const TranscriptItemSchema = z.union([
  z.object({ speaker: z.string().min(1).max(120), role: z.enum(["agent", "user"]), text: z.string().min(1).max(5000) }),
  z.object({
    kind: z.literal("tool_invocation"),
    toolCallId: z.string().min(1).max(80),
    toolName: z.string().min(1).max(80),
    input: transcriptRecordSchema,
  }),
  z.object({
    kind: z.literal("tool_result"),
    toolCallId: z.string().min(1).max(80),
    toolName: z.string().max(80).optional(),
    result: transcriptRecordSchema,
  }),
]);

/** Build plain text from transcript for LLM analysis (utterances + brief tool lines). */
function transcriptToTextForAnalysis(transcript) {
  if (!transcript || !Array.isArray(transcript)) return "";
  return transcript
    .map((t) => {
      if (t.kind === "tool_invocation") return `[Tool invoked: ${t.toolName}]`;
      if (t.kind === "tool_result") return `[Tool result: ${t.toolName || "?"}]`;
      return `${t.role === "user" ? "USER" : "AGENT"}: ${String(t.text || "").trim()}`;
    })
    .filter(Boolean)
    .join("\n");
}

// --- Internal: agent pushes transcript during call and on shutdown (so when user hangs up we have it) ---
app.post("/api/internal/calls/:id/transcript", requireAgentSecret, async (req, res) => {
  const { id } = req.params;
  if (!USE_DB) return res.status(400).json({ error: "Internal endpoints require Postgres mode" });
  const current = await store.getCallById(id);
  if (!current) return res.status(404).json({ error: "Call not found" });

  const schema = z.object({
    transcript: z.array(TranscriptItemSchema).max(500),
  });
  let parsed;
  try {
    parsed = schema.safeParse(req.body);
  } catch (parseErr) {
    logger.warn({ callId: id, err: String(parseErr?.message || parseErr) }, "[internal.transcript] parse threw");
    return res.status(400).json({ error: "Invalid transcript payload" });
  }
  if (!parsed.success) {
    logger.warn({ callId: id, error: parsed.error.flatten() }, "[internal.transcript] validation failed");
    return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  }

  await store.updateCall(id, { transcript: parsed.data.transcript });
  return res.json({ ok: true });
});

// --- Internal: agent requests cold transfer (SIP REFER) for a phone call ---
// LiveKit SIP participant: identity often "sip-<number>"; kind may be 2 (SIP) in ParticipantInfo.
app.post("/api/internal/calls/:id/transfer", requireAgentSecret, async (req, res) => {
  const { id } = req.params;
  const bodyTransferTo = typeof req.body?.transferTo === "string" ? req.body.transferTo.trim() : "";
  logger.info(
    { callId: id, bodyTransferTo: bodyTransferTo || "(empty)", hasBody: !!req.body },
    "[internal.transfer] request received"
  );

  const schema = z.object({ transferTo: z.string().min(1).max(80) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    logger.warn({ callId: id, validation: parsed.error.flatten() }, "[internal.transfer] validation failed");
    return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  }
  if (!USE_DB) {
    logger.warn({ callId: id }, "[internal.transfer] rejected: Postgres mode required");
    return res.status(400).json({ error: "Internal endpoints require Postgres mode" });
  }

  const call = await store.getCallById(id);
  if (!call) {
    logger.warn({ callId: id }, "[internal.transfer] call not found");
    return res.status(404).json({ error: "Call not found" });
  }
  if (call.endedAt) {
    logger.warn({ callId: id, endedAt: call.endedAt }, "[internal.transfer] rejected: call already ended");
    return res.status(400).json({ error: "Call already ended" });
  }
  if (call.to === "webtest") {
    logger.warn({ callId: id, to: call.to }, "[internal.transfer] rejected: web call");
    return res.status(400).json({ error: "Transfer not available on web calls" });
  }

  const roomName = call.roomName;
  if (!roomName) {
    logger.warn({ callId: id, roomName: roomName }, "[internal.transfer] rejected: no room for call");
    return res.status(400).json({ error: "No room for this call" });
  }

  let transferTo = parsed.data.transferTo.trim();
  if (!transferTo.startsWith("tel:") && !transferTo.startsWith("sip:")) transferTo = `tel:${transferTo}`;

  logger.info({ callId: id, roomName, transferTo }, "[internal.transfer] attempt: resolving SIP participant");

  try {
    const rs = roomService();
    const participants = await rs.listParticipants(roomName);
    const participantSummary = participants.map((p) => ({ identity: p.identity, kind: p.kind }));
    logger.info(
      { callId: id, roomName, participantCount: participants.length, participants: participantSummary },
      "[internal.transfer] participants listed"
    );

    // Prefer participant whose identity starts with "sip" (the actual SIP trunk leg). Fallback to kind === 2.
    const sipParticipant =
      participants.find((p) => p.identity && String(p.identity).toLowerCase().startsWith("sip")) ||
      participants.find(
        (p) =>
          p.kind === 2 || (typeof p.kind === "string" && String(p.kind).toUpperCase() === "SIP")
      );
    if (!sipParticipant?.identity) {
      logger.warn(
        { callId: id, roomName, participantIdentities: participants.map((p) => p.identity), participantSummary },
        "[internal.transfer] no SIP participant in room"
      );
      return res.status(400).json({ error: "No SIP participant in room", participantCount: participants.length });
    }

    logger.info(
      { callId: id, roomName, sipIdentity: sipParticipant.identity, transferTo },
      "[internal.transfer] calling LiveKit transferSipParticipant"
    );
    const sip = sipClient();
    await sip.transferSipParticipant(roomName, sipParticipant.identity, transferTo, { playDialtone: false });
    logger.info(
      { callId: id, roomName, identity: sipParticipant.identity, transferTo },
      "[internal.transfer] success: SIP transfer completed"
    );
    // End the call record with outcome "transferred" and stop egress so recording length matches (no 20+ sec tail).
    const callForEnd = await store.getCallById(id);
    if (callForEnd && !callForEnd.endedAt) {
      try {
        await endTelephonyCallFromWebhook(callForEnd, "transferred");
      } catch (eEnd) {
        logger.warn({ callId: id, err: String(eEnd?.message || eEnd) }, "[internal.transfer] endTelephonyCallFromWebhook failed");
      }
    }
    return res.json({ ok: true, status: "transferred" });
  } catch (e) {
    const code = e?.metadata?.["sip_status_code"] ?? e?.code;
    const msg = e?.message || String(e);
    const errDetail = {
      callId: id,
      roomName,
      transferTo,
      err: msg,
      sipCode: code,
      errName: e?.name,
      errStack: e?.stack ? String(e.stack).slice(0, 500) : undefined,
      metadata: e?.metadata,
    };
    logger.warn(errDetail, "[internal.transfer] transfer failed (LiveKit or SIP error)");
    return res.status(500).json({ error: "Transfer failed", message: msg, sipStatusCode: code });
  }
});

// --- Internal: fetch agent config (toolConfigs, enabledTools) when room metadata has none ---
// Supports workspaceId+agentId (preferred) or agentId only (fallback when room metadata is missing; e.g. webtest room name is call-{agentId}-{nanoid}).
app.get("/api/internal/agents/config", requireAgentSecret, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Internal endpoints require Postgres mode" });
  const workspaceId = (req.query.workspaceId || "").toString().trim();
  const agentId = (req.query.agentId || "").toString().trim();
  if (!agentId) {
    logger.warn({ workspaceId: workspaceId || "(empty)", agentId: agentId || "(empty)" }, "[internal.agents.config] missing agentId");
    return res.status(400).json({ error: "agentId query param required" });
  }
  let agent = null;
  if (workspaceId) {
    agent = await store.getAgent(workspaceId, agentId);
  } else {
    agent = await store.getAgentById(agentId);
  }
  if (!agent) {
    logger.warn({ workspaceId: workspaceId || "(omit)", agentId }, "[internal.agents.config] agent not found");
    return res.status(404).json({ error: "Agent not found" });
  }
  const toolConfigs = agent.toolConfigs && typeof agent.toolConfigs === "object" ? agent.toolConfigs : {};
  const keys = Object.keys(toolConfigs);
  logger.info({ agentId, workspaceId: workspaceId || "(from id)", toolConfigKeys: keys }, "[internal.agents.config] returning config");
  return res.json({
    toolConfigs,
    enabledTools: Array.isArray(agent.enabledTools) ? agent.enabledTools : ["end_call"],
  });
});

// --- Internal KB search (for the LiveKit agent tools) ---
app.post("/api/internal/kb/search", requireAgentSecret, async (req, res) => {
  const schema = z.object({
    callId: z.string().min(1).max(64),
    query: z.string().min(1).max(500),
    folderIds: z.array(z.string().min(1).max(40)).max(50).optional(),
    limit: z.number().int().min(1).max(10).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  if (!USE_DB) return res.status(400).json({ error: "Internal endpoints require Postgres mode" });

  const call = await store.getCallById(parsed.data.callId);
  if (!call?.workspaceId) return res.status(404).json({ error: "Call not found" });
  const workspaceId = call.workspaceId;

  const validFolderIds = new Set((await store.listKbFolders(workspaceId)).map((f) => f.id));
  const requested = (parsed.data.folderIds || []).filter((id) => validFolderIds.has(id));
  const folderIdsToUse = requested.length ? requested : [];
  if (!folderIdsToUse.length) return res.json({ results: [] });

  const q = parsed.data.query.toLowerCase();
  const limit = parsed.data.limit ?? 5;
  const results = [];
  for (const folderId of folderIdsToUse) {
    const docs = await store.listKbDocs(workspaceId, folderId);
    for (const d of docs) {
      const text = String(d.contentText || "");
      const hay = text.toLowerCase();
      const idx = hay.indexOf(q);
      if (idx === -1) continue;
      const start = Math.max(0, idx - 220);
      const end = Math.min(text.length, idx + q.length + 220);
      const excerpt = text.slice(start, end).replace(/\s+/g, " ").trim();
      results.push({
        docId: d.id,
        folderId: d.folderId,
        title: d.title || d.sourceFilename || "Document",
        kind: d.kind,
        excerpt,
        score: 1,
      });
    }
  }
  results.sort((a, b) => b.score - a.score);
  return res.json({ results: results.slice(0, limit) });
});

function normalizeCountries(v) {
  if (!v) return ["all"];
  if (Array.isArray(v)) return v.length ? v : ["all"];
  if (typeof v === "string") {
    const parts = v
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    return parts.length ? parts : ["all"];
  }
  return ["all"];
}

function stripUndefined(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));
}

function openaiGenerateAgentPrompt({ apiKey, model, input }) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model,
      temperature: 0.4,
      messages: [
        {
          role: "system",
          content:
            "You generate production-grade system prompts for voice agents. " +
            "Output ONLY the final prompt text (no JSON, no markdown fences). " +
            "The prompt must be detailed, structured, and optimized for short, one-question-at-a-time voice conversations. " +
            "Include: ROLE, GOAL, STYLE, FLOW, BUSINESS CONTEXT, REQUIRED DATA, FAQs, DO NOT, ESCALATION, CALL SUMMARY, EXAMPLES. " +
            "Never invent business facts; rely only on provided inputs; if missing, add safe placeholders.",
        },
        {
          role: "user",
          content:
            "Create a system prompt using the following template + questionnaire answers. " +
            "Make it long and high quality, but still practical for real calls.\n\n" +
            JSON.stringify(input, null, 2),
        },
      ],
    });

    const req = https.request(
      {
        hostname: "api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              return reject(new Error(`OpenAI error ${res.statusCode}: ${String(data).slice(0, 400)}`));
            }
            const parsed = JSON.parse(data);
            const txt =
              parsed?.choices?.[0]?.message?.content != null ? String(parsed.choices[0].message.content) : "";
            resolve(txt);
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function openaiAutoEvaluateCall({ apiKey, model, input }) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content:
            "You are a strict QA evaluator for voice agents. " +
            "Return ONLY valid JSON with keys: score (0-100), summary (string), " +
            "strengths (array of strings), issues (array of strings), " +
            "suggestedFixes (array of strings), nextTests (array of strings). " +
            "Be concise, actionable, and grounded in the transcript.",
        },
        {
          role: "user",
          content: JSON.stringify(input, null, 2),
        },
      ],
    });

    const req = https.request(
      {
        hostname: "api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              return reject(new Error(`OpenAI error ${res.statusCode}: ${String(data).slice(0, 400)}`));
            }
            const parsed = JSON.parse(data);
            const txt =
              parsed?.choices?.[0]?.message?.content != null ? String(parsed.choices[0].message.content) : "";
            resolve(txt);
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Run post-call data extraction: LLM reads transcript and returns one value per extraction item.
 * @param {{ apiKey: string, model: string, transcriptText: string, extractionItems: Array<{ name: string, type?: string, description?: string, options?: string[] }> }}
 * @returns {Promise<Array<{ name: string, value: string|number|boolean|null, description?: string }>>}
 */
function runPostCallExtraction({ apiKey, model, transcriptText, extractionItems }) {
  if (!extractionItems || extractionItems.length === 0) {
    return Promise.resolve([]);
  }
  const itemDescriptions = extractionItems
    .map((item, i) => {
      const desc = item.description || item.name;
      const type = (item.type || "text").toLowerCase();
      const opts = Array.isArray(item.options) && item.options.length > 0 ? ` One of: ${item.options.join(", ")}.` : "";
      return `${i + 1}. "${item.name}" (${type}): ${desc}${opts}`;
    })
    .join("\n");

  const systemContent =
    "You extract structured data from a call transcript. " +
    "Return ONLY a JSON array of objects, one per item, each with exactly: name (string), value (string, number, boolean, or null). " +
    "Use the exact item names given. If something cannot be determined from the transcript, use null for value. " +
    "For booleans use true/false. For numbers use a number, not a string.";

  const userContent = `Transcript:\n${transcriptText.slice(0, 12000)}\n\nExtract these items:\n${itemDescriptions}`;

  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model,
      temperature: 0.1,
      messages: [
        { role: "system", content: systemContent },
        { role: "user", content: userContent },
      ],
    });

    const req = https.request(
      {
        hostname: "api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              return reject(new Error(`OpenAI error ${res.statusCode}: ${String(data).slice(0, 400)}`));
            }
            const parsed = JSON.parse(data);
            const txt =
              parsed?.choices?.[0]?.message?.content != null ? String(parsed.choices[0].message.content).trim() : "";
            if (!txt) {
              return resolve(extractionItems.map((item) => ({ name: item.name, value: null, description: item.description })));
            }
            let arr;
            try {
              arr = JSON.parse(txt);
            } catch {
              const start = txt.indexOf("[");
              const end = txt.lastIndexOf("]");
              if (start !== -1 && end !== -1 && end > start) arr = JSON.parse(txt.slice(start, end + 1));
            }
            if (!Array.isArray(arr)) {
              return resolve(extractionItems.map((item) => ({ name: item.name, value: null, description: item.description })));
            }
            const results = extractionItems.map((item) => {
              const found = arr.find((o) => o && String(o.name).trim() === String(item.name).trim());
              const val = found && Object.prototype.hasOwnProperty.call(found, "value") ? found.value : null;
              return {
                name: item.name,
                value: val === undefined ? null : val,
                description: item.description,
              };
            });
            resolve(results);
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/**
 * Run preset analysis for every call with transcript: call_summary, in_voicemail, user_sentiment, call_successful.
 * Stored in call.metrics.preset_analysis and used in webhooks + UI. No agent config required.
 * @returns {Promise<{ call_summary: string, in_voicemail: boolean, user_sentiment: string|null, call_successful: boolean }>}
 */
function runPresetAnalysis({ apiKey, model, transcriptText, outcome }) {
  if (!apiKey || !transcriptText || transcriptText.length < 10) {
    return Promise.resolve({
      call_summary: "",
      in_voicemail: false,
      user_sentiment: null,
      call_successful: false,
    });
  }
  const systemContent =
    "You analyze a call transcript. Return ONLY a JSON object with exactly these keys: " +
    "call_summary (string, 1-3 sentence summary of what happened), " +
    "in_voicemail (boolean, true if the call reached voicemail or left a message), " +
    "user_sentiment (string, one of: positive, negative, neutral, or null if unclear), " +
    "call_successful (boolean, true if the call achieved a reasonable outcome e.g. completed conversation, left message, or resolved intent). " +
    "No other keys. Use the exact key names.";
  const userContent = `Outcome: ${outcome || "unknown"}\n\nTranscript:\n${transcriptText.slice(0, 10000)}`;

  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model: model || "gpt-4.1-mini",
      temperature: 0.2,
      messages: [
        { role: "system", content: systemContent },
        { role: "user", content: userContent },
      ],
    });
    const req = https.request(
      {
        hostname: "api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        headers: {
          authorization: `Bearer ${apiKey}`,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              return resolve({ call_summary: "", in_voicemail: false, user_sentiment: null, call_successful: false });
            }
            const parsed = JSON.parse(data);
            const txt =
              parsed?.choices?.[0]?.message?.content != null ? String(parsed.choices[0].message.content).trim() : "";
            if (!txt) {
              return resolve({ call_summary: "", in_voicemail: false, user_sentiment: null, call_successful: false });
            }
            let obj;
            try {
              obj = JSON.parse(txt);
            } catch {
              const start = txt.indexOf("{");
              const end = txt.lastIndexOf("}");
              if (start !== -1 && end > start) obj = JSON.parse(txt.slice(start, end + 1));
            }
            if (!obj || typeof obj !== "object") {
              return resolve({ call_summary: "", in_voicemail: false, user_sentiment: null, call_successful: false });
            }
            resolve({
              call_summary: typeof obj.call_summary === "string" ? obj.call_summary.trim().slice(0, 2000) : "",
              in_voicemail: Boolean(obj.in_voicemail),
              user_sentiment:
                obj.user_sentiment === "positive" || obj.user_sentiment === "negative" || obj.user_sentiment === "neutral"
                  ? obj.user_sentiment
                  : null,
              call_successful: Boolean(obj.call_successful),
            });
          } catch (e) {
            resolve({ call_summary: "", in_voicemail: false, user_sentiment: null, call_successful: false });
          }
        });
      }
    );
    req.on("error", () => resolve({ call_summary: "", in_voicemail: false, user_sentiment: null, call_successful: false }));
    req.write(body);
    req.end();
  });
}

// Serve uploaded call recordings (web-test recordings)
const RECORDINGS_DIR = path.join(__dirname, "..", "recordings");
if (!fs.existsSync(RECORDINGS_DIR)) fs.mkdirSync(RECORDINGS_DIR, { recursive: true });
app.use("/recordings", express.static(RECORDINGS_DIR));

// --- Agent profiles (stored locally in ./data/agents.json) ---
app.get("/api/agents", requireAuth, async (req, res) => {
  if (USE_DB) {
    const agents = await store.listAgents(req.workspace.id);
    return res.json({ agents });
  }
  return res.json({ agents: readAgents() });
});

app.post("/api/agents", requireAuth, async (req, res) => {
  const schema = z.object({
    name: z.string().min(1).max(60),
    promptDraft: z.string().max(PROMPT_MAX).optional(),
    promptPublished: z.string().max(PROMPT_MAX).optional(),
    welcome: WelcomeConfigSchema,
    voice: VoiceConfigSchema,
    llmModel: LlmModelSchema,
    autoEvalEnabled: z.boolean().optional(),
    knowledgeFolderIds: KnowledgeFolderIdsSchema,
    maxCallSeconds: MaxCallSecondsSchema,
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "Validation failed",
      details: parsed.error.flatten(),
      hint: `Prompt max length is ${PROMPT_MAX} characters`,
    });
  }

  if (USE_DB) {
    const agent = await store.createAgent({
      ...parsed.data,
      workspaceId: req.workspace.id,
      llmModel: parsed.data.llmModel ?? DEFAULT_LLM_MODEL,
      knowledgeFolderIds: parsed.data.knowledgeFolderIds ?? [],
    });
    return res.status(201).json({ agent });
  }

  const agents = readAgents();
  const now = Date.now();
  const agent = {
    id: nanoid(10),
    name: parsed.data.name,
    promptDraft: parsed.data.promptDraft ?? "",
    promptPublished: parsed.data.promptPublished ?? "",
    publishedAt: parsed.data.promptPublished ? now : null,
    llmModel: parsed.data.llmModel ?? cfg.defaultLlmModel,
    autoEvalEnabled: Boolean(parsed.data.autoEvalEnabled),
    knowledgeFolderIds: parsed.data.knowledgeFolderIds ?? [],
    maxCallSeconds: Math.max(0, Math.round(Number(parsed.data.maxCallSeconds || 0))),
    welcome: {
      mode: parsed.data.welcome?.mode ?? "user",
      aiMessageMode: parsed.data.welcome?.aiMessageMode ?? "dynamic",
      aiMessageText: parsed.data.welcome?.aiMessageText ?? "",
      aiDelaySeconds: parsed.data.welcome?.aiDelaySeconds ?? 0,
    },
    voice: parsed.data.voice
      ? {
          provider: parsed.data.voice.provider ?? null,
          model: parsed.data.voice.model ?? null,
          voiceId: parsed.data.voice.voiceId ?? null,
        }
      : {},
    createdAt: now,
    updatedAt: now,
  };
  agents.unshift(agent);
  writeAgents(agents);
  return res.status(201).json({ agent });
});

// Generate a production-grade agent prompt from template + questionnaire (AI-generated).
app.post("/api/agents/generate-prompt", requireAuth, async (req, res) => {
  const schema = z.object({
    templateId: z.string().min(1).max(40),
    agentName: z.string().max(120).optional(),
    businessName: z.string().max(120).optional(),
    industry: z.string().max(120).optional(),
    location: z.string().max(120).optional(),
    timezone: z.string().max(60).optional(),
    languages: z.string().max(120).optional(),
    primaryGoal: z.string().max(600).optional(),
    targetCustomer: z.string().max(240).optional(),
    tone: z.string().max(40).optional(),
    greetingStyle: z.string().max(240).optional(),
    offerings: z.string().max(1200).optional(),
    hours: z.string().max(240).optional(),
    bookingLink: z.string().max(300).optional(),
    requiredFields: z.string().max(400).optional(),
    faqs: z.string().max(2000).optional(),
    disallowed: z.string().max(1200).optional(),
    escalation: z.string().max(1200).optional(),
    policies: z.string().max(2000).optional(),
    extra: z.string().max(2500).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

  const apiKey = String(process.env.OPENAI_API_KEY || "").trim();
  if (!apiKey) return res.status(500).json({ error: "OPENAI_API_KEY is not set on the server" });
  const model = String(process.env.OPENAI_GENERATE_MODEL || "gpt-4.1-mini").trim();

  try {
    const prompt = await openaiGenerateAgentPrompt({ apiKey, model, input: parsed.data });
    const trimmed = String(prompt || "").trim();
    if (!trimmed) return res.status(500).json({ error: "OpenAI returned empty prompt" });
    return res.json({ promptDraft: trimmed });
  } catch (e) {
    return res.status(502).json({ error: "Prompt generation failed" });
  }
});

app.get("/api/agents/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const agent = USE_DB ? await store.getAgent(req.workspace.id, id) : readAgents().find((a) => a.id === id);
  if (!agent) return res.status(404).json({ error: "Agent not found" });
  res.json({ agent });
});

// Agent variants (A/B prompt testing)
app.get("/api/agents/:id/variants", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Variants require Postgres mode" });
  const agentId = String(req.params.id || "").trim();
  const rows = await store.listAgentVariants(req.workspace.id, agentId);
  return res.json({ variants: rows });
});

app.post("/api/agents/:id/variants", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Variants require Postgres mode" });
  const agentId = String(req.params.id || "").trim();
  const schema = z.object({
    name: z.string().min(1).max(80),
    prompt: z.string().min(1).max(200_000),
    trafficPercent: z.number().int().min(0).max(100),
    enabled: z.boolean().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const row = await store.createAgentVariant(req.workspace.id, agentId, parsed.data);
  return res.status(201).json({ variant: row });
});

app.put("/api/agents/:id/variants/:variantId", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Variants require Postgres mode" });
  const variantId = String(req.params.variantId || "").trim();
  const schema = z.object({
    name: z.string().min(1).max(80).optional(),
    prompt: z.string().min(1).max(200_000).optional(),
    trafficPercent: z.number().int().min(0).max(100).optional(),
    enabled: z.boolean().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const row = await store.updateAgentVariant(req.workspace.id, variantId, parsed.data);
  if (!row) return res.status(404).json({ error: "Variant not found" });
  return res.json({ variant: row });
});

app.delete("/api/agents/:id/variants/:variantId", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Variants require Postgres mode" });
  const variantId = String(req.params.variantId || "").trim();
  await store.deleteAgentVariant(req.workspace.id, variantId);
  return res.json({ ok: true });
});

app.put("/api/agents/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const schema = z.object({
    name: z.string().min(1).max(60).optional(),
    promptDraft: z.string().max(PROMPT_MAX).optional(),
    publish: z.boolean().optional(),
    welcome: WelcomeConfigSchema,
    voice: VoiceConfigSchema,
    backgroundAudio: BackgroundAudioConfigSchema,
    enabledTools: z.array(z.string()).optional(),
    toolConfigs: z.record(z.string(), z.object({
      name: z.string().max(80).optional(),
      description: z.string().max(800).optional(),
      transferTo: z.string().max(40).optional(),
      apiKey: z.string().max(200).optional(),
      eventTypeId: z.string().max(80).optional(),
      timezone: z.string().max(80).optional(),
    })).optional(),
    backchannelEnabled: z.boolean().optional(),
    llmModel: LlmModelSchema,
    autoEvalEnabled: z.boolean().optional(),
    knowledgeFolderIds: KnowledgeFolderIdsSchema,
    maxCallSeconds: MaxCallSecondsSchema,
    defaultDynamicVariables: z.record(z.string(), z.string()).optional(),
    callSettings: CallSettingsSchema,
    fallbackVoice: FallbackVoiceSchema,
    postCallDataExtraction: PostCallDataExtractionSchema,
    postCallExtractionModel: PostCallExtractionModelSchema,
    webhookUrl: z.union([z.string().url().max(2000), z.literal("")]).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "Validation failed",
      details: parsed.error.flatten(),
      hint: `Prompt max length is ${PROMPT_MAX} characters`,
    });
  }

  if (USE_DB) {
    const agent = await store.updateAgent(req.workspace.id, id, {
      ...parsed.data,
      webhookUrl: parsed.data.webhookUrl !== undefined ? (parsed.data.webhookUrl === "" ? null : parsed.data.webhookUrl) : undefined,
    });
    if (!agent) return res.status(404).json({ error: "Agent not found" });
    return res.json({ agent });
  }

  const agents = readAgents();
  const idx = agents.findIndex((a) => a.id === id);
  if (idx === -1) return res.status(404).json({ error: "Agent not found" });

  const current = agents[idx];
  // Backward compat for older stored agents
  const currentDraft = current.promptDraft ?? current.prompt ?? "";
  const currentPublished = current.promptPublished ?? "";

  const nextDraft = parsed.data.promptDraft ?? currentDraft;
  const shouldPublish = Boolean(parsed.data.publish);
  const nextPublished = shouldPublish ? nextDraft : currentPublished;

  const next = {
    ...current,
    ...parsed.data,
    promptDraft: nextDraft,
    promptPublished: nextPublished,
    publishedAt: shouldPublish ? Date.now() : (current.publishedAt ?? null),
    welcome: parsed.data.welcome ? { ...(current.welcome ?? {}), ...parsed.data.welcome } : current.welcome,
    voice: parsed.data.voice ? { ...(current.voice ?? {}), ...parsed.data.voice } : current.voice,
    backgroundAudio: parsed.data.backgroundAudio ? { ...(current.backgroundAudio ?? {}), ...parsed.data.backgroundAudio } : (current.backgroundAudio ?? {}),
    llmModel: parsed.data.llmModel ?? (current.llmModel ?? ""),
    autoEvalEnabled: parsed.data.autoEvalEnabled == null ? (current.autoEvalEnabled ?? false) : Boolean(parsed.data.autoEvalEnabled),
    knowledgeFolderIds: parsed.data.knowledgeFolderIds ?? (current.knowledgeFolderIds ?? []),
    enabledTools: parsed.data.enabledTools ?? (current.enabledTools ?? ["end_call"]),
    toolConfigs: parsed.data.toolConfigs ?? (current.toolConfigs ?? {}),
    maxCallSeconds:
      parsed.data.maxCallSeconds == null
        ? (current.maxCallSeconds ?? 0)
        : Math.max(0, Math.round(Number(parsed.data.maxCallSeconds || 0))),
    defaultDynamicVariables:
      parsed.data.defaultDynamicVariables !== undefined
        ? (parsed.data.defaultDynamicVariables && typeof parsed.data.defaultDynamicVariables === "object" ? parsed.data.defaultDynamicVariables : {})
        : (current.defaultDynamicVariables ?? {}),
    callSettings:
      parsed.data.callSettings !== undefined
        ? (parsed.data.callSettings && typeof parsed.data.callSettings === "object" ? parsed.data.callSettings : {})
        : (current.callSettings ?? {}),
    fallbackVoice:
      parsed.data.fallbackVoice !== undefined
        ? (parsed.data.fallbackVoice && typeof parsed.data.fallbackVoice === "object" ? parsed.data.fallbackVoice : null)
        : (current.fallbackVoice ?? null),
    postCallDataExtraction:
      parsed.data.postCallDataExtraction !== undefined
        ? (Array.isArray(parsed.data.postCallDataExtraction) ? parsed.data.postCallDataExtraction : [])
        : (current.postCallDataExtraction ?? []),
    postCallExtractionModel:
      parsed.data.postCallExtractionModel !== undefined
        ? String(parsed.data.postCallExtractionModel || "").trim()
        : (current.postCallExtractionModel ?? ""),
    webhookUrl:
      parsed.data.webhookUrl !== undefined
        ? (parsed.data.webhookUrl === "" ? null : (parsed.data.webhookUrl || null))
        : (current.webhookUrl ?? null),
    updatedAt: Date.now(),
  };
  delete next.prompt;
  delete next.publish;
  agents[idx] = next;
  writeAgents(agents);
  res.json({ agent: next });
});

app.delete("/api/agents/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  if (USE_DB) {
    await store.deleteAgent(req.workspace.id, id);
    return res.json({ ok: true });
  }
  const agents = readAgents();
  const next = agents.filter((a) => a.id !== id);
  writeAgents(next);
  res.json({ ok: true });
});

// --- Workspaces (Phase 1) ---
app.get("/api/workspaces", requireAuth, async (req, res) => {
  // Single-workspace-per-user for now.
  return res.json({ workspaces: [req.workspace] });
});

app.post("/api/workspaces", requireAuth, async (req, res) => {
  const schema = z.object({ name: z.string().min(1).max(80) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  }

  if (USE_DB) {
    const workspace = await store.updateWorkspace(req.workspace.id, { name: parsed.data.name });
    return res.json({ workspace });
  }

  const rows = readWorkspaces();
  const now = Date.now();
  const ws = {
    id: nanoid(10),
    name: parsed.data.name,
    twilioSubaccountSid: null,
    createdAt: now,
    updatedAt: now,
  };
  writeWorkspaces([ws, ...rows]);
  return res.status(201).json({ workspace: ws });
});

// --- Twilio (Phase 2) ---
app.get("/api/workspaces/:id/twilio", requireAuth, async (req, res) => {
  const id = String(req.params.id);
  if (id !== req.workspace.id) return res.status(403).json({ error: "Forbidden" });
  const ws = req.workspace;
  return res.json({ workspace: ws, twilioConfigured: Boolean(tw.getMasterCreds()) });
});

// Inbound diagnostics: Twilio trunk origination URIs + LiveKit inbound trunk (for debugging "trunking issue").
app.get("/api/workspaces/:id/inbound-diagnostics", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Requires Postgres mode" });
  const id = String(req.params.id);
  if (id !== req.workspace.id) return res.status(403).json({ error: "Forbidden" });
  const ws = req.workspace;
  const sipEndpoint = String(process.env.LIVEKIT_SIP_ENDPOINT || "").trim();
  let originationUrls = [];
  if (ws.twilioSubaccountSid && ws.twilioSipTrunkSid) {
    try {
      originationUrls = await tw.listSipTrunkOriginationUrls({
        subaccountSid: ws.twilioSubaccountSid,
        trunkSid: ws.twilioSipTrunkSid,
      });
    } catch (e) {
      originationUrls = [{ error: String(e?.message || e) }];
    }
  }
  const phoneNumbers = await store.listPhoneNumbers(ws.id);
  return res.json({
    LIVEKIT_SIP_ENDPOINT: sipEndpoint || null,
    twilioSipTrunkSid: ws.twilioSipTrunkSid || null,
    livekitInboundTrunkId: ws.livekitInboundTrunkId || null,
    originationUrls,
    expectedOriginationSipUrl: sipEndpoint ? `sip:${sipEndpoint};transport=tls` : null,
    phoneNumbers: phoneNumbers.map((p) => ({ id: p.id, e164: p.e164, inboundAgentId: p.inboundAgentId || null })),
  });
});

app.post("/api/workspaces/:id/twilio/subaccount", requireAuth, async (req, res) => {
  const id = String(req.params.id);
  if (id !== req.workspace.id) return res.status(403).json({ error: "Forbidden" });
  let ws = req.workspace;

  try {
    const { sid, created } = await tw.ensureSubaccount({
      friendlyName: `rapidcallai:${ws.name || ws.id}`,
      existingSid: ws.twilioSubaccountSid ?? null,
    });

    if (USE_DB) {
      // If a NEW subaccount was created (old one was from a different master), clear stale Twilio data
      if (created && ws.twilioSubaccountSid) {
        console.log(`[ensure-subaccount] Twilio master account changed — old subaccount ${ws.twilioSubaccountSid} replaced with ${sid}. Clearing stale trunk/credential references.`);
        const p = getPool();
        await p.query(`
          UPDATE workspaces SET
            twilio_sip_trunk_sid = NULL,
            twilio_sip_domain_name = NULL,
            twilio_sip_cred_username = NULL,
            twilio_sip_cred_password = NULL,
            livekit_outbound_trunk_id = NULL,
            livekit_inbound_trunk_id = NULL
          WHERE id = $1
        `, [id]);
      }
      const updated = await store.updateWorkspace(id, { twilioSubaccountSid: sid });
      return res.json({ workspace: updated, created });
    }

    const rows = readWorkspaces();
    const idx = rows.findIndex((w) => w.id === id);
    const next = { ...rows[idx], twilioSubaccountSid: sid, updatedAt: Date.now() };
    rows[idx] = next;
    writeWorkspaces(rows);
    return res.json({ workspace: next, created });
  } catch (e) {
    return res.status(400).json({ error: e instanceof Error ? e.message : "Twilio subaccount failed" });
  }
});

app.get("/api/workspaces/:id/twilio/available-numbers", requireAuth, async (req, res) => {
  const id = String(req.params.id);
  if (id !== req.workspace.id) return res.status(403).json({ error: "Forbidden" });
  const ws = req.workspace;

  try {
    const results = await tw.searchAvailableNumbers({
      subaccountSid: ws.twilioSubaccountSid,
      country: req.query.country,
      type: req.query.type,
      contains: req.query.contains,
      limit: req.query.limit,
    });
    return res.json({ numbers: results });
  } catch (e) {
    return res.status(400).json({ error: e instanceof Error ? e.message : "Search failed" });
  }
});

app.post("/api/workspaces/:id/twilio/buy-number", requireAuth, async (req, res) => {
  const id = String(req.params.id);
  if (id !== req.workspace.id) return res.status(403).json({ error: "Forbidden" });
  let ws = req.workspace;

  const schema = z.object({
    phoneNumber: z.string().min(3).max(32),
    label: z.string().max(120).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  }

  try {
    // Ensure we have a subaccount first.
    const { sid: subSid, created: subCreated } = await tw.ensureSubaccount({
      friendlyName: `rapidcallai:${ws.name || ws.id}`,
      existingSid: ws.twilioSubaccountSid ?? null,
    });
    // If subaccount changed (old one was from a different master), clear stale data
    if (subCreated && ws.twilioSubaccountSid && USE_DB) {
      console.log(`[buy-number] Twilio master account changed — clearing stale trunk/credential references for workspace ${ws.id}`);
      const p = getPool();
      await p.query(`
        UPDATE workspaces SET
          twilio_subaccount_sid = $2,
          twilio_sip_trunk_sid = NULL,
          twilio_sip_domain_name = NULL,
          twilio_sip_cred_username = NULL,
          twilio_sip_cred_password = NULL,
          livekit_outbound_trunk_id = NULL,
          livekit_inbound_trunk_id = NULL
        WHERE id = $1
      `, [id, subSid]);
      ws.twilioSubaccountSid = subSid;
      ws.twilioSipTrunkSid = null;
      ws.twilioSipDomainName = null;
      ws.twilioSipCredUsername = null;
      ws.twilioSipCredPassword = null;
      ws.livekitOutboundTrunkId = null;
      ws.livekitInboundTrunkId = null;
    } else if (!ws.twilioSubaccountSid) {
      if (USE_DB) await store.updateWorkspace(id, { twilioSubaccountSid: subSid });
      else {
        const rows = readWorkspaces();
        const idx = rows.findIndex((w) => w.id === id);
        rows[idx] = { ...rows[idx], twilioSubaccountSid: subSid, updatedAt: Date.now() };
        writeWorkspaces(rows);
      }
      ws.twilioSubaccountSid = subSid;
    }

    const purchased = await tw.buyNumber({
      subaccountSid: ws.twilioSubaccountSid,
      phoneNumber: parsed.data.phoneNumber,
      friendlyName: parsed.data.label || undefined,
    });

    // Save as a phone number record (initially unconfigured).
    const inboundTrunkId = String(process.env.SIP_INBOUND_TRUNK_ID || "").trim();
    const outboundTrunkId = String(process.env.SIP_OUTBOUND_TRUNK_ID || "").trim();
    const sipEndpoint = String(process.env.LIVEKIT_SIP_ENDPOINT || "").trim();

    if (USE_DB) {
      let phoneNumber = await store.createPhoneNumber({
        workspaceId: ws.id,
        e164: purchased.phoneNumber,
        label: parsed.data.label ?? "",
        provider: "twilio",
        status: "unconfigured",
        twilioNumberSid: purchased.sid,
        livekitInboundTrunkId: inboundTrunkId || null,
        livekitOutboundTrunkId: outboundTrunkId || null,
        allowedInboundCountries: ["all"],
        allowedOutboundCountries: ["all"],
      });

      // --- Auto-provision: Twilio voice URL + LiveKit SIP trunks ---
      const provisionErrors = [];

      // 1) Configure Twilio number to forward inbound calls to our server → LiveKit SIP
      try {
        await tw.configureNumberForSip({
          subaccountSid: ws.twilioSubaccountSid,
          numberSid: purchased.sid,
          e164: purchased.phoneNumber,
          sipEndpoint,
        });
        logger.info({ e164: purchased.phoneNumber }, "[buy-number] Twilio voice URL configured");
      } catch (e) {
        const msg = String(e?.message || e);
        logger.warn({ e164: purchased.phoneNumber, err: msg }, "[buy-number] failed to configure Twilio voice URL");
        provisionErrors.push(`Twilio voice URL: ${msg}`);
      }

      // 2) Auto-provision LiveKit inbound trunk for the workspace (if not using env trunk)
      let effectiveInboundTrunkId = inboundTrunkId || ws.livekitInboundTrunkId;
      if (!effectiveInboundTrunkId) {
        // Auto-create inbound trunk for this workspace
        try {
          logger.info({ workspaceId: ws.id, e164: purchased.phoneNumber }, "[buy-number] auto-creating LiveKit inbound trunk");
          const inboundResult = await createInboundTrunkForWorkspace({
            workspaceId: ws.id,
            numbers: [purchased.phoneNumber],
          });
          effectiveInboundTrunkId = inboundResult.trunkId;
          
          // Persist the inbound trunk ID on the workspace
          await store.updateWorkspace(ws.id, {
            livekitInboundTrunkId: effectiveInboundTrunkId,
          });
          
          logger.info({ workspaceId: ws.id, trunkId: effectiveInboundTrunkId, e164: purchased.phoneNumber }, "[buy-number] auto-created LiveKit inbound trunk");
        } catch (e) {
          const existingTrunkId = parseConflictingInboundTrunkId(e);
          if (existingTrunkId) {
            effectiveInboundTrunkId = existingTrunkId;
            await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
            logger.info({ workspaceId: ws.id, trunkId: effectiveInboundTrunkId, e164: purchased.phoneNumber }, "[buy-number] using existing inbound trunk (number already on it)");
          } else {
            const msg = String(e?.message || e);
            logger.warn({ workspaceId: ws.id, e164: purchased.phoneNumber, err: msg }, "[buy-number] failed to auto-create inbound trunk");
            provisionErrors.push(`Inbound trunk creation: ${msg}`);
          }
        }
      } else {
        // Add number to existing inbound trunk
        try {
          await addNumberToInboundTrunk(effectiveInboundTrunkId, purchased.phoneNumber);
          logger.info({ e164: purchased.phoneNumber, trunkId: effectiveInboundTrunkId }, "[buy-number] added to inbound trunk");
        } catch (e) {
          const msg = String(e?.message ?? e?.error ?? e ?? "").toLowerCase();
          const isTrunkMissing = isTrunkNotFoundError(e) || e?.code === "TRUNK_NOT_FOUND" || msg.includes("object cannot be found") || (msg.includes("twirp") && msg.includes("not found"));
          if (isTrunkMissing) {
            // Inbound trunk no longer exists — create a new one
            logger.warn({ workspaceId: ws.id, e164: purchased.phoneNumber, oldTrunkId: effectiveInboundTrunkId }, "[buy-number] inbound trunk not found in LiveKit, creating new one");
            try {
              const inboundResult = await createInboundTrunkForWorkspace({
                workspaceId: ws.id,
                numbers: [purchased.phoneNumber],
              });
              effectiveInboundTrunkId = inboundResult.trunkId;
              await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
              logger.info({ workspaceId: ws.id, trunkId: effectiveInboundTrunkId, e164: purchased.phoneNumber }, "[buy-number] created new inbound trunk");
            } catch (createErr) {
              const existingTrunkId = parseConflictingInboundTrunkId(createErr);
              if (existingTrunkId) {
                effectiveInboundTrunkId = existingTrunkId;
                await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
                logger.info({ workspaceId: ws.id, trunkId: effectiveInboundTrunkId, e164: purchased.phoneNumber }, "[buy-number] using existing inbound trunk (number already on it)");
              } else {
                const createMsg = String(createErr?.message || createErr);
                logger.warn({ workspaceId: ws.id, e164: purchased.phoneNumber, err: createMsg }, "[buy-number] failed to create inbound trunk");
                provisionErrors.push(`Inbound trunk creation: ${createMsg}`);
              }
            }
          } else {
            logger.warn({ e164: purchased.phoneNumber, err: msg }, "[buy-number] failed to add to inbound trunk");
            provisionErrors.push(`Inbound trunk: ${msg}`);
          }
        }
      }

      // 3) Auto-provision Twilio SIP trunk + LiveKit outbound trunk for the workspace.
      //    This ensures the Caller ID is recognized by Twilio (number belongs to same
      //    subaccount as the SIP trunk). Falls back to env SIP_OUTBOUND_TRUNK_ID if set.
      let effectiveOutboundTrunkId = ws.livekitOutboundTrunkId || outboundTrunkId;
      try {
        // 3a) Ensure a Twilio Elastic SIP Trunk exists on the subaccount.
        const { trunkSid, domainName, secure } = await tw.ensureSipTrunk({
          subaccountSid: ws.twilioSubaccountSid,
          existingTrunkSid: ws.twilioSipTrunkSid,
          workspaceId: ws.id,
        });
        // IMPORTANT: Twilio "secure" only controls SRTP (disabled because LiveKit doesn't support it).
        // Always use TLS signaling on LiveKit side (transport=3).
        const isSecure = true; // Always TLS signaling, regardless of Twilio SRTP setting
        logger.info({ trunkSid, domainName, twilioSecure: secure, livekitTls: isSecure }, "[buy-number] Twilio SIP trunk ensured");

        // 3b) Ensure termination credentials exist on the trunk.
        const { credUsername, credPassword } = await tw.ensureSipTrunkTerminationCreds({
          subaccountSid: ws.twilioSubaccountSid,
          trunkSid,
          existingUsername: ws.twilioSipCredUsername,
          existingPassword: ws.twilioSipCredPassword,
        });
        logger.info({ trunkSid }, "[buy-number] Twilio SIP trunk creds ensured");

        // 3c) Associate the purchased phone number with the Twilio SIP trunk.
        try {
          await tw.associateNumberWithSipTrunk({
            subaccountSid: ws.twilioSubaccountSid,
            trunkSid,
            numberSid: purchased.sid,
          });
          logger.info({ e164: purchased.phoneNumber, trunkSid }, "[buy-number] number associated with Twilio SIP trunk");
        } catch (assocErr) {
          // May fail if already associated — that's fine.
          if (!String(assocErr?.message || "").includes("already associated")) {
            throw assocErr;
          }
        }

        // 3c2) Ensure Origination URI → LiveKit SIP endpoint exists on the trunk.
        //      REQUIRED for inbound calls: PSTN → Twilio trunk → Origination URI → LiveKit.
        try {
          const origResult = await tw.ensureSipTrunkOriginationUri({
            subaccountSid: ws.twilioSubaccountSid,
            trunkSid,
            sipEndpoint,
            secure: isSecure,
          });
          if (origResult.created) {
            logger.info({ trunkSid, sipEndpoint, secure: isSecure }, "[buy-number] origination URI added to Twilio trunk");
          }
        } catch (origErr) {
          const msg = String(origErr?.message || origErr);
          logger.warn({ trunkSid, err: msg }, "[buy-number] failed to add origination URI");
          provisionErrors.push(`Origination URI: ${msg}`);
        }

        // 3c3) IP Access Control List — only if LIVEKIT_SIP_IP_ADDRESSES is set.
        // If NOT set, remove any existing ACLs to avoid blocking LiveKit's dynamic IPs.
        // Authentication is handled by termination credentials, so IP ACL is optional.
        const sipIpAddresses = String(process.env.LIVEKIT_SIP_IP_ADDRESSES || "").trim();
        if (sipIpAddresses) {
          try {
            const ipList = sipIpAddresses.split(",").map((ip) => ip.trim()).filter(Boolean);
            if (ipList.length > 0) {
              const aclResult = await tw.ensureSipTrunkIpAcl({
                subaccountSid: ws.twilioSubaccountSid,
                trunkSid,
                ipAddresses: ipList,
              });
              logger.info({ trunkSid, aclSid: aclResult.aclSid, ipsAdded: aclResult.ipAddressesAdded, totalIps: aclResult.totalIps }, "[buy-number] IP ACL configured");
            }
          } catch (aclErr) {
            const msg = String(aclErr?.message || aclErr);
            logger.warn({ trunkSid, err: msg }, "[buy-number] failed to configure IP ACL");
            provisionErrors.push(`IP ACL: ${msg}`);
          }
        } else {
          // No IP list → remove any existing ACLs so they don't block calls
          logger.info({ trunkSid }, "[buy-number] LIVEKIT_SIP_IP_ADDRESSES not set — removing IP ACL restrictions (credentials handle auth)");
          try {
            await tw.removeAllSipTrunkIpAcls({ subaccountSid: ws.twilioSubaccountSid, trunkSid });
          } catch (aclErr) {
            logger.warn({ trunkSid, err: String(aclErr?.message || aclErr) }, "[buy-number] failed to remove IP ACLs (best-effort)");
          }
        }

        // 3d) Create or update the LiveKit outbound trunk for this workspace.
        if (!ws.livekitOutboundTrunkId) {
          const { trunkId: lkTrunkId } = await createOutboundTrunkForWorkspace({
            workspaceId: ws.id,
            twilioSipDomainName: domainName,
            credUsername,
            credPassword,
            numbers: [purchased.phoneNumber],
            secure: isSecure,
          });
          effectiveOutboundTrunkId = lkTrunkId;
          // Explicitly ensure transport is correct (createOutboundTrunkForWorkspace should set it, but double-check)
          try {
            await ensureOutboundTrunkTransport(lkTrunkId, isSecure);
          } catch (e) {
            logger.warn({ trunkId: lkTrunkId, err: String(e?.message || e) }, "[buy-number] failed to ensure transport on new trunk (best-effort)");
          }
          logger.info({ lkTrunkId, domainName, secure: isSecure }, "[buy-number] LiveKit outbound trunk created");
        } else {
          // Trunk already exists — ensure correct transport and add the number to it.
          effectiveOutboundTrunkId = ws.livekitOutboundTrunkId;
          try {
            await ensureOutboundTrunkTransport(effectiveOutboundTrunkId, isSecure);
          } catch (e) {
            // If trunk doesn't exist, recreate it
            if (isTrunkNotFoundError(e) || e?.code === "TRUNK_NOT_FOUND") {
              logger.warn({ trunkId: effectiveOutboundTrunkId, err: String(e?.message || e) }, "[buy-number] trunk doesn't exist, recreating...");
              // Recreate the trunk
              const result = await createOutboundTrunkForWorkspace({
                workspaceId: ws.id,
                twilioSipDomainName: domainName,
                credUsername,
                credPassword,
                numbers: [purchased.phoneNumber],
                secure: isSecure,
              });
              effectiveOutboundTrunkId = result.trunkId;
              logger.info({ e164: purchased.phoneNumber, trunkId: effectiveOutboundTrunkId }, "[buy-number] recreated LiveKit outbound trunk");
            } else {
              logger.warn({ trunkId: effectiveOutboundTrunkId, err: String(e?.message || e) }, "[buy-number] failed to update trunk transport (best-effort)");
            }
          }
          
          // Add number to trunk (if it still exists)
          if (effectiveOutboundTrunkId) {
            try {
              await addNumberToOutboundTrunk(effectiveOutboundTrunkId, purchased.phoneNumber);
              logger.info({ e164: purchased.phoneNumber, trunkId: effectiveOutboundTrunkId }, "[buy-number] added to LiveKit outbound trunk");
            } catch (e) {
              // If trunk doesn't exist when adding number, recreate it
              if (isTrunkNotFoundError(e)) {
                logger.warn({ trunkId: effectiveOutboundTrunkId, err: String(e?.message || e) }, "[buy-number] trunk doesn't exist when adding number, recreating...");
                const result = await createOutboundTrunkForWorkspace({
                  workspaceId: ws.id,
                  twilioSipDomainName: domainName,
                  credUsername,
                  credPassword,
                  numbers: [purchased.phoneNumber],
                  secure: isSecure,
                });
                effectiveOutboundTrunkId = result.trunkId;
                logger.info({ e164: purchased.phoneNumber, trunkId: effectiveOutboundTrunkId }, "[buy-number] recreated LiveKit outbound trunk after addNumber failed");
              } else {
                logger.warn({ trunkId: effectiveOutboundTrunkId, err: String(e?.message || e) }, "[buy-number] failed to add number to trunk (may already be there)");
              }
            }
          }
        }

        // 3e) Persist trunk IDs on the workspace.
        await store.updateWorkspace(ws.id, {
          twilioSipTrunkSid: trunkSid,
          twilioSipDomainName: domainName,
          twilioSipCredUsername: credUsername,
          twilioSipCredPassword: credPassword,
          livekitOutboundTrunkId: effectiveOutboundTrunkId,
        });
      } catch (e) {
        const msg = String(e?.message || e);
        logger.warn({ e164: purchased.phoneNumber, err: msg }, "[buy-number] outbound trunk auto-provision failed");
        provisionErrors.push(`Outbound trunk: ${msg}`);

        // Fallback: try the env-based trunk ID.
        if (outboundTrunkId && outboundTrunkId !== effectiveOutboundTrunkId) {
          try {
            await addNumberToOutboundTrunk(outboundTrunkId, purchased.phoneNumber);
            effectiveOutboundTrunkId = outboundTrunkId;
            logger.info({ e164: purchased.phoneNumber, trunkId: outboundTrunkId }, "[buy-number] added to fallback outbound trunk");
          } catch (fallbackErr) {
            logger.warn({ err: String(fallbackErr?.message || fallbackErr) }, "[buy-number] fallback outbound trunk also failed");
          }
        }
      }

      // 4) Update status to active (or partially configured if errors)
      const newStatus = provisionErrors.length === 0 ? "active" : "partial";
      phoneNumber = await store.updatePhoneNumber(phoneNumber.id, {
        status: newStatus,
        livekitInboundTrunkId: effectiveInboundTrunkId || null,
        livekitOutboundTrunkId: effectiveOutboundTrunkId || outboundTrunkId || null,
      });

      return res.status(201).json({
        phoneNumber,
        purchased,
        provisioned: provisionErrors.length === 0,
        provisionErrors: provisionErrors.length > 0 ? provisionErrors : undefined,
      });
    }

    const rows = readPhoneNumbers();
    const now = Date.now();
    const phoneNumber = {
      id: nanoid(10),
      workspaceId: ws.id,
      e164: purchased.phoneNumber,
      label: parsed.data.label ?? "",
      provider: "twilio",
      status: "active",
      twilioNumberSid: purchased.sid,
      livekitInboundTrunkId: inboundTrunkId || null,
      livekitOutboundTrunkId: outboundTrunkId || null,
      inboundAgentId: null,
      outboundAgentId: null,
      allowedInboundCountries: ["all"],
      allowedOutboundCountries: ["all"],
      createdAt: now,
      updatedAt: now,
    };
    writePhoneNumbers([phoneNumber, ...rows]);
    return res.status(201).json({ phoneNumber, purchased });
  } catch (e) {
    return res.status(400).json({ error: e instanceof Error ? e.message : "Buy failed" });
  }
});

// --- Phone Numbers (Phase 1) ---
app.get("/api/phone-numbers", requireAuth, async (req, res) => {
  const workspaceId = req.workspace.id;

  if (USE_DB) {
    const phoneNumbers = await store.listPhoneNumbers(workspaceId);
    return res.json({ phoneNumbers });
  }

  const rows = readPhoneNumbers().filter((p) => p.workspaceId === workspaceId);
  rows.sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
  return res.json({ phoneNumbers: rows });
});

app.post("/api/phone-numbers", requireAuth, async (req, res) => {
  const schema = z.object({
    e164: z.string().min(3).max(32),
    label: z.string().max(120).optional(),
    provider: z.enum(["twilio"]).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  }

  const workspaceId = req.workspace.id;

  if (USE_DB) {
    try {
      let e164 = String(parsed.data.e164).trim();
      if (!e164.startsWith("+")) e164 = `+${e164}`;

      let phoneNumber = await store.createPhoneNumber({
        workspaceId,
        e164,
        label: parsed.data.label ?? "",
        provider: parsed.data.provider ?? "twilio",
        status: "unconfigured",
        allowedInboundCountries: ["all"],
        allowedOutboundCountries: ["all"],
      });

      // Auto-add to LiveKit inbound and outbound trunks (no Twilio changes).
      const ws = req.workspace;
      const inboundTrunkIdEnv = String(process.env.SIP_INBOUND_TRUNK_ID || "").trim();
      const outboundTrunkIdEnv = String(process.env.SIP_OUTBOUND_TRUNK_ID || "").trim();
      let effectiveInboundTrunkId = ws.livekitInboundTrunkId || inboundTrunkIdEnv || null;
      let effectiveOutboundTrunkId = ws.livekitOutboundTrunkId || outboundTrunkIdEnv || null;
      const provisionErrors = [];

      if (!effectiveInboundTrunkId) {
        try {
          const inboundResult = await createInboundTrunkForWorkspace({
            workspaceId,
            numbers: [e164],
          });
          effectiveInboundTrunkId = inboundResult.trunkId;
          await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
        } catch (e) {
          const existingTrunkId = parseConflictingInboundTrunkId(e);
          if (existingTrunkId) {
            effectiveInboundTrunkId = existingTrunkId;
            await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
            try {
              await addNumberToInboundTrunk(effectiveInboundTrunkId, e164);
            } catch (addErr) {
              provisionErrors.push(`Inbound add: ${addErr?.message || addErr}`);
            }
          } else {
            provisionErrors.push(`Inbound trunk: ${e?.message || e}`);
          }
        }
      } else {
        try {
          await addNumberToInboundTrunk(effectiveInboundTrunkId, e164);
        } catch (e) {
          const msg = String(e?.message ?? e?.error ?? e ?? "").toLowerCase();
          const isAlready = msg.includes("already") || msg.includes("duplicate");
          const isTrunkMissing = isTrunkNotFoundError(e) || e?.code === "TRUNK_NOT_FOUND" || msg.includes("object cannot be found") || (msg.includes("twirp") && msg.includes("not found"));
          if (isAlready) {
            // Number already on trunk — ok (e.g. connect-via-SIP retry or manual add)
          } else if (isTrunkMissing) {
            try {
              const inboundResult = await createInboundTrunkForWorkspace({ workspaceId, numbers: [e164] });
              effectiveInboundTrunkId = inboundResult.trunkId;
              await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
            } catch (createErr) {
              const existingTrunkId = parseConflictingInboundTrunkId(createErr);
              if (existingTrunkId) {
                effectiveInboundTrunkId = existingTrunkId;
                await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
              } else {
                provisionErrors.push(`Inbound trunk: ${createErr?.message || createErr}`);
              }
            }
          } else {
            provisionErrors.push(`Inbound trunk: ${msg}`);
          }
        }
      }

      if (effectiveOutboundTrunkId) {
        try {
          await addNumberToOutboundTrunk(effectiveOutboundTrunkId, e164);
        } catch (e) {
          provisionErrors.push(`Outbound trunk: ${e?.message || e}`);
        }
      } else {
        provisionErrors.push("Outbound trunk: no workspace or env outbound trunk configured");
      }

      const newStatus = provisionErrors.length === 0 ? "active" : "partial";
      phoneNumber = await store.updatePhoneNumber(phoneNumber.id, {
        status: newStatus,
        livekitInboundTrunkId: effectiveInboundTrunkId || null,
        livekitOutboundTrunkId: effectiveOutboundTrunkId || null,
      });

      if (provisionErrors.length > 0) {
        logger.warn({ phoneNumberId: phoneNumber.id, e164, provisionErrors }, "[phone-numbers] auto-add to LiveKit trunks had errors");
      }

      return res.status(201).json({
        phoneNumber,
        provisionErrors: provisionErrors.length > 0 ? provisionErrors : undefined,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Create phone number failed";
      return res.status(400).json({ error: msg });
    }
  }

  const rows = readPhoneNumbers();
  const now = Date.now();
  const phoneNumber = {
    id: nanoid(10),
    workspaceId,
    e164: parsed.data.e164,
    label: parsed.data.label ?? "",
    provider: parsed.data.provider ?? "twilio",
    status: "unconfigured",
    twilioNumberSid: null,
    inboundAgentId: null,
    outboundAgentId: null,
    allowedInboundCountries: ["all"],
    allowedOutboundCountries: ["all"],
    createdAt: now,
    updatedAt: now,
  };
  writePhoneNumbers([phoneNumber, ...rows]);
  return res.status(201).json({ phoneNumber });
});

app.get("/api/phone-numbers/:id", requireAuth, async (req, res) => {
  const id = String(req.params.id);
  if (USE_DB) {
    const phoneNumber = await store.getPhoneNumber(id);
    if (!phoneNumber) return res.status(404).json({ error: "Not found" });
    if (phoneNumber.workspaceId !== req.workspace.id) return res.status(404).json({ error: "Not found" });
    return res.json({ phoneNumber });
  }
  const phoneNumber = readPhoneNumbers().find((p) => p.id === id);
  if (!phoneNumber) return res.status(404).json({ error: "Not found" });
  if (phoneNumber.workspaceId !== req.workspace.id) return res.status(404).json({ error: "Not found" });
  return res.json({ phoneNumber });
});

// Ensure a phone number is on the LiveKit inbound trunk (for "connect via SIP" numbers where inbound was missing).
app.post("/api/phone-numbers/:id/ensure-inbound", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Ensure-inbound requires Postgres mode" });
  const id = String(req.params.id);
  const phoneNumber = await store.getPhoneNumber(id);
  if (!phoneNumber || phoneNumber.workspaceId !== req.workspace.id) return res.status(404).json({ error: "Not found" });
  const e164 = String(phoneNumber.e164 || "").trim();
  if (!e164) return res.status(400).json({ error: "Phone number has no E.164" });
  const ws = req.workspace;
  const workspaceId = ws.id;
  const inboundTrunkIdEnv = String(process.env.SIP_INBOUND_TRUNK_ID || "").trim();
  let effectiveInboundTrunkId = ws.livekitInboundTrunkId || inboundTrunkIdEnv || null;
  const errors = [];
  if (!effectiveInboundTrunkId) {
    try {
      const inboundResult = await createInboundTrunkForWorkspace({ workspaceId, numbers: [e164] });
      effectiveInboundTrunkId = inboundResult.trunkId;
      await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
      logger.info({ e164, trunkId: effectiveInboundTrunkId }, "[ensure-inbound] created inbound trunk and added number");
    } catch (e) {
      const existingTrunkId = parseConflictingInboundTrunkId(e);
      if (existingTrunkId) {
        effectiveInboundTrunkId = existingTrunkId;
        await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
        try {
          await addNumberToInboundTrunk(effectiveInboundTrunkId, e164);
        } catch (addErr) {
          errors.push(String(addErr?.message || addErr));
        }
      } else {
        errors.push(String(e?.message || e));
      }
    }
  } else {
    try {
      await addNumberToInboundTrunk(effectiveInboundTrunkId, e164);
      logger.info({ e164, trunkId: effectiveInboundTrunkId }, "[ensure-inbound] added number to existing inbound trunk");
    } catch (e) {
      const msg = String(e?.message ?? e?.error ?? e ?? "").toLowerCase();
      const isAlready = msg.includes("already") || msg.includes("duplicate");
      const isTrunkMissing = isTrunkNotFoundError(e) || msg.includes("object cannot be found") || (msg.includes("twirp") && msg.includes("not found"));
      if (isAlready) {
        // Already on trunk — success
      } else if (isTrunkMissing) {
        try {
          const inboundResult = await createInboundTrunkForWorkspace({ workspaceId, numbers: [e164] });
          effectiveInboundTrunkId = inboundResult.trunkId;
          await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
          logger.info({ e164, trunkId: effectiveInboundTrunkId }, "[ensure-inbound] recreated inbound trunk and added number");
        } catch (createErr) {
          const existingTrunkId = parseConflictingInboundTrunkId(createErr);
          if (existingTrunkId) {
            effectiveInboundTrunkId = existingTrunkId;
            await store.updateWorkspace(ws.id, { livekitInboundTrunkId: effectiveInboundTrunkId });
          } else {
            errors.push(String(createErr?.message || createErr));
          }
        }
      } else {
        errors.push(String(e?.message || e));
      }
    }
  }
  if (effectiveInboundTrunkId) {
    await store.updatePhoneNumber(id, { livekitInboundTrunkId: effectiveInboundTrunkId });
  }
  const updated = await store.getPhoneNumber(id);
  if (errors.length > 0) {
    return res.status(207).json({ phoneNumber: updated, ok: false, errors });
  }
  return res.json({ phoneNumber: updated, ok: true });
});

app.put("/api/phone-numbers/:id", requireAuth, async (req, res) => {
  const id = String(req.params.id);
  const schema = z.object({
    label: z.string().max(120).optional(),
    inboundAgentId: z.string().min(1).nullable().optional(),
    outboundAgentId: z.string().min(1).nullable().optional(),
    livekitInboundTrunkId: z.string().min(1).nullable().optional(),
    livekitOutboundTrunkId: z.string().min(1).nullable().optional(),
    livekitSipUsername: z.string().min(1).nullable().optional(),
    livekitSipPassword: z.string().min(1).nullable().optional(),
    sipTerminationUri: z.string().max(512).nullable().optional(),
    sipOutboundTransport: z.enum(["tcp", "udp", "tls"]).nullable().optional(),
    allowedInboundCountries: z.union([z.array(z.string()), z.string()]).optional(),
    allowedOutboundCountries: z.union([z.array(z.string()), z.string()]).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  }

  // IMPORTANT: only apply fields the client actually sent.
  // Otherwise undefined values would overwrite existing values (e.g. saving trunk clears agent).
  const patch = stripUndefined({
    label: parsed.data.label,
    inboundAgentId: parsed.data.inboundAgentId,
    outboundAgentId: parsed.data.outboundAgentId,
    livekitInboundTrunkId: parsed.data.livekitInboundTrunkId,
    livekitOutboundTrunkId: parsed.data.livekitOutboundTrunkId,
    livekitSipUsername: parsed.data.livekitSipUsername,
    livekitSipPassword: parsed.data.livekitSipPassword,
    sipTerminationUri: parsed.data.sipTerminationUri,
    sipOutboundTransport: parsed.data.sipOutboundTransport,
    allowedInboundCountries:
      parsed.data.allowedInboundCountries === undefined ? undefined : normalizeCountries(parsed.data.allowedInboundCountries),
    allowedOutboundCountries:
      parsed.data.allowedOutboundCountries === undefined ? undefined : normalizeCountries(parsed.data.allowedOutboundCountries),
  });

  if (USE_DB) {
    const existing = await store.getPhoneNumber(id);
    if (!existing || existing.workspaceId !== req.workspace.id) return res.status(404).json({ error: "Not found" });
    const phoneNumber = await store.updatePhoneNumber(id, patch);
    if (!phoneNumber) return res.status(404).json({ error: "Not found" });
    return res.json({ phoneNumber });
  }

  const rows = readPhoneNumbers();
  const idx = rows.findIndex((p) => p.id === id);
  if (idx < 0) return res.status(404).json({ error: "Not found" });
  const current = rows[idx];
  if (current.workspaceId !== req.workspace.id) return res.status(404).json({ error: "Not found" });
  const next = { ...current, ...patch, updatedAt: Date.now() };
  rows[idx] = next;
  writePhoneNumbers(rows);
  return res.json({ phoneNumber: next });
});

app.delete("/api/phone-numbers/:id", requireAuth, async (req, res) => {
  const id = String(req.params.id);
  if (USE_DB) {
    const existing = await store.getPhoneNumber(id);
    if (!existing || existing.workspaceId !== req.workspace.id) return res.status(404).json({ error: "Not found" });

    const e164 = existing.e164;
    const inTrunk = existing.livekitInboundTrunkId || String(process.env.SIP_INBOUND_TRUNK_ID || "").trim();
    const outTrunk = existing.livekitOutboundTrunkId || String(process.env.SIP_OUTBOUND_TRUNK_ID || "").trim();

    // Best-effort: remove number from LiveKit SIP trunks
    if (inTrunk && e164) {
      try { await removeNumberFromInboundTrunk(inTrunk, e164); } catch (e) {
        logger.warn({ e164, err: String(e?.message || e) }, "[delete-number] failed to remove from inbound trunk");
      }
    }
    if (outTrunk && e164) {
      if (existing.provider === "sip") {
        try { await deleteOutboundTrunk(outTrunk); } catch (e) {
          logger.warn({ e164, err: String(e?.message || e) }, "[delete-number] failed to delete SIP outbound trunk");
        }
      } else {
        try { await removeNumberFromOutboundTrunk(outTrunk, e164); } catch (e) {
          logger.warn({ e164, err: String(e?.message || e) }, "[delete-number] failed to remove from outbound trunk");
        }
      }
    }

    // Best-effort: release the number on Twilio
    if (existing.twilioNumberSid && req.workspace.twilioSubaccountSid) {
      try {
        const client = tw.getSubaccountClient(req.workspace.twilioSubaccountSid);
        if (client) await client.incomingPhoneNumbers(existing.twilioNumberSid).remove();
        logger.info({ e164 }, "[delete-number] released on Twilio");
      } catch (e) {
        logger.warn({ e164, err: String(e?.message || e) }, "[delete-number] failed to release on Twilio");
      }
    }

    await store.deletePhoneNumber(id);
    return res.json({ ok: true });
  }
  const rows = readPhoneNumbers().filter((p) => p.id !== id);
  writePhoneNumbers(rows);
  return res.json({ ok: true });
});

// --- Reset workspace Twilio data (needed when switching Twilio accounts) ---
app.post("/api/workspaces/:id/reset-twilio", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Requires Postgres mode" });
  const ws = req.workspace;
  if (!ws || ws.id !== req.params.id) {
    return res.status(404).json({ error: "Workspace not found" });
  }
  try {
    const p = getPool();
    await p.query(`
      UPDATE workspaces SET
        twilio_subaccount_sid = NULL,
        twilio_sip_trunk_sid = NULL,
        twilio_sip_domain_name = NULL,
        twilio_sip_cred_username = NULL,
        twilio_sip_cred_password = NULL,
        livekit_outbound_trunk_id = NULL,
        livekit_inbound_trunk_id = NULL,
        updated_at = $2
      WHERE id = $1
    `, [ws.id, Date.now()]);
    // Also clear the phone numbers' trunk references
    await p.query(`
      UPDATE phone_numbers SET
        livekit_outbound_trunk_id = NULL,
        livekit_inbound_trunk_id = NULL
      WHERE workspace_id = $1
    `, [ws.id]);
    console.log(`[reset-twilio] ✓ Cleared all Twilio/LiveKit references for workspace ${ws.id}`);
    return res.json({ ok: true, message: "Twilio data cleared. Reprovision your phone numbers to set up the new account." });
  } catch (e) {
    console.error(`[reset-twilio] Failed: ${e?.message || e}`);
    return res.status(500).json({ error: e?.message || "Failed to reset Twilio data" });
  }
});

// --- Reprovision SIP trunk for a phone number (fixes Caller ID 403 + inbound no-audio) ---
app.post("/api/phone-numbers/:id/reprovision-outbound", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Requires Postgres mode" });
  const phoneNumber = await store.getPhoneNumber(req.params.id);
  if (!phoneNumber || phoneNumber.workspaceId !== req.workspace.id) {
    return res.status(404).json({ error: "Phone number not found" });
  }
  const ws = req.workspace;
  if (!ws.twilioSubaccountSid) {
    return res.status(400).json({ error: "Workspace has no Twilio subaccount" });
  }

  const sipEndpoint = String(process.env.LIVEKIT_SIP_ENDPOINT || "").trim();
  const provisionErrors = [];
  if (!sipEndpoint) {
    console.warn("[reprovision-outbound] LIVEKIT_SIP_ENDPOINT is not set — inbound calls will fail (Twilio trunking issue). Set it to your LiveKit SIP host, e.g. 25f6q0vix3k.sip.livekit.cloud");
    provisionErrors.push("LIVEKIT_SIP_ENDPOINT is not set. Inbound calls require it. Set to your LiveKit SIP host (e.g. 25f6q0vix3k.sip.livekit.cloud).");
  }
  try {
      // 1) Ensure Twilio SIP trunk (with secure trunking + call transfer).
      const { trunkSid, domainName, secure } = await tw.ensureSipTrunk({
        subaccountSid: ws.twilioSubaccountSid,
        existingTrunkSid: ws.twilioSipTrunkSid,
        workspaceId: ws.id,
      });
      // IMPORTANT: Twilio "secure" only controls SRTP (disabled because LiveKit doesn't support it).
      // Always use TLS signaling on LiveKit side (transport=3).
      const isSecure = true; // Always TLS signaling, regardless of Twilio SRTP setting

      // 2) Ensure termination credentials (and ensure they're associated with the Twilio trunk).
      const { credUsername, credPassword } = await tw.ensureSipTrunkTerminationCreds({
        subaccountSid: ws.twilioSubaccountSid,
        trunkSid,
        existingUsername: ws.twilioSipCredUsername,
        existingPassword: ws.twilioSipCredPassword,
      });
      
      // If credentials changed, LiveKit trunk must be recreated with new credentials
      const credentialsChanged = credUsername !== ws.twilioSipCredUsername || credPassword !== ws.twilioSipCredPassword;
      if (credentialsChanged) {
        console.log(`[reprovision-outbound] Credentials changed (old: ${ws.twilioSipCredUsername}, new: ${credUsername}) — LiveKit trunk will be recreated`);
      }

      // 3) Associate the phone number with the Twilio trunk.
      try {
        await tw.associateNumberWithSipTrunk({
          subaccountSid: ws.twilioSubaccountSid,
          trunkSid,
          numberSid: phoneNumber.twilioNumberSid,
        });
      } catch (e) {
        if (!String(e?.message || "").includes("already associated")) {
          provisionErrors.push(`Associate number: ${e?.message || e}`);
        }
      }

    // 3b) Ensure Origination URI → LiveKit SIP endpoint (required for inbound calls).
    if (sipEndpoint) {
      const expectedSipUrl = `sip:${sipEndpoint};transport=tls`;
      console.log(`[reprovision-outbound] Setting Twilio trunk origination for inbound: ${expectedSipUrl}`);
      try {
        await tw.ensureSipTrunkOriginationUri({
          subaccountSid: ws.twilioSubaccountSid,
          trunkSid,
          sipEndpoint,
          secure: isSecure,
        });
        console.log(`[reprovision-outbound] ✓ Origination URI set — inbound calls will route to LiveKit`);
      } catch (e) {
        console.warn(`[reprovision-outbound] Origination URI failed: ${e?.message || e}`);
        provisionErrors.push(`Origination URI: ${e?.message || e}`);
      }
    }

    // 3c) IP Access Control List — only if LIVEKIT_SIP_IP_ADDRESSES is set.
    // If NOT set, remove any existing ACLs to avoid blocking LiveKit's dynamic IPs.
    // Authentication is handled by termination credentials, so IP ACL is optional.
    const sipIpAddresses = String(process.env.LIVEKIT_SIP_IP_ADDRESSES || "").trim();
    if (sipIpAddresses) {
      try {
        const ipList = sipIpAddresses.split(",").map((ip) => ip.trim()).filter(Boolean);
        if (ipList.length > 0) {
          const aclResult = await tw.ensureSipTrunkIpAcl({
            subaccountSid: ws.twilioSubaccountSid,
            trunkSid,
            ipAddresses: ipList,
          });
          console.log(`[reprovision-outbound] IP ACL configured: ${aclResult.aclSid}, ${aclResult.ipAddressesAdded} IPs added, ${aclResult.totalIps} total`);
        }
      } catch (e) {
        console.warn(`[reprovision-outbound] Failed to configure IP ACL: ${e?.message || e}`);
        provisionErrors.push(`IP ACL: ${e?.message || e}`);
      }
    } else {
      // No IP list → remove any existing ACLs so they don't block calls
      console.log(`[reprovision-outbound] LIVEKIT_SIP_IP_ADDRESSES not set — removing IP ACL restrictions (credentials handle auth)`);
      try {
        await tw.removeAllSipTrunkIpAcls({ subaccountSid: ws.twilioSubaccountSid, trunkSid });
      } catch (e) {
        console.warn(`[reprovision-outbound] Failed to remove IP ACLs (best-effort): ${e?.message || e}`);
      }
    }

    // 4) Create or reuse LiveKit outbound trunk.
    // CRITICAL: Check transport and address match Twilio configuration.
    const targetTransport = isSecure ? 3 : 2; // TLS (3) if secure, TCP (2) if not — LiveKit SIPTransport: 0=AUTO, 1=UDP, 2=TCP, 3=TLS
    const targetName = isSecure ? 'TLS' : 'TCP';
    let lkTrunkId = ws.livekitOutboundTrunkId;
    let needsRecreate = false;
    
    if (lkTrunkId) {
      // Check current transport and address - if they don't match, recreate
      try {
        const trunkInfo = await getOutboundTrunkInfo(lkTrunkId);
        const currentTransport = trunkInfo?.transport ?? null;
        const currentAddress = trunkInfo?.outboundAddress || trunkInfo?.address || null;
        
        console.log(`[reprovision-outbound] Current trunk ${lkTrunkId} transport: ${currentTransport} (0=AUTO, 1=UDP, 2=TCP, 3=TLS), target: ${targetTransport} (${targetName}), secure: ${isSecure}`);
        console.log(`[reprovision-outbound] Current trunk ${lkTrunkId} address: ${currentAddress}, Twilio termination URI: ${domainName}`);
        
        // Check if address matches Twilio termination URI
        if (currentAddress && currentAddress !== domainName) {
          console.log(`[reprovision-outbound] Trunk ${lkTrunkId} address "${currentAddress}" doesn't match Twilio termination URI "${domainName}". Will try to update, or recreate if update fails...`);
          // Try to update the address first
          try {
            await ensureOutboundTrunkAddress(lkTrunkId, domainName);
            console.log(`[reprovision-outbound] ✓ Successfully updated trunk ${lkTrunkId} address to match Twilio termination URI`);
          } catch (e) {
            if (isTrunkNotFoundError(e) || e?.code === "TRUNK_NOT_FOUND") {
              console.warn(`[reprovision-outbound] Trunk ${lkTrunkId} doesn't exist in LiveKit: ${e?.message || e}. Will recreate...`);
            } else {
              console.warn(`[reprovision-outbound] Failed to update trunk address: ${e?.message || e}. Will recreate trunk...`);
            }
            needsRecreate = true;
          }
        } else if (!currentAddress) {
          console.warn(`[reprovision-outbound] Trunk ${lkTrunkId} has no address set. Will recreate...`);
          needsRecreate = true;
        }
        
        if (currentTransport !== targetTransport) {
          // Transport doesn't match - need to recreate
          console.log(`[reprovision-outbound] Trunk ${lkTrunkId} uses transport ${currentTransport} (${currentTransport === 3 ? 'TLS' : currentTransport === 2 ? 'TCP' : currentTransport === 1 ? 'UDP' : currentTransport === 0 ? 'AUTO' : 'unknown'}), must be ${targetName} (${targetTransport}). Recreating...`);
          needsRecreate = true;
        } else if (!needsRecreate) {
          // Already correct transport and address, but try updating anyway to ensure it's correct
          console.log(`[reprovision-outbound] Trunk ${lkTrunkId} already reports ${targetName} (${targetTransport}) and correct address, but ensuring it's correct...`);
          try {
            // Ensure address matches (in case it was updated in Twilio)
            await ensureOutboundTrunkAddress(lkTrunkId, domainName);
            await ensureOutboundTrunkTransport(lkTrunkId, isSecure);
            // Verify it's still correct after update
            const verifyInfo = await getOutboundTrunkInfo(lkTrunkId);
            const verifyAddress = verifyInfo?.outboundAddress || verifyInfo?.address || null;
            if (verifyInfo?.transport !== targetTransport || verifyAddress !== domainName) {
              console.warn(`[reprovision-outbound] Update didn't work - transport is ${verifyInfo?.transport}, address is "${verifyAddress}". Recreating...`);
              needsRecreate = true;
            }
          } catch (e) {
            if (isTrunkNotFoundError(e) || e?.code === "TRUNK_NOT_FOUND") {
              console.warn(`[reprovision-outbound] Trunk ${lkTrunkId} doesn't exist in LiveKit: ${e?.message || e}. Will recreate...`);
            } else {
              console.warn(`[reprovision-outbound] Failed to update trunk: ${e?.message || e}. Recreating...`);
            }
            needsRecreate = true;
          }
        }
      } catch (e) {
        // Check if this is a "trunk not found" error
        if (isTrunkNotFoundError(e) || e?.code === "TRUNK_NOT_FOUND") {
          console.warn(`[reprovision-outbound] Trunk ${lkTrunkId} doesn't exist in LiveKit: ${e?.message || e}. Will recreate...`);
        } else {
          console.warn(`[reprovision-outbound] Could not check trunk ${lkTrunkId} state: ${e?.message || e}. Recreating...`);
        }
        needsRecreate = true;
      }
    }
    
    // Force recreate if credentials changed
    if (credentialsChanged && !needsRecreate) {
      console.log(`[reprovision-outbound] Forcing trunk recreation due to credential change`);
      needsRecreate = true;
    }
    
    if (!lkTrunkId || needsRecreate) {
      // Delete old trunk if recreating
      if (needsRecreate && lkTrunkId) {
        try {
          console.log(`[reprovision-outbound] Deleting trunk ${lkTrunkId} before recreation`);
          await deleteOutboundTrunk(lkTrunkId);
          // Wait for deletion to propagate
          await new Promise((resolve) => setTimeout(resolve, 2000));
        } catch (e) {
          console.warn(`[reprovision-outbound] Failed to delete old trunk (may not exist): ${e?.message || e}`);
          // Continue anyway - recreation will create a new trunk
        }
        lkTrunkId = null; // Clear so we create a new one
      }
      
      // Create new trunk with correct transport
      console.log(`[reprovision-outbound] Creating new LiveKit outbound trunk with ${targetName} transport (${targetTransport}), secure: ${isSecure}`);
      const result = await createOutboundTrunkForWorkspace({
        workspaceId: ws.id,
        twilioSipDomainName: domainName,
        credUsername,
        credPassword,
        numbers: [phoneNumber.e164],
        secure: isSecure,
      });
      lkTrunkId = result.trunkId;
      console.log(`[reprovision-outbound] ✓ Created new trunk ${lkTrunkId} with ${targetName} transport (${targetTransport})`);
      
      // Verify the new trunk actually has the correct transport and address
      try {
        const verifyNew = await getOutboundTrunkInfo(lkTrunkId);
        const verifyAddress = verifyNew?.outboundAddress || verifyNew?.address || null;
        if (verifyNew?.transport !== targetTransport) {
          console.error(`[reprovision-outbound] WARNING: New trunk ${lkTrunkId} was created but transport is ${verifyNew?.transport} instead of ${targetTransport} (${targetName})!`);
          provisionErrors.push(`New trunk created but transport verification failed: got ${verifyNew?.transport}, expected ${targetTransport}`);
        } else {
          console.log(`[reprovision-outbound] ✓ Verified new trunk ${lkTrunkId} uses ${targetName} transport (${targetTransport})`);
        }
        if (verifyAddress !== domainName) {
          console.error(`[reprovision-outbound] WARNING: New trunk ${lkTrunkId} address "${verifyAddress}" doesn't match Twilio termination URI "${domainName}"!`);
          provisionErrors.push(`New trunk created but address verification failed: got "${verifyAddress}", expected "${domainName}"`);
        } else {
          console.log(`[reprovision-outbound] ✓ Verified new trunk ${lkTrunkId} address matches Twilio termination URI "${domainName}"`);
        }
      } catch (e) {
        console.warn(`[reprovision-outbound] Could not verify new trunk: ${e?.message || e}`);
      }
    } else {
      // Trunk exists and has correct transport - just ensure the number is added
      try {
        await addNumberToOutboundTrunk(lkTrunkId, phoneNumber.e164);
      } catch { /* may already be there */ }
    }

    // 5) Ensure LiveKit inbound trunk exists (needed for receiving inbound calls)
    const inboundTrunkId = process.env.SIP_INBOUND_TRUNK_ID || null;
    let effectiveInboundTrunkId = inboundTrunkId || ws.livekitInboundTrunkId;
    if (!effectiveInboundTrunkId) {
      try {
        console.log(`[reprovision-outbound] Auto-creating LiveKit inbound trunk for workspace ${ws.id}`);
        const inboundResult = await createInboundTrunkForWorkspace({
          workspaceId: ws.id,
          numbers: [phoneNumber.e164],
        });
        effectiveInboundTrunkId = inboundResult.trunkId;
        console.log(`[reprovision-outbound] ✓ Created inbound trunk ${effectiveInboundTrunkId}`);
      } catch (e) {
        const existingTrunkId = parseConflictingInboundTrunkId(e);
        if (existingTrunkId) {
          effectiveInboundTrunkId = existingTrunkId;
          console.log(`[reprovision-outbound] ✓ Number already on existing inbound trunk ${existingTrunkId}, using it`);
        } else {
          console.warn(`[reprovision-outbound] Failed to create inbound trunk: ${e?.message || e}`);
          provisionErrors.push(`Inbound trunk creation: ${e?.message || e}`);
        }
      }
    } else {
      // Ensure the phone number is registered on the existing inbound trunk
      try {
        await addNumberToInboundTrunk(effectiveInboundTrunkId, phoneNumber.e164);
        console.log(`[reprovision-outbound] ✓ Added ${phoneNumber.e164} to inbound trunk ${effectiveInboundTrunkId}`);
      } catch (e) {
        const msg = String(e?.message ?? e?.error ?? e ?? "").toLowerCase();
        const isAlready = msg.includes("already") || msg.includes("duplicate");
        const isTrunkMissing = isTrunkNotFoundError(e) || e?.code === "TRUNK_NOT_FOUND" || msg.includes("object cannot be found") || (msg.includes("twirp") && msg.includes("not found"));
        if (isAlready) {
          // Number already on trunk — ok
        } else if (isTrunkMissing) {
          // Inbound trunk no longer exists in LiveKit — create a new one or use existing that has this number
          console.warn(`[reprovision-outbound] Inbound trunk ${effectiveInboundTrunkId} not found in LiveKit, creating new one`);
          effectiveInboundTrunkId = null;
          try {
            const inboundResult = await createInboundTrunkForWorkspace({
              workspaceId: ws.id,
              numbers: [phoneNumber.e164],
            });
            effectiveInboundTrunkId = inboundResult.trunkId;
            console.log(`[reprovision-outbound] ✓ Created new inbound trunk ${effectiveInboundTrunkId}`);
          } catch (createErr) {
            const existingTrunkId = parseConflictingInboundTrunkId(createErr);
            if (existingTrunkId) {
              effectiveInboundTrunkId = existingTrunkId;
              console.log(`[reprovision-outbound] ✓ Number already on existing inbound trunk ${existingTrunkId}, using it`);
            } else {
              console.warn(`[reprovision-outbound] Failed to create inbound trunk: ${createErr?.message || createErr}`);
              provisionErrors.push(`Inbound trunk creation: ${createErr?.message || createErr}`);
            }
          }
        } else {
          console.warn(`[reprovision-outbound] Failed to add number to inbound trunk: ${e?.message || e}`);
          provisionErrors.push(`Inbound trunk: ${e?.message || e}`);
        }
      }
    }

    // 6) Configure Twilio voice URL for inbound calls (TwiML webhook)
    if (sipEndpoint && phoneNumber.twilioNumberSid) {
      try {
        await tw.configureNumberForSip({
          subaccountSid: ws.twilioSubaccountSid,
          numberSid: phoneNumber.twilioNumberSid,
          e164: phoneNumber.e164,
          sipEndpoint,
        });
        console.log(`[reprovision-outbound] ✓ Configured Twilio voice URL for ${phoneNumber.e164}`);
      } catch (e) {
        console.warn(`[reprovision-outbound] Failed to configure voice URL: ${e?.message || e}`);
        provisionErrors.push(`Voice URL: ${e?.message || e}`);
      }
    }

    // 7) Persist. Clear stale inbound trunk ID when we recreated (or failed to create) so next run doesn't retry old ID.
    const updateData = {
      twilioSipTrunkSid: trunkSid,
      twilioSipDomainName: domainName,
      twilioSipCredUsername: credUsername,
      twilioSipCredPassword: credPassword,
      livekitOutboundTrunkId: lkTrunkId,
    };
    if (effectiveInboundTrunkId) {
      updateData.livekitInboundTrunkId = effectiveInboundTrunkId;
    } else {
      await getPool().query("UPDATE workspaces SET livekit_inbound_trunk_id = NULL WHERE id = $1", [ws.id]);
    }
    await store.updateWorkspace(ws.id, updateData);

    // Update phone number status: "active" if no errors, keep "partial" if some steps failed
    const newStatus = provisionErrors.length === 0 ? "active" : "partial";
    await store.updatePhoneNumber(phoneNumber.id, {
      livekitOutboundTrunkId: lkTrunkId,
      livekitInboundTrunkId: effectiveInboundTrunkId || undefined,
      status: newStatus,
    });
    console.log(`[reprovision-outbound] ✓ Phone number ${phoneNumber.e164} status → ${newStatus}`);

    return res.json({
      ok: true,
      status: newStatus,
      trunkId: lkTrunkId,
      inboundTrunkId: effectiveInboundTrunkId || null,
      twilioTrunkSid: trunkSid,
      domainName,
      errors: provisionErrors.length ? provisionErrors : undefined,
    });
  } catch (e) {
    logger.warn({ err: String(e?.message || e) }, "[reprovision-outbound] failed");
    return res.status(500).json({ error: e instanceof Error ? e.message : "Reprovisioning failed" });
  }
});

// --- Check IP addresses from Twilio calls (for debugging SIP ACL issues) ---
app.get("/api/twilio/calls/:callSid/ips", requireAuth, async (req, res) => {
  const { callSid } = req.params;
  if (!callSid || !callSid.startsWith("CA")) {
    return res.status(400).json({ error: "Invalid Twilio Call SID" });
  }
  
  try {
    const ws = req.workspace;
    const ipInfo = await tw.getCallIpAddresses({
      callSid,
      subaccountSid: ws.twilioSubaccountSid || undefined,
    });
    
    return res.json(ipInfo);
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Failed to fetch IP addresses" });
  }
});

app.get("/api/twilio/workspaces/:id/recent-call-ips", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Requires Postgres mode" });
  
  const workspaceId = req.params.id;
  if (workspaceId !== req.workspace.id) {
    return res.status(403).json({ error: "Access denied" });
  }
  
  const ws = req.workspace;
  if (!ws.twilioSipTrunkSid) {
    return res.status(400).json({ error: "Workspace has no Twilio SIP trunk" });
  }
  
  const limit = req.query.limit ? Number(req.query.limit) : 10;
  
  try {
    const result = await tw.getIpAddressesFromRecentCalls({
      trunkSid: ws.twilioSipTrunkSid,
      subaccountSid: ws.twilioSubaccountSid || undefined,
      limit: Math.min(limit, 50),
    });
    
    return res.json(result);
  } catch (e) {
    return res.status(500).json({ error: e?.message || "Failed to fetch IP addresses" });
  }
});

// --- Outbound Jobs (MVP) ---
// Accept either (agentId, phoneE164, metadata) or Retell-style (from_number, to_number, agent_id, rapidcall_llm_dynamic_variables).
// Dynamic variables are used for {{VarName}} in the agent prompt and sent in webhooks as rapidcall_llm_dynamic_variables.
app.post("/api/outbound/jobs", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Outbound jobs require Postgres mode" });
  const schema = z.object({
    agentId: z.string().min(1).max(40).optional(),
    agent_id: z.string().min(1).max(40).optional(),
    leadName: z.string().max(120).optional(),
    phoneE164: z.string().min(6).max(20).optional(),
    to_number: z.string().min(6).max(20).optional(),
    from_number: z.string().max(20).optional(),
    timezone: z.string().max(60).optional(),
    maxAttempts: z.number().int().min(1).max(10).optional(),
    recordingEnabled: z.boolean().optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
    rapidcall_llm_dynamic_variables: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

  const agentId = parsed.data.agentId ?? parsed.data.agent_id;
  const phoneRaw = parsed.data.phoneE164 ?? parsed.data.to_number;
  if (!agentId) return res.status(400).json({ error: "agent_id or agentId is required" });
  if (!phoneRaw) return res.status(400).json({ error: "to_number or phoneE164 is required" });

  const phone = String(phoneRaw).trim();
  if (!/^\+?[1-9]\d{6,14}$/.test(phone)) {
    return res.status(400).json({ error: "to_number / phoneE164 must be in E.164 format" });
  }

  const agent = await store.getAgent(req.workspace.id, agentId);
  if (!agent) return res.status(404).json({ error: "Agent not found" });

  const dynamicVars = parsed.data.rapidcall_llm_dynamic_variables ?? {};
  const metadata = { ...(typeof parsed.data.metadata === "object" && parsed.data.metadata ? parsed.data.metadata : {}) };
  if (parsed.data.from_number != null && String(parsed.data.from_number).trim()) {
    metadata.fromNumber = String(parsed.data.from_number).trim();
  }
  for (const [k, v] of Object.entries(dynamicVars)) {
    if (k !== "fromNumber") metadata[k] = v;
  }

  const job = await store.createOutboundJob(req.workspace.id, {
    leadName: parsed.data.leadName ?? "",
    phoneE164: phone,
    timezone: parsed.data.timezone ?? "UTC",
    maxAttempts: parsed.data.maxAttempts ?? 3,
    agentId,
    recordingEnabled: Boolean(parsed.data.recordingEnabled),
    metadata,
  });
  await store.addOutboundJobLog(req.workspace.id, job.id, {
    level: "info",
    message: "Job created",
    meta: { agentId: job.agentId, phoneE164: job.phoneE164 },
  });
  outboundJobsQueuedTotal.inc();

  // Trigger the outbound worker immediately so the call starts right away
  outboundWorker.triggerNow();

  // Auto-create/update contact from outbound job (best-effort)
  try {
    const phone = job.phoneE164.startsWith("+") ? job.phoneE164 : `+${job.phoneE164}`;
    await contactStore.upsertContactFromCall(req.workspace.id, phone, job.leadName ?? "", "outbound");
  } catch (e) {
    logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[outbound.jobs] contact auto-create failed");
  }

  return res.status(201).json({ job });
});

app.get("/api/outbound/jobs", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Outbound jobs require Postgres mode" });
  const status = req.query.status ? String(req.query.status) : undefined;
  const limit = req.query.limit ? Number(req.query.limit) : undefined;
  const offset = req.query.offset ? Number(req.query.offset) : undefined;
  const jobs = await store.listOutboundJobs(req.workspace.id, { status, limit, offset });
  return res.json({ jobs });
});

app.get("/api/outbound/jobs/:id", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Outbound jobs require Postgres mode" });
  const job = await store.getOutboundJob(req.workspace.id, String(req.params.id || ""));
  if (!job) return res.status(404).json({ error: "Job not found" });
  return res.json({ job });
});

app.get("/api/outbound/jobs/:id/logs", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Outbound jobs require Postgres mode" });
  const id = String(req.params.id || "");
  const logs = await store.listOutboundJobLogs(req.workspace.id, id, 200);
  return res.json({ logs });
});

app.post("/api/outbound/jobs/:id/cancel", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Outbound jobs require Postgres mode" });
  const id = String(req.params.id || "");
  const job = await store.getOutboundJob(req.workspace.id, id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  const next = await store.updateOutboundJob(req.workspace.id, id, {
    status: "canceled",
    lastError: "Canceled by user",
  });
  await store.addOutboundJobLog(req.workspace.id, id, { level: "warn", message: "Job canceled by user" });
  return res.json({ job: next });
});

app.post("/api/outbound/jobs/:id/dnc", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Outbound jobs require Postgres mode" });
  const id = String(req.params.id || "");
  const schema = z.object({ reason: z.string().max(200).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const job = await store.getOutboundJob(req.workspace.id, id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  const next = await store.updateOutboundJob(req.workspace.id, id, {
    dnc: true,
    dncReason: parsed.data.reason ?? "",
    status: "canceled",
  });
  await store.addOutboundJobLog(req.workspace.id, id, {
    level: "warn",
    message: "DNC set for job",
    meta: { reason: parsed.data.reason ?? "" },
  });
  return res.json({ job: next });
});

// --- Twilio inbound webhook -> bridge into LiveKit SIP (Phase 3) ---
app.get("/api/twilio/inbound", async (_req, res) => {
  // Useful for quick connectivity tests from browser/curl.
  res.json({ ok: true });
});

app.post("/api/twilio/inbound", async (req, res) => {
  // Twilio sends form fields like: To, From, CallSid, ...
  const to = String(req.body?.To || "").trim();
  const from = String(req.body?.From || "").trim();
  const twilioCallSid = String(req.body?.CallSid || "").trim();

  const VoiceResponse = require("twilio").twiml.VoiceResponse;
  const vr = new VoiceResponse();

  if (!to) {
    console.log("[twilio-inbound] missing To", { twilioCallSid, bodyKeys: Object.keys(req.body || {}) });
    vr.say("Missing To number.");
    res.type("text/xml").send(vr.toString());
    return;
  }

  // Find phone number config
  let phoneRow = null;

  if (USE_DB) {
    phoneRow = await store.getPhoneNumberByE164(to);
  } else {
    phoneRow = readPhoneNumbers().find((p) => p.e164 === to) ?? null;
  }

  if (!phoneRow) {
    vr.say("This number is not configured yet.");
    res.type("text/xml").send(vr.toString());
    return;
  }

  // LiveKit docs for Twilio Programmable Voice require SIP trunk auth (username/password) and dialing:
  //   sip:<your_twilio_number>@<your LiveKit SIP endpoint>
  // Ref: https://docs.livekit.io/telephony/accepting-calls/inbound-twilio/
  const sipEndpoint = String(process.env.LIVEKIT_SIP_ENDPOINT || "").trim();
  const sipUser = String(phoneRow.livekitSipUsername || "").trim();
  const sipPass = String(phoneRow.livekitSipPassword || "").trim();

  if (!sipEndpoint) {
    console.log("[twilio-inbound] LIVEKIT_SIP_ENDPOINT not set", { twilioCallSid, to, from });
    vr.say("LiveKit SIP endpoint is not configured.");
    res.type("text/xml").send(vr.toString());
    return;
  }

  // Use TLS transport so Twilio connects to LiveKit over TLS (matches outbound; avoids "TLS required" from LiveKit).
  let dest = `sip:${to}@${sipEndpoint};transport=tls`;

  if (!phoneRow.inboundAgentId) {
    console.warn("[twilio-inbound] No inbound agent configured for this number — call will reach LiveKit but may have no voice. Set Inbound agent in Phone Numbers.", { to, from, phoneNumberId: phoneRow.id });
  }

  console.log("[twilio-inbound] dial", {
    twilioCallSid,
    to,
    from,
    dest,
    hasAuth: Boolean(sipUser && sipPass),
    inboundAgentId: phoneRow.inboundAgentId || null,
  });

  // timeout: seconds to wait for LiveKit to answer; default 30 so caller doesn't ring forever
  const dial = vr.dial({ answerOnBridge: true, timeout: 30 });
  // SIP auth is optional: LiveKit inbound trunks can work without auth when identified by number.
  const sipNode = sipUser && sipPass ? dial.sip({ username: sipUser, password: sipPass }, dest) : dial.sip(dest);
  // Propagate Twilio CallSid to the SIP endpoint so LiveKit can surface it as participant attributes (best-effort).
  // This helps us reconcile carrier billing later.
  try {
    if (sipNode && typeof sipNode.parameter === "function" && twilioCallSid) {
      sipNode.parameter({ name: "X-Twilio-CallSid", value: twilioCallSid });
    }
  } catch {
    // ignore
  }
  res.type("text/xml").send(vr.toString());
});

function verifyTwilioWebhook(req) {
  const authToken = String(process.env.TWILIO_AUTH_TOKEN || "").trim();
  if (!authToken) return false;
  const signature = String(req.headers["x-twilio-signature"] || "").trim();
  if (!signature) return false;
  const base = getPublicBaseUrl(req);
  if (!base) return false;
  const url = `${base}${req.originalUrl}`;
  return twilio.validateRequest(authToken, signature, url, req.body || {});
}

// NOTE: Old /webhooks/telephony removed. Outbound calls now use LiveKit SIP (CreateSIPParticipant).
// LiveKit handles call events internally. Outbound worker polls job status.

// --- Start a voice session for an agent profile ---
app.post("/api/agents/:id/start", requireAuth, async (req, res) => {
  const { id } = req.params;
  const startSchema = z
    .object({
      welcome: WelcomeConfigSchema,
      voice: z.object({
        provider: z.enum(["cartesia", "elevenlabs"]).optional(),
        model: z.string().optional(),
        voiceId: z.string().optional(),
      }).optional(),
      enabledTools: z.array(z.string()).optional(),
    })
    .optional();
  const startParsed = startSchema?.safeParse(req.body);
  if (startParsed && !startParsed.success) {
    return res.status(400).json({ error: "Validation failed", details: startParsed.error.flatten() });
  }

  const agent = USE_DB ? await store.getAgent(req.workspace.id, id) : readAgents().find((a) => a.id === id);
  if (!agent) return res.status(404).json({ error: "Agent not found" });
  const promptDraft = agent.promptDraft ?? agent.prompt ?? "";
  const promptPublished = agent.promptPublished ?? "";
  const basePrompt = (promptDraft && String(promptDraft).trim()) ? promptDraft : promptPublished;
  let promptUsed = basePrompt;
  let variantChosen = null;
  if (USE_DB) {
    try {
      const variants = await store.listAgentVariants(req.workspace.id, agent.id);
      const enabled = variants.filter((v) => v.enabled && v.trafficPercent > 0);
      const total = enabled.reduce((acc, v) => acc + v.trafficPercent, 0);
      if (enabled.length && total > 0) {
        const roll = Math.random() * total;
        let acc = 0;
        for (const v of enabled) {
          acc += v.trafficPercent;
          if (roll <= acc) {
            variantChosen = v;
            break;
          }
        }
        if (variantChosen?.prompt) {
          promptUsed = `${basePrompt}\n\n# Variant (A/B Test)\n${variantChosen.prompt}`;
        }
      }
    } catch (e) {
      logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "variant selection failed");
    }
  }
  if (!basePrompt || String(basePrompt).trim().length === 0) {
    return res.status(400).json({ error: "Agent prompt is empty. Set a prompt before starting a session." });
  }
  // Apply default dynamic variables ({{VarName}} -> fallback values when not provided per-call)
  promptUsed = substituteDynamicVariables(promptUsed, agent.defaultDynamicVariables ?? {});

  const welcome = {
    mode: startParsed?.data?.welcome?.mode ?? agent.welcome?.mode ?? "user",
    aiMessageMode: startParsed?.data?.welcome?.aiMessageMode ?? agent.welcome?.aiMessageMode ?? "dynamic",
    aiMessageText: startParsed?.data?.welcome?.aiMessageText ?? agent.welcome?.aiMessageText ?? "",
    aiDelaySeconds: startParsed?.data?.welcome?.aiDelaySeconds ?? agent.welcome?.aiDelaySeconds ?? 0,
  };
  const voice = startParsed?.data?.voice ?? agent.voice ?? {};
  const enabledTools = startParsed?.data?.enabledTools ?? agent.enabledTools ?? ["end_call"];
  const backgroundAudio = agent.backgroundAudio ?? {};
  const toolConfigs = agent.toolConfigs && typeof agent.toolConfigs === "object" ? agent.toolConfigs : {};
  const toolConfigKeys = Object.keys(toolConfigs);
  logger.info(
    { agentId: id, workspaceId: req.workspace.id, toolConfigKeys, toolConfigKeysCount: toolConfigKeys.length },
    "[agents.start] webtest room: agent config for metadata"
  );

  const backchannelEnabled = Boolean(agent.backchannelEnabled);
  const llmModel = String(agent.llmModel || "").trim() || DEFAULT_LLM_MODEL;
  const maxCallSeconds = Number(agent.maxCallSeconds || 0);

  // IMPORTANT:
  // Web test rooms must match an existing LiveKit dispatch rule (telephony typically uses roomPrefix "call-").
  // If dispatch doesn't trigger, the agent won't join and the web test appears "stuck".
  const webRoomPrefix = String(process.env.LIVEKIT_WEB_ROOM_PREFIX || "call-").trim() || "call-";
  const roomName = `${webRoomPrefix}${id}-${nanoid(6)}`;
  const identity = `user-${nanoid(8)}`;
  const callId = `call_${nanoid(12)}`;
  callsStartedTotal.inc({ source: "web" });
  inProgressCallsGaugeValue += 1;

  // Persist a call record immediately (web test)
  const now = Date.now();
  const callRecord = {
    id: callId,
    workspaceId: req.workspace.id,
    agentId: agent.id,
    agentName: agent.name,
    to: "webtest",
    roomName,
    startedAt: now,
    endedAt: null,
    durationSec: null,
    outcome: "in_progress",
    costUsd: null,
    transcript: [],
    recording: null, // will be filled if egress is enabled
    metrics: {
      normalized: { source: "web" },
      abTest: variantChosen
        ? { variantId: variantChosen.id, variantName: variantChosen.name, promptMode: "base_plus_variant" }
        : null,
    },
    createdAt: now,
    updatedAt: now,
  };
  if (USE_DB) {
    await store.createCall(callRecord);
  } else {
    const calls = readCalls();
    calls.unshift(callRecord);
    writeCalls(calls);
  }

  if (agent.webhookUrl && USE_DB) {
    try {
      sendAgentWebhook(agent, "call_started", callRecord);
    } catch (e) {
      logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[agents.start] webhook call_started failed");
    }
  }

  const rs = roomService();
  // If you configured LiveKit dispatch rules (recommended), they will start the correct agent based on room name/prefix.
  // Only set this when you *explicitly* want to target a named agent.
  const webAgentName = String(process.env.LIVEKIT_WEB_AGENT_NAME || process.env.LIVEKIT_AGENT_NAME || "").trim();
  // Create the room and embed the agent prompt in room metadata so the Python agent can read it.
  await rs.createRoom({
    name: roomName,
    metadata: JSON.stringify({
      call: { id: callId, to: "webtest" },
      agent: {
        id: agent.id,
        workspaceId: req.workspace.id,
        name: agent.name,
        prompt: promptUsed,
        promptBase: basePrompt,
        promptVariant: variantChosen?.prompt ?? null,
        voice,
        enabledTools: Array.isArray(enabledTools) ? enabledTools : ["end_call"],
        toolConfigs,
        backchannelEnabled,
        backgroundAudio,
        llmModel,
        maxCallSeconds,
        knowledgeFolderIds: Array.isArray(agent.knowledgeFolderIds) ? agent.knowledgeFolderIds : [],
        variant: variantChosen ? { id: variantChosen.id, name: variantChosen.name } : null,
        defaultDynamicVariables: agent.defaultDynamicVariables ?? {},
        callSettings: agent.callSettings ?? {},
        fallbackVoice: agent.fallbackVoice ?? null,
        postCallDataExtraction: Array.isArray(agent.postCallDataExtraction) ? agent.postCallDataExtraction : [],
        postCallExtractionModel: agent.postCallExtractionModel ?? "",
      },
      welcome,
    }),
    emptyTimeout: 10,
    maxParticipants: 2,
  });

  // Explicit dispatch (more reliable on Cloud than createRoom.agents)
  if (webAgentName) {
    try {
      const dc = agentDispatchService();
      await dc.createDispatch(roomName, webAgentName, {
        metadata: JSON.stringify({ source: "webtest", callId, agentId: agent.id }),
      });
    } catch (e) {
      // Surface this to the UI; otherwise it looks like an infinite "Connecting..."
      return res.status(502).json({
        error: "Failed to dispatch LiveKit agent to room",
        details: String(e?.message || e),
        hint:
          "Check that your LiveKit Cloud agent is deployable (not Builder), is running, and that LIVEKIT_AGENT_NAME matches LIVEKIT_WEB_AGENT_NAME.",
      });
    }
  }

  // Start egress recording (audio-only) to S3 if configured.
  try {
    const e = await startCallEgress({ roomName, callId });
    if (e.enabled) {
      const recording = {
        kind: "egress_s3",
        egressId: e.egressId,
        bucket: e.bucket,
        key: e.key,
        status: "recording",
        url: `/api/calls/${callId}/recording`,
      };
      if (USE_DB) {
        await store.updateCall(callId, { recording });
      } else {
        const calls2 = readCalls();
        const idx = calls2.findIndex((c) => c.id === callId);
        if (idx !== -1) {
          calls2[idx] = { ...calls2[idx], recording, updatedAt: Date.now() };
          writeCalls(calls2);
        }
      }
    }
  } catch (e) {
    // Non-fatal: call still works, just no recording.
    // eslint-disable-next-line no-console
    logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "Failed to start egress");
    sendAlert("egress_start_failed", { requestId: req.requestId, error: String(e?.message || e) });
  }

  const token = await createParticipantToken({
    roomName,
    identity,
    name: "Web User",
    metadata: JSON.stringify({ app: "agent-ui" }),
  });

  // Client uses this to connect with LiveKit JS SDK
  res.json({
    livekitUrl: process.env.LIVEKIT_URL,
    roomName,
    token,
    agent: { id: agent.id, name: agent.name },
    callId,
    expectedAgentName: webAgentName || null,
  });
});

// --- Call History (stored locally in ./data/calls.json) ---
app.get("/api/calls", requireAuth, async (req, res) => {
  if (USE_DB) {
    const calls = await store.listCalls(req.workspace.id);

    // Best-effort cleanup: if a call is stuck "in_progress" for a long time, mark it completed.
    // This protects against agent/network failures that prevent /end from being posted.
    const now = Date.now();
    const STALE_MS = 15 * 60 * 1000;
    for (const c of calls.slice(0, 50)) {
      if (c.outcome === "in_progress" && !c.endedAt && now - Number(c.startedAt || 0) > STALE_MS) {
        // IMPORTANT: do NOT set endedAt=now, otherwise stuck calls can turn into hours/days of phantom minutes.
        // Instead, end at startedAt + STALE_MS and mark outcome so billing can exclude it.
        const startedAt = Number(c.startedAt || now);
        const endedAt = startedAt + STALE_MS;
        const durationSec = Math.max(0, Math.round(STALE_MS / 1000));
        // Fire-and-forget; don't block response.
        // eslint-disable-next-line no-void
        void store.updateCall(c.id, { endedAt, durationSec, outcome: "stale_timeout" });
      }
    }

    return res.json({
      calls: calls.map((c) => {
        const norm = normalizeDurationSec({
          durationSecStored: c.durationSec,
          startedAtMs: c.startedAt,
          endedAtMs: c.endedAt,
        });
        return {
          ...c,
          durationSec: norm.durationSec,
          costUsd: typeof c.costUsd === "number" ? c.costUsd : null,
        };
      }),
    });
  }
  const calls = readCalls();
  return res.json({
    calls: calls.map((c) => {
      const norm = normalizeDurationSec({
        durationSecStored: c.durationSec,
        startedAtMs: c.startedAt,
        endedAtMs: c.endedAt,
      });
      return {
        id: c.id,
        agentId: c.agentId,
        agentName: c.agentName,
        to: c.to,
        roomName: c.roomName,
        startedAt: c.startedAt,
        endedAt: c.endedAt,
        durationSec: norm.durationSec,
        outcome: c.outcome,
        costUsd: typeof c.costUsd === "number" ? c.costUsd : null,
        recordingUrl: c.recording?.url ?? null,
        createdAt: c.createdAt,
        updatedAt: c.updatedAt,
      };
    }),
  });
});

app.get("/api/calls/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const call = USE_DB ? await store.getCall(req.workspace.id, id) : readCalls().find((c) => c.id === id);
  if (!call) return res.status(404).json({ error: "Call not found" });
  const norm = normalizeDurationSec({
    durationSecStored: call.durationSec,
    startedAtMs: call.startedAt,
    endedAtMs: call.endedAt,
  });
  // Prefer recording duration when available; reject implausible values (e.g. ms stored as sec).
  const MAX_REASONABLE_DURATION_SEC = 6 * 60 * 60;
  const rawRec = call.recording?.durationSec != null ? Number(call.recording.durationSec) : NaN;
  const durationSec =
    Number.isFinite(rawRec) && rawRec >= 0 && rawRec <= MAX_REASONABLE_DURATION_SEC
      ? Math.round(rawRec)
      : norm.durationSec;
  res.json({ call: { ...call, durationSec } });
});

// Export call data (transcript + metrics) for QA/review
app.get("/api/calls/:id/export", requireAuth, async (req, res) => {
  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ error: "Missing call id" });
  const call = USE_DB ? await store.getCall(req.workspace.id, id) : readCalls().find((c) => c.id === id);
  if (!call) return res.status(404).json({ error: "Call not found" });
  const norm = normalizeDurationSec({
    durationSecStored: call.durationSec,
    startedAtMs: call.startedAt,
    endedAtMs: call.endedAt,
  });
  return res.json({
    call: {
      id: call.id,
      agentId: call.agentId,
      agentName: call.agentName,
      roomName: call.roomName,
      to: call.to,
      startedAt: call.startedAt,
      endedAt: call.endedAt,
      durationSec: norm.durationSec,
      outcome: call.outcome,
      metrics: call.metrics ?? null,
      transcript: call.transcript ?? [],
    },
  });
});

// Call evaluations (QA scoring)
app.get("/api/calls/:id/evaluations", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Evaluations require Postgres mode" });
  const callId = String(req.params.id || "").trim();
  const rows = await store.listCallEvaluations(req.workspace.id, callId);
  return res.json({ evaluations: rows });
});

app.post("/api/calls/:id/evaluations", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Evaluations require Postgres mode" });
  const callId = String(req.params.id || "").trim();
  const schema = z.object({
    score: z.number().int().min(0).max(100),
    notes: z.string().max(2000).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const row = await store.createCallEvaluation(req.workspace.id, callId, { ...parsed.data, source: "manual" });
  return res.status(201).json({ evaluation: row });
});

// Auto-evaluate a call with AI
app.post("/api/calls/:id/auto-evaluate", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Evaluations require Postgres mode" });
  const callId = String(req.params.id || "").trim();
  const call = await store.getCall(req.workspace.id, callId);
  if (!call) return res.status(404).json({ error: "Call not found" });
  if (!call.transcript || call.transcript.length === 0) {
    return res.status(400).json({ error: "Transcript required for auto evaluation" });
  }

  const apiKey = String(process.env.OPENAI_API_KEY || "").trim();
  if (!apiKey) return res.status(500).json({ error: "OPENAI_API_KEY is not set on the server" });
  const model = String(process.env.OPENAI_EVAL_MODEL || process.env.OPENAI_GENERATE_MODEL || "gpt-4.1-mini").trim();

  const agent = await store.getAgent(req.workspace.id, call.agentId);
  const transcriptText = transcriptToTextForAnalysis(call.transcript).slice(0, 9000);

  try {
    const raw = await openaiAutoEvaluateCall({
      apiKey,
      model,
      input: {
        agentName: agent?.name ?? call.agentName ?? "Agent",
        prompt: agent?.promptPublished ?? agent?.promptDraft ?? "",
        outcome: call.outcome ?? null,
        durationSec: call.durationSec ?? null,
        transcript: transcriptText,
      },
    });
    const text = String(raw || "").trim();
    let details = null;
    try {
      details = JSON.parse(text);
    } catch {
      const start = text.indexOf("{");
      const end = text.lastIndexOf("}");
      if (start !== -1 && end !== -1 && end > start) {
        details = JSON.parse(text.slice(start, end + 1));
      }
    }
    if (!details || typeof details !== "object") {
      return res.status(502).json({ error: "Auto evaluation failed to parse JSON" });
    }
    const score = Math.max(0, Math.min(100, Math.round(Number(details.score ?? 0))));
    const summary = typeof details.summary === "string" ? details.summary : "";
    const row = await store.createCallEvaluation(req.workspace.id, callId, {
      score,
      notes: summary,
      source: "auto",
      details,
    });
    return res.status(201).json({ evaluation: row });
  } catch (e) {
    return res.status(502).json({ error: "Auto evaluation failed" });
  }
});

// Call labels (tags)
app.get("/api/calls/:id/labels", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Labels require Postgres mode" });
  const callId = String(req.params.id || "").trim();
  const rows = await store.listCallLabels(req.workspace.id, callId);
  return res.json({ labels: rows });
});

app.post("/api/calls/:id/labels", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Labels require Postgres mode" });
  const callId = String(req.params.id || "").trim();
  const schema = z.object({ label: z.string().min(1).max(80) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  const row = await store.addCallLabel(req.workspace.id, callId, parsed.data.label);
  return res.status(201).json({ label: row });
});

app.delete("/api/calls/:id/labels", requireAuth, async (req, res) => {
  if (!USE_DB) return res.status(400).json({ error: "Labels require Postgres mode" });
  const callId = String(req.params.id || "").trim();
  const schema = z.object({ label: z.string().min(1).max(80) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  await store.deleteCallLabel(req.workspace.id, callId, parsed.data.label);
  return res.json({ ok: true });
});

// Called by the Python agent to attach per-call metrics (usage/models/latency) to the call record.
app.post("/api/calls/:id/metrics", requireAgentSecret, async (req, res) => {
  const { id } = req.params;
  const schema = z.object({
    usage: z
      .object({
        llm_prompt_tokens: z.number().int().nonnegative().optional(),
        llm_prompt_cached_tokens: z.number().int().nonnegative().optional(),
        llm_completion_tokens: z.number().int().nonnegative().optional(),
        tts_characters_count: z.number().int().nonnegative().optional(),
        tts_audio_duration: z.number().nonnegative().optional(),
        stt_audio_duration: z.number().nonnegative().optional(),
        // optional: allow the agent to attach model identifiers directly under usage
        llm_model: z.string().min(1).max(120).optional(),
        stt_model: z.string().min(1).max(120).optional(),
        tts_model: z.string().min(1).max(120).optional(),
      })
      .optional(),
    models: z
      .object({
        llm: z.string().min(1).max(120).optional(),
        stt: z.string().min(1).max(120).optional(),
        tts: z.string().min(1).max(120).optional(),
      })
      .optional(),
    // Normalized per-call fields that drive minute-based billing.
    normalized: z
      .object({
        source: z.enum(["web", "telephony", "unknown"]).optional(),
        participantsCountAvg: z.number().positive().optional(),
        recordingEnabled: z.boolean().optional(),
      })
      .optional(),
    telephony: z
      .object({
        trunkNumber: z.string().min(0).max(64).optional(),
        callerNumber: z.string().min(0).max(64).optional(),
        twilioCallSid: z.string().min(0).max(64).optional(),
        rateKey: z.string().min(0).max(64).optional(),
      })
      .optional(),
    latency: z
      .object({
        llm_ttft_ms_avg: z.number().nonnegative().optional(),
        eou_transcription_ms_avg: z.number().nonnegative().optional(),
        eou_end_ms_avg: z.number().nonnegative().optional(),
        agent_turn_latency_ms_avg: z.number().nonnegative().optional(),
      })
      .optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  callMetricsPostedTotal.inc({ hasUsage: parsed.data.usage ? "true" : "false" });

  const current = USE_DB ? await store.getCallById(id) : readCalls().find((c) => c.id === id);
  if (!current) return res.status(404).json({ error: "Call not found" });
  const usage = parsed.data.usage ?? current.metrics?.usage ?? null;
  const models = parsed.data.models ?? current.metrics?.models ?? null;
  const llmModel = models?.llm ?? usage?.llm_model ?? null;
  const sttModel = models?.stt ?? usage?.stt_model ?? null;
  const ttsModel = models?.tts ?? usage?.tts_model ?? null;
  const latency = parsed.data.latency ?? current.metrics?.latency ?? null;
  const normalizedIn = parsed.data.normalized ?? null;
  const telephonyIn = parsed.data.telephony ?? null;

  // Normalize models into usage so pricing lookups can be consistent.
  const usageWithModels =
    usage && typeof usage === "object"
      ? { ...usage, stt_model: sttModel ?? usage.stt_model, tts_model: ttsModel ?? usage.tts_model }
      : usage;

  const prevTelephony = current.metrics?.telephony && typeof current.metrics.telephony === "object" ? current.metrics.telephony : {};
  const mergedTelephony = { ...prevTelephony, ...(telephonyIn || {}) };

  const prevNormalized = current.metrics?.normalized && typeof current.metrics.normalized === "object" ? current.metrics.normalized : {};
  const mergedNormalized = { ...prevNormalized, ...(normalizedIn || {}) };

  const llmIn = Number(usage?.llm_prompt_tokens || 0);
  const llmOut = Number(usage?.llm_completion_tokens || 0);
  const tokensTotal = llmIn + llmOut;

  const next = {
    ...current,
    metrics: {
      ...(current.metrics && typeof current.metrics === "object" ? current.metrics : {}),
      usage: usageWithModels,
      models: { ...(models || {}), llm: llmModel ?? undefined, stt: sttModel ?? undefined, tts: ttsModel ?? undefined },
      latency,
      tokensTotal,
      telephony: mergedTelephony,
      normalized: { ...mergedNormalized },
    },
    updatedAt: Date.now(),
  };

  if (USE_DB) {
    const updated = await store.updateCall(id, { metrics: next.metrics });
    // eslint-disable-next-line no-console
    console.log(
      `Metrics saved for ${id}: tokens=${updated?.metrics?.tokensTotal ?? "—"} latencyMs=${updated?.metrics?.latency?.agent_turn_latency_ms_avg ?? "—"}`
    );
    return res.json({ call: updated });
  }

  const calls = readCalls();
  const idx = calls.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ error: "Call not found" });
  calls[idx] = next;
  writeCalls(calls);
  // eslint-disable-next-line no-console
  console.log(`Metrics saved for ${id}: tokens=${next.metrics?.tokensTotal ?? "—"} latencyMs=${next.metrics?.latency?.agent_turn_latency_ms_avg ?? "—"}`);
  return res.json({ call: next });
});

// --- Analytics ---
app.get("/api/analytics", requireAuth, async (req, res) => {
  const fromMs = req.query.from ? Number(req.query.from) : null;
  const toMs = req.query.to ? Number(req.query.to) : null;
  const hasFrom = typeof fromMs === "number" && Number.isFinite(fromMs);
  const hasTo = typeof toMs === "number" && Number.isFinite(toMs);
  const now = Date.now();
  const defaultFrom = now - 7 * 24 * 60 * 60 * 1000;
  const qFrom = hasFrom ? fromMs : defaultFrom;
  const qTo = hasTo ? toMs : now;

  if (USE_DB) {
    const p = getPool();
    const { rows } = await p.query(
      `
      SELECT
        COUNT(*)::BIGINT AS call_count,
        COUNT(*) FILTER (WHERE ended_at IS NOT NULL)::BIGINT AS completed_call_count,
        AVG(duration_sec) FILTER (WHERE ended_at IS NOT NULL) AS avg_duration_sec,
        AVG((metrics->'latency'->>'agent_turn_latency_ms_avg')::DOUBLE PRECISION)
          FILTER (WHERE ended_at IS NOT NULL AND metrics IS NOT NULL AND (metrics->'latency'->>'agent_turn_latency_ms_avg') IS NOT NULL) AS avg_latency_ms,
        SUM((metrics->>'tokensTotal')::BIGINT)
          FILTER (WHERE ended_at IS NOT NULL AND metrics IS NOT NULL AND (metrics->>'tokensTotal') IS NOT NULL) AS total_tokens
      FROM calls
      WHERE workspace_id=$1 AND started_at >= $2 AND started_at <= $3
    `,
      [req.workspace.id, qFrom, qTo]
    );

    const r = rows[0] || {};
    const avgDurationSec = r.avg_duration_sec == null ? null : Math.round(Number(r.avg_duration_sec));
    const avgLatencyMs = r.avg_latency_ms == null ? null : Math.round(Number(r.avg_latency_ms));
    const totalTokens = r.total_tokens == null ? null : Number(r.total_tokens);

    const { rows: seriesRows } = await p.query(
      `
      SELECT
        to_char(date_trunc('day', to_timestamp(started_at / 1000.0) AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day,
        COUNT(*)::BIGINT AS calls,
        (SUM(duration_sec) FILTER (WHERE ended_at IS NOT NULL AND duration_sec IS NOT NULL))::BIGINT AS seconds
      FROM calls
      WHERE workspace_id=$1 AND started_at >= $2 AND started_at <= $3
      GROUP BY 1
      ORDER BY 1 ASC
    `,
      [req.workspace.id, qFrom, qTo]
    );

    return res.json({
      range: { from: qFrom, to: qTo, tz: "UTC" },
      totals: {
        callCount: Number(r.call_count || 0),
        completedCallCount: Number(r.completed_call_count || 0),
        avgDurationSec,
        avgLatencyMs,
        totalTokens,
      },
      series: seriesRows.map((row) => ({
        day: row.day,
        calls: Number(row.calls || 0),
        minutes: row.seconds == null ? 0 : Math.round(Number(row.seconds) / 60),
      })),
    });
  }

  const calls = readCalls();
  const inRange = calls.filter((c) => (c.startedAt || 0) >= qFrom && (c.startedAt || 0) <= qTo);
  const completed = inRange.filter((c) => c.endedAt);
  const count = inRange.length;
  const completedCount = completed.length;

  const avgDurationSec =
    completedCount === 0 ? null : Math.round(completed.reduce((a, c) => a + (c.durationSec || 0), 0) / completedCount);

  const latencyValues = completed
    .map((c) => c.metrics?.latency?.agent_turn_latency_ms_avg)
    .filter((v) => typeof v === "number" && Number.isFinite(v));
  const avgLatencyMs =
    latencyValues.length === 0 ? null : Math.round(latencyValues.reduce((a, v) => a + v, 0) / latencyValues.length);

  const tokenValues = completed
    .map((c) => c.metrics?.tokensTotal)
    .filter((v) => typeof v === "number" && Number.isFinite(v));
  const totalTokens = tokenValues.length ? tokenValues.reduce((a, v) => a + v, 0) : null;

  const byDay = new Map();
  for (const c of inRange) {
    const d = new Date(c.startedAt || 0);
    const day = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(
      2,
      "0"
    )}`;
    const entry = byDay.get(day) || { day, calls: 0, minutes: 0 };
    entry.calls += 1;
    entry.minutes += Math.round(((c.durationSec || 0) / 60) * 100) / 100;
    byDay.set(day, entry);
  }
  const series = Array.from(byDay.values()).sort((a, b) => (a.day < b.day ? -1 : 1));

  return res.json({
    range: { from: qFrom, to: qTo, tz: "UTC" },
    totals: {
      callCount: count,
      completedCallCount: completedCount,
      avgDurationSec,
      avgLatencyMs,
      totalTokens,
    },
    series,
  });
});

// --- Billing (RESET) ---
// Part 0 hard reset: previous cost estimation/COGS logic and /api/billing/* endpoints are removed.

// Billing endpoints removed (reset).

app.get("/api/agents/:id/analytics", requireAuth, async (req, res) => {
  const { id } = req.params;

  if (USE_DB) {
    const agent = await store.getAgent(req.workspace.id, id);
    if (!agent) return res.status(404).json({ error: "Agent not found" });
    const p = getPool();
    const { rows } = await p.query(
      `
      SELECT
        COUNT(*)::BIGINT AS call_count,
        COUNT(*) FILTER (WHERE ended_at IS NOT NULL)::BIGINT AS completed_call_count,
        AVG(duration_sec) FILTER (WHERE ended_at IS NOT NULL) AS avg_duration_sec,
        AVG((metrics->'latency'->>'agent_turn_latency_ms_avg')::DOUBLE PRECISION)
          FILTER (WHERE ended_at IS NOT NULL AND metrics IS NOT NULL AND (metrics->'latency'->>'agent_turn_latency_ms_avg') IS NOT NULL) AS avg_latency_ms,
        SUM((metrics->>'tokensTotal')::BIGINT)
          FILTER (WHERE ended_at IS NOT NULL AND metrics IS NOT NULL AND (metrics->>'tokensTotal') IS NOT NULL) AS total_tokens
      FROM calls
      WHERE workspace_id=$1 AND agent_id=$2
    `,
      [req.workspace.id, id]
    );

    const { rows: latestRows } = await p.query(
      `
      SELECT
        id,
        ended_at,
        duration_sec,
        (metrics->>'tokensTotal')::BIGINT AS tokens_total,
        (metrics->'latency'->>'agent_turn_latency_ms_avg')::DOUBLE PRECISION AS latency_ms
      FROM calls
      WHERE workspace_id=$1 AND agent_id=$2 AND ended_at IS NOT NULL
      ORDER BY ended_at DESC
      LIMIT 1
    `,
      [req.workspace.id, id]
    );

    const r = rows[0] || {};
    const avgDurationSec = r.avg_duration_sec == null ? null : Math.round(Number(r.avg_duration_sec));
    const avgLatencyMs = r.avg_latency_ms == null ? null : Math.round(Number(r.avg_latency_ms));
    const totalTokens = r.total_tokens == null ? null : Number(r.total_tokens);

    const latest = latestRows[0] || null;

    return res.json({
      agentId: id,
      totals: {
        callCount: Number(r.call_count || 0),
        completedCallCount: Number(r.completed_call_count || 0),
        avgDurationSec,
        avgLatencyMs,
        totalTokens,
      },
      latest: latest
        ? {
            callId: latest.id,
            endedAt: latest.ended_at,
            durationSec: latest.duration_sec,
            tokensTotal: latest.tokens_total ?? null,
            latencyMs: latest.latency_ms ?? null,
          }
        : null,
    });
  }

  const calls = readCalls().filter((c) => c.agentId === id);
  const completed = calls.filter((c) => c.endedAt);
  const completedCount = completed.length;

  const avgDurationSec =
    completedCount === 0 ? null : Math.round(completed.reduce((a, c) => a + (c.durationSec || 0), 0) / completedCount);

  const latencyValues = completed
    .map((c) => c.metrics?.latency?.agent_turn_latency_ms_avg)
    .filter((v) => typeof v === "number" && Number.isFinite(v));
  const avgLatencyMs =
    latencyValues.length === 0 ? null : Math.round(latencyValues.reduce((a, v) => a + v, 0) / latencyValues.length);

  const tokenValues = completed
    .map((c) => c.metrics?.tokensTotal)
    .filter((v) => typeof v === "number" && Number.isFinite(v));
  const totalTokens = tokenValues.length ? tokenValues.reduce((a, v) => a + v, 0) : null;

  // Latest completed call snapshot (for header)
  const latest = completed.slice().sort((a, b) => (b.endedAt || 0) - (a.endedAt || 0))[0] || null;

  res.json({
    agentId: id,
    totals: {
      callCount: calls.length,
      completedCallCount: completedCount,
      avgDurationSec,
      avgLatencyMs,
      totalTokens,
    },
    latest: latest
      ? {
          callId: latest.id,
          endedAt: latest.endedAt,
          durationSec: latest.durationSec,
          tokensTotal: latest.metrics?.tokensTotal ?? null,
          latencyMs: latest.metrics?.latency?.agent_turn_latency_ms_avg ?? null,
        }
      : null,
  });
});

// Per-agent usage totals for pricing UX (e.g. compute $/min from historical token intensity).
app.get("/api/agents/:id/usage-summary", requireAuth, async (req, res) => {
  const { id } = req.params;
  const fromMs = req.query.from ? Number(req.query.from) : null;
  const toMs = req.query.to ? Number(req.query.to) : null;
  const hasFrom = typeof fromMs === "number" && Number.isFinite(fromMs);
  const hasTo = typeof toMs === "number" && Number.isFinite(toMs);

  const now = new Date();
  const periodStart = hasFrom ? new Date(fromMs) : new Date(now.getFullYear(), now.getMonth(), 1);
  const periodEnd = hasTo ? new Date(toMs) : new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);
  const qFrom = periodStart.getTime();
  const qTo = periodEnd.getTime();

  if (USE_DB) {
    const agent = await store.getAgent(req.workspace.id, id);
    if (!agent) return res.status(404).json({ error: "Agent not found" });
    const p = getPool();
    const { rows } = await p.query(
      `
      SELECT
        COALESCE(SUM(duration_sec), 0)::BIGINT AS duration_sec,
        COALESCE(SUM(COALESCE((metrics->'usage'->>'llm_prompt_tokens')::BIGINT, 0)), 0)::BIGINT AS llm_prompt_tokens,
        COALESCE(SUM(COALESCE((metrics->'usage'->>'llm_prompt_cached_tokens')::BIGINT, 0)), 0)::BIGINT AS llm_prompt_cached_tokens,
        COALESCE(SUM(COALESCE((metrics->'usage'->>'llm_completion_tokens')::BIGINT, 0)), 0)::BIGINT AS llm_completion_tokens,
        COALESCE(SUM(COALESCE((metrics->'usage'->>'stt_audio_duration')::DOUBLE PRECISION, 0)), 0)::DOUBLE PRECISION AS stt_audio_seconds,
        COALESCE(SUM(COALESCE((metrics->'usage'->>'tts_characters_count')::BIGINT, 0)), 0)::BIGINT AS tts_characters
      FROM calls
      WHERE workspace_id=$1
        AND agent_id=$2
        AND ended_at IS NOT NULL
        AND started_at >= $3 AND started_at <= $4
    `,
      [req.workspace.id, id, qFrom, qTo]
    );
    const r = rows[0] || {};
    const durationSec = Number(r.duration_sec || 0);
    const minutes = durationSec > 0 ? durationSec / 60 : 0;
    return res.json({
      agentId: id,
      range: { from: qFrom, to: qTo, tz: "UTC" },
      totals: {
        durationSec,
        minutes,
        llmPromptTokens: Number(r.llm_prompt_tokens || 0),
        llmPromptCachedTokens: Number(r.llm_prompt_cached_tokens || 0),
        llmCompletionTokens: Number(r.llm_completion_tokens || 0),
        sttAudioSeconds: Number(r.stt_audio_seconds || 0),
        ttsCharacters: Number(r.tts_characters || 0),
      },
    });
  }

  const calls = readCalls()
    .filter((c) => c.agentId === id)
    .filter((c) => c.endedAt != null)
    .filter((c) => Number(c.startedAt || 0) >= qFrom && Number(c.startedAt || 0) <= qTo);

  let durationSec = 0;
  let llmPromptTokens = 0;
  let llmPromptCachedTokens = 0;
  let llmCompletionTokens = 0;
  let sttAudioSeconds = 0;
  let ttsCharacters = 0;
  for (const c of calls) {
    durationSec += Number(c.durationSec || 0);
    const u = c.metrics?.usage || {};
    llmPromptTokens += Number(u.llm_prompt_tokens || 0);
    llmPromptCachedTokens += Number(u.llm_prompt_cached_tokens || 0);
    llmCompletionTokens += Number(u.llm_completion_tokens || 0);
    sttAudioSeconds += Number(u.stt_audio_duration || 0);
    ttsCharacters += Number(u.tts_characters_count || 0);
  }
  const minutes = durationSec > 0 ? durationSec / 60 : 0;
  return res.json({
    agentId: id,
    range: { from: qFrom, to: qTo, tz: "UTC" },
    totals: { durationSec, minutes, llmPromptTokens, llmPromptCachedTokens, llmCompletionTokens, sttAudioSeconds, ttsCharacters },
  });
});

// Stream the call recording (supports Range requests for <audio> playback).
app.get("/api/calls/:id/recording", requireAuth, async (req, res) => {
  const { id } = req.params;
  const call = USE_DB ? await store.getCall(req.workspace.id, id) : readCalls().find((c) => c.id === id);
  if (!call) return res.status(404).send("Call not found");
  if (!call.recording || call.recording.kind !== "egress_s3") return res.status(404).send("No recording");

  const { bucket, key } = call.recording;
  try {
    const range = req.headers.range;
    const obj = await getObject({ bucket, key, range });

    const contentType = obj.ContentType || "audio/mpeg";
    const contentLength = obj.ContentLength;
    const contentRange = obj.ContentRange;

    res.setHeader("Content-Type", contentType);
    res.setHeader("Accept-Ranges", "bytes");
    if (contentLength != null) res.setHeader("Content-Length", String(contentLength));
    if (contentRange) res.setHeader("Content-Range", contentRange);

    // If Range was requested, AWS returns partial content (206).
    if (range && contentRange) res.status(206);

    if (!obj.Body) return res.status(500).send("Recording body missing");
    obj.Body.pipe(res);
    return;
  } catch (e) {
    // eslint-disable-next-line no-console
    logger.warn({ requestId: req.requestId, err: String(e?.name || e?.message || e) }, "Recording stream failed");
    sendAlert("recording_stream_failed", { requestId: req.requestId, error: String(e?.name || e?.message || e) });
    return res.status(500).send("Failed to stream recording");
  }
});

// Public (token-gated) stream endpoint for browser <audio> playback.
// We avoid returning raw S3 presigned URLs because some deployments use private S3 endpoints (MinIO/VPC) that browsers can't reach.
app.get("/api/calls/:id/recording-playback", async (req, res) => {
  const { id } = req.params;
  const token = String(req.query.token || "");
  const v = verifyRecordingPlaybackToken({ callId: id, token });
  if (!v.ok) return res.status(401).send("Unauthorized");

  const call = USE_DB ? await store.getCallById(id) : readCalls().find((c) => c.id === id);
  if (!call) return res.status(404).send("Call not found");
  if (!call.recording || call.recording.kind !== "egress_s3") return res.status(404).send("No recording");
  if (call.recording.status && call.recording.status !== "ready") return res.status(409).send("Recording not ready");

  const { bucket, key } = call.recording;
  try {
    // Playback GET counter (used for S3 GET request cost, per call).
    // Best-effort: do not block streaming.
    setTimeout(async () => {
      try {
        const c = USE_DB ? await store.getCallById(id) : readCalls().find((x) => x.id === id);
        if (!c) return;
        const prevMetrics = c.metrics && typeof c.metrics === "object" ? c.metrics : {};
        const prevRec = prevMetrics.recording && typeof prevMetrics.recording === "object" ? prevMetrics.recording : {};
        const nextCount = Number(prevRec.playbackGetCount || 0) + 1;
        const patch = {
          metrics: {
            ...prevMetrics,
            recording: { ...prevRec, playbackGetCount: nextCount, lastPlaybackAtMs: Date.now() },
          },
          recording:
            c.recording && typeof c.recording === "object"
              ? { ...c.recording, playbackGetCount: nextCount }
              : c.recording,
        };
        if (USE_DB) {
          await store.updateCall(id, patch);
        } else {
          const calls = readCalls();
          const idx = calls.findIndex((x) => x.id === id);
          if (idx !== -1) {
            calls[idx] = { ...calls[idx], ...patch, updatedAt: Date.now() };
            writeCalls(calls);
          }
        }
      } catch {
        // ignore
      }
    }, 0);

    const range = req.headers.range;
    const obj = await getObject({ bucket, key, range });

    const contentType = obj.ContentType || "audio/mpeg";
    const contentLength = obj.ContentLength;
    const contentRange = obj.ContentRange;

    res.setHeader("Content-Type", contentType);
    res.setHeader("Accept-Ranges", "bytes");
    if (contentLength != null) res.setHeader("Content-Length", String(contentLength));
    if (contentRange) res.setHeader("Content-Range", contentRange);
    res.setHeader("Cache-Control", "private, max-age=0, no-store");

    if (range && contentRange) res.status(206);

    if (!obj.Body) return res.status(500).send("Recording body missing");
    obj.Body.pipe(res);
    return;
  } catch (e) {
    // eslint-disable-next-line no-console
    logger.warn({ requestId: req.requestId, err: String(e?.name || e?.message || e) }, "Recording playback stream failed");
    sendAlert("recording_playback_failed", { requestId: req.requestId, error: String(e?.name || e?.message || e) });
    return res.status(500).send("Failed to stream recording");
  }
});

// Return a playback-friendly recording URL (audio tag can't send Authorization headers).
app.get("/api/calls/:id/recording-url", requireAuth, async (req, res) => {
  const { id } = req.params;
  const call = USE_DB ? await store.getCall(req.workspace.id, id) : readCalls().find((c) => c.id === id);
  if (!call) return res.status(404).json({ error: "Call not found" });
  if (!call.recording) return res.status(404).json({ error: "No recording" });

  // S3 egress recording (preferred): return a short-lived presigned URL.
  if (call.recording.kind === "egress_s3") {
    if (call.recording.status !== "ready") {
      return res.status(409).json({ error: "Recording not ready", status: call.recording.status });
    }
    try {
      const expMs = Date.now() + 30 * 60 * 1000;
      const token = signRecordingPlaybackToken({ callId: id, expMs });
      if (!token) {
        return res.status(500).json({
          error: "Recording playback is not configured (set RECORDING_PLAYBACK_SECRET or AGENT_SHARED_SECRET)",
        });
      }
      const base = getPublicApiBaseUrl(req);
      const url = `${base}/api/calls/${encodeURIComponent(id)}/recording-playback?token=${encodeURIComponent(token)}`;
      return res.json({ url, expiresInSeconds: 60 * 30 });
    } catch (e) {
      return res.status(500).json({ error: "Failed to create recording playback URL" });
    }
  }

  // Local uploaded recording: served by express.static(/recordings) with no auth required.
  if (call.recording.url) {
    return res.json({ url: call.recording.url });
  }

  return res.status(404).json({ error: "No recording URL" });
});

// Preview TTS voice audio for the dashboard (used by Voice Configuration UI).
// Returns audio/mpeg (ElevenLabs) or audio/wav (Cartesia bytes endpoint returns raw PCM which we wrap as WAV).
app.post("/api/tts/preview", requireAuth, async (req, res) => {
  const schema = z.object({
    provider: z.enum(["elevenlabs", "cartesia"]),
    model: z.string().min(1).max(120).optional(),
    voiceId: z.string().min(1).max(120),
    text: z.string().min(1).max(300),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

  const provider = parsed.data.provider;
  const text = parsed.data.text;

  try {
    if (provider === "elevenlabs") {
      // LiveKit docs use ELEVEN_API_KEY; keep ELEVENLABS_API_KEY for backward compat.
      const apiKey = String(process.env.ELEVEN_API_KEY || process.env.ELEVENLABS_API_KEY || "").trim();
      if (!apiKey) return res.status(500).json({ error: "ELEVEN_API_KEY (or ELEVENLABS_API_KEY) is not set on the server" });
      const modelId = parsed.data.model || "eleven_flash_v2_5";

      const r = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${encodeURIComponent(parsed.data.voiceId)}`, {
        method: "POST",
        headers: {
          "xi-api-key": apiKey,
          "content-type": "application/json",
          accept: "audio/mpeg",
        },
        body: JSON.stringify({
          text,
          model_id: modelId,
          voice_settings: { stability: 0.45, similarity_boost: 0.8, style: 0.25, use_speaker_boost: true },
        }),
      });

      if (!r.ok) {
        const errTxt = await r.text().catch(() => "");
        return res.status(502).json({ error: `ElevenLabs preview failed (${r.status})`, details: errTxt.slice(0, 500) });
      }

      res.setHeader("Content-Type", "audio/mpeg");
      res.setHeader("Cache-Control", "no-store");
      const buf = Buffer.from(await r.arrayBuffer());
      return res.status(200).send(buf);
    }

    // Cartesia (bytes endpoint -> raw PCM s16le). Wrap as WAV for browser playback.
    const apiKey = String(process.env.CARTESIA_API_KEY || "").trim();
    if (!apiKey) return res.status(500).json({ error: "CARTESIA_API_KEY is not set on the server" });
    const modelId = parsed.data.model || "sonic-2";
    const sampleRate = 24000;

    const payload = {
      model_id: modelId,
      voice: { mode: "id", id: parsed.data.voiceId },
      output_format: { container: "raw", encoding: "pcm_s16le", sample_rate: sampleRate },
      language: "en",
      transcript: text,
    };

    const r = await fetch("https://api.cartesia.ai/tts/bytes", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-API-Key": apiKey,
        "Cartesia-Version": "2025-04-16",
      },
      body: JSON.stringify(payload),
    });

    if (!r.ok) {
      const errTxt = await r.text().catch(() => "");
      return res.status(502).json({ error: `Cartesia preview failed (${r.status})`, details: errTxt.slice(0, 500) });
    }

    const pcm = Buffer.from(await r.arrayBuffer());
    const wav = wavFromPcmS16le(pcm, sampleRate);
    res.setHeader("Content-Type", "audio/wav");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(wav);
  } catch (e) {
    return res.status(500).json({ error: "Preview failed" });
  }
});

app.post("/api/calls/:id/end", requireAuth, async (req, res) => {
  const { id } = req.params;
  const schema = z.object({
    outcome: z.string().min(1).max(80).optional(),
    transcript: z
      .array(
        z.object({
          speaker: z.string().min(1).max(120),
          role: z.enum(["agent", "user"]),
          text: z.string().min(1).max(5000),
          final: z.boolean().optional(),
          firstReceivedTime: z.number().optional(),
        })
      )
      .optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

  const current = USE_DB ? await store.getCall(req.workspace.id, id) : readCalls().find((c) => c.id === id);
  if (!current) return res.status(404).json({ error: "Call not found" });
  const now = Date.now();
  const endedAt = current.endedAt ?? now;
  const durationSec = Math.max(0, Math.round((endedAt - current.startedAt) / 1000));

  let outcomeToStore = parsed.data.outcome ?? (current.outcome === "in_progress" ? "agent_hangup" : current.outcome);
  if (outcomeToStore === "ended" || outcomeToStore === "completed") outcomeToStore = "agent_hangup";
  const next = {
    ...current,
    endedAt,
    durationSec,
    outcome: outcomeToStore,
    transcript: parsed.data.transcript ? parsed.data.transcript : current.transcript,
    updatedAt: now,
  };

  // Metrics: web end (best-effort; this endpoint is used by webtest UI)
  try {
    callsEndedTotal.inc({ source: "web", outcome: String(outcomeToStore || "completed") });
    callDurationSeconds.observe({ source: "web", outcome: String(outcomeToStore || "completed") }, Number(durationSec || 0));
    inProgressCallsGaugeValue = Math.max(0, inProgressCallsGaugeValue - 1);
  } catch {
    // ignore
  }

  // Stop egress recording immediately so recording length matches call end; then poll for ready/failed.
  if (next.recording && next.recording.kind === "egress_s3" && next.recording.egressId) {
    const egressId = next.recording.egressId;
    next.recording = { ...next.recording, status: "stopping" };
    try {
      await stopEgress(egressId);
    } catch (eStop) {
      logger.warn({ callId: id, egressId, err: String(eStop?.message || eStop) }, "[calls.end] stopEgress failed");
    }
    setTimeout(async () => {
      const started = Date.now();
      const maxMs = 90_000;
      const intervalMs = 2000;

      while (Date.now() - started < maxMs) {
        try {
          const info = await getEgressInfo(egressId);
          const status = info?.status;
          if (status === 3) {
            // EGRESS_COMPLETE — align stored duration with actual recording length
            if (USE_DB) {
              const c = await store.getCallById(id);
              if (c?.recording?.kind === "egress_s3") {
                let sizeBytes = c.recording.sizeBytes ?? null;
                try {
                  const h = await headObject({ bucket: c.recording.bucket, key: c.recording.key });
                  if (typeof h?.ContentLength === "number" && Number.isFinite(h.ContentLength)) sizeBytes = h.ContentLength;
                } catch {
                  // ignore
                }
                let durationSec = c.durationSec;
                const recordingDurationSec = egressDiffToDurationSec(info?.startedAt ?? info?.started_at, info?.endedAt ?? info?.ended_at);
                if (recordingDurationSec != null) durationSec = recordingDurationSec;
                await store.updateCall(id, {
                  recording: {
                    ...c.recording,
                    status: "ready",
                    sizeBytes,
                    ...(recordingDurationSec != null ? { durationSec: recordingDurationSec } : {}),
                  },
                  ...(durationSec != null ? { durationSec } : {}),
                });
              }
            } else {
              const calls3 = readCalls();
              const idx3 = calls3.findIndex((c) => c.id === id);
              if (idx3 !== -1 && calls3[idx3].recording?.kind === "egress_s3") {
                let sizeBytes = calls3[idx3].recording.sizeBytes ?? null;
                try {
                  const h = await headObject({ bucket: calls3[idx3].recording.bucket, key: calls3[idx3].recording.key });
                  if (typeof h?.ContentLength === "number" && Number.isFinite(h.ContentLength)) sizeBytes = h.ContentLength;
                } catch {
                  // ignore
                }
                calls3[idx3] = {
                  ...calls3[idx3],
                  recording: { ...calls3[idx3].recording, status: "ready", sizeBytes },
                  updatedAt: Date.now(),
                };
                writeCalls(calls3);
              }
            }
            return;
          }
          if (status === 4 || status === 5) {
            // EGRESS_FAILED / EGRESS_ABORTED
            if (USE_DB) {
              const c = await store.getCallById(id);
              if (c?.recording?.kind === "egress_s3") await store.updateCall(id, { recording: { ...c.recording, status: "failed" } });
            } else {
              const calls3 = readCalls();
              const idx3 = calls3.findIndex((c) => c.id === id);
              if (idx3 !== -1 && calls3[idx3].recording?.kind === "egress_s3") {
                calls3[idx3] = {
                  ...calls3[idx3],
                  recording: { ...calls3[idx3].recording, status: "failed" },
                  updatedAt: Date.now(),
                };
                writeCalls(calls3);
              }
            }
            return;
          }
        } catch {
          // ignore and keep polling
        }
        await new Promise((r) => setTimeout(r, intervalMs));
      }
    }, 0);
  }

  if (USE_DB) {
    const updatePayload = {
      endedAt: next.endedAt,
      durationSec: next.durationSec,
      outcome: next.outcome,
      transcript: next.transcript,
      recording: next.recording ?? null,
    };

    // Preset analysis (call_summary, in_voicemail, user_sentiment, call_successful) for every call with transcript
    if (next.transcript && next.transcript.length > 0) {
      const apiKey = String(process.env.OPENAI_API_KEY || "").trim();
      if (apiKey) {
        try {
          const transcriptText = transcriptToTextForAnalysis(next.transcript);
          const modelDefault = String(process.env.OPENAI_EVAL_MODEL || process.env.OPENAI_GENERATE_MODEL || "gpt-4.1-mini").trim();
          const presetResult = await runPresetAnalysis({ apiKey, model: modelDefault, transcriptText, outcome: outcomeToStore });
          updatePayload.metrics = { ...(current.metrics && typeof current.metrics === "object" ? current.metrics : {}), preset_analysis: presetResult };
        } catch (ePre) {
          logger.warn({ requestId: req.requestId, err: String(ePre?.message || ePre) }, "[calls.end] preset analysis failed");
        }
      }
    }

    // Post-call data extraction: if agent has extraction items and we have transcript, run LLM extraction.
    const extractionItems =
      current.agentId && next.transcript && next.transcript.length > 0
        ? (async () => {
            try {
              const agent = await store.getAgent(req.workspace.id, current.agentId);
              const items = Array.isArray(agent?.postCallDataExtraction) ? agent.postCallDataExtraction : [];
              if (items.length === 0) return null;
              const apiKey = String(process.env.OPENAI_API_KEY || "").trim();
              if (!apiKey) return null;
              const model =
                String(agent?.postCallExtractionModel || "").trim() ||
                String(process.env.OPENAI_EVAL_MODEL || process.env.OPENAI_GENERATE_MODEL || "gpt-4.1-mini").trim();
              const transcriptText = transcriptToTextForAnalysis(next.transcript);
              const results = await runPostCallExtraction({
                apiKey,
                model,
                transcriptText,
                extractionItems: items.map((it) => ({
                  name: it.name || "",
                  type: it.type,
                  description: it.description || it.name,
                  options: it.options,
                })),
              });
              return { analysisStatus: "completed", postCallExtractionResults: results };
            } catch (e) {
              logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[calls.end] post-call extraction failed");
              return { analysisStatus: "failed", postCallExtractionResults: [] };
            }
          })()
        : null;

    const extractionResult = await extractionItems;
    if (extractionResult) {
      updatePayload.analysisStatus = extractionResult.analysisStatus;
      updatePayload.postCallExtractionResults = extractionResult.postCallExtractionResults;
    }

    let updated = await store.updateCall(id, updatePayload);

    // Billing: emit usage to Metronome and attach cost to call for instant UI
    if (USE_DB && updated?.workspaceId) {
      try {
        const workspace = await store.getWorkspace(updated.workspaceId);
        const metronomeClient = require("./metronome/client");
        const billingUsage = require("./billing/usage");
        const costResult = await billingUsage.emitCallUsageAndComputeCost(updated, workspace, metronomeClient);
        if (costResult) {
          const withCost = await store.updateCall(id, {
            metrics: { ...(updated.metrics || {}), costBreakdown: costResult.costBreakdown, computedTotalCost: costResult.computedTotalCost },
          });
          if (withCost) updated = withCost;
        }
      } catch (eBilling) {
        logger.warn({ requestId: req.requestId, err: String(eBilling?.message || eBilling), callId: id }, "[calls.end] billing usage/cost failed");
      }
    }

    if (updated.agentId && updated.workspaceId) {
      try {
        const agent = await store.getAgent(updated.workspaceId, updated.agentId);
        if (agent) {
          sendAgentWebhook(agent, "call_ended", updated);
          if (updated.metrics?.preset_analysis || (extractionResult && (updated.analysisStatus || (updated.postCallExtractionResults && updated.postCallExtractionResults.length > 0)))) {
            sendAgentWebhook(agent, "call_analyzed", updated);
          }
        }
      } catch (e) {
        logger.warn({ requestId: req.requestId, err: String(e?.message || e) }, "[calls.end] webhook send failed");
      }
    }

    // Auto-evaluate in the background if enabled on the agent.
    if (updated?.agentId) {
      setTimeout(async () => {
        try {
          const agent = await store.getAgent(req.workspace.id, updated.agentId);
          if (!agent?.autoEvalEnabled) return;
          const apiKey = String(process.env.OPENAI_API_KEY || "").trim();
          if (!apiKey) return;
          const transcriptText = transcriptToTextForAnalysis(updated.transcript ?? []).slice(0, 9000);
          if (!transcriptText) return;
          const existing = await store.listCallEvaluations(req.workspace.id, updated.id);
          if (existing.some((e) => e.source === "auto")) return;
          const model = String(process.env.OPENAI_EVAL_MODEL || process.env.OPENAI_GENERATE_MODEL || "gpt-4.1-mini").trim();
          const raw = await openaiAutoEvaluateCall({
            apiKey,
            model,
            input: {
              agentName: agent?.name ?? updated.agentName ?? "Agent",
              prompt: agent?.promptPublished ?? agent?.promptDraft ?? "",
              outcome: updated.outcome ?? null,
              durationSec: updated.durationSec ?? null,
              transcript: transcriptText,
            },
          });
          const text = String(raw || "").trim();
          let details = null;
          try {
            details = JSON.parse(text);
          } catch {
            const start = text.indexOf("{");
            const end = text.lastIndexOf("}");
            if (start !== -1 && end !== -1 && end > start) {
              details = JSON.parse(text.slice(start, end + 1));
            }
          }
          if (!details || typeof details !== "object") return;
          const score = Math.max(0, Math.min(100, Math.round(Number(details.score ?? 0))));
          const summary = typeof details.summary === "string" ? details.summary : "";
          await store.createCallEvaluation(req.workspace.id, updated.id, {
            score,
            notes: summary,
            source: "auto",
            details,
          });
        } catch {
          // ignore auto-eval errors
        }
      }, 0);
    }
    return res.json({ call: updated });
  }

  const calls = readCalls();
  const idx = calls.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ error: "Call not found" });
  calls[idx] = next;
  writeCalls(calls);
  return res.json({ call: next });
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

// (kbUpload declared near top; keep route declarations above stable)

app.post("/api/calls/:id/recording", requireAuth, upload.single("file"), async (req, res) => {
  const { id } = req.params;
  const calls = readCalls();
  const idx = calls.findIndex((c) => c.id === id);
  if (idx === -1 && !USE_DB) return res.status(404).json({ error: "Call not found" });
  if (!req.file) return res.status(400).json({ error: "Missing file" });

  const ext = req.file.mimetype.includes("webm") ? "webm" : req.file.mimetype.includes("ogg") ? "ogg" : "bin";
  const filename = `${id}.${ext}`;
  const abs = path.join(RECORDINGS_DIR, filename);
  fs.writeFileSync(abs, req.file.buffer);

  const url = `/recordings/${filename}`;
  const now = Date.now();
  const recording = {
    filename,
    mime: req.file.mimetype,
    sizeBytes: req.file.size,
    url,
  };

  if (USE_DB) {
    const existing = await store.getCall(req.workspace.id, id);
    if (!existing) return res.status(404).json({ error: "Call not found" });
    const updated = await store.updateCall(id, { recording });
    if (!updated) return res.status(404).json({ error: "Call not found" });
    return res.json({ ok: true, recordingUrl: url, call: updated });
  }

  const next = { ...calls[idx], recording, updatedAt: now };
  calls[idx] = next;
  writeCalls(calls);
  return res.json({ ok: true, recordingUrl: url, call: next });
});

const port = Number(process.env.PORT || 8787);
async function main() {
  if (USE_DB) {
    try {
      await initSchema();
      // eslint-disable-next-line no-console
      console.log("Postgres: schema ready.");
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error("Postgres init failed:", e?.message || e);
      process.exit(1);
    }
  } else {
    // eslint-disable-next-line no-console
    logger.warn("DATABASE_URL not set; falling back to local JSON storage (./data/*.json).");
  }

  // Background cleanup: ensure "in_progress" calls don't stick forever.
  // If an agent/job never posts /end, we cap the call at STALE_MS and mark it stale_timeout.
  if (USE_DB) {
    const STALE_MS = 15 * 60 * 1000;
    const intervalMs = 60 * 1000;
    setInterval(async () => {
      try {
        const p = getPool();
        if (!p) return;
        const now = Date.now();
        const cutoff = now - STALE_MS;
        // Update in batches to avoid large locks.
        const { rows } = await p.query(
          `
          SELECT id, started_at
          FROM calls
          WHERE ended_at IS NULL
            AND outcome = 'in_progress'
            AND started_at < $1
          ORDER BY started_at ASC
          LIMIT 200
        `,
          [cutoff]
        );
        if (!rows.length) return;
        for (const r of rows) {
          const startedAt = Number(r.started_at || now);
          const endedAt = startedAt + STALE_MS;
          const durationSec = Math.max(0, Math.round(STALE_MS / 1000));
          // eslint-disable-next-line no-void
          void store.updateCall(String(r.id), { endedAt, durationSec, outcome: "stale_timeout" });
        }
      } catch {
        // ignore; best-effort cleanup
      }
    }, intervalMs);
  }

  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Server listening on http://localhost:${port}`);
    // eslint-disable-next-line no-console
    console.log(`CORS origin(s): ${clientOrigins.join(", ")}`);
    // eslint-disable-next-line no-console
    console.log(
      `Egress(S3) enabled: ${Boolean(process.env.EGRESS_S3_BUCKET && process.env.EGRESS_S3_REGION)} (bucket=${
        process.env.EGRESS_S3_BUCKET || "—"
      }, region=${process.env.EGRESS_S3_REGION || "—"})`
    );

    // Safe debug to catch common .env mistakes (like trailing spaces in keys).
    // eslint-disable-next-line no-console
    const envKeys = Object.keys(process.env);
    const egressKeys = envKeys.filter((k) => k.includes("EGRESS_S3_")).sort();
    const suspiciousKeys = envKeys
      .filter((k) => k.trim().startsWith("EGRESS_S3_") && k !== k.trim())
      .sort();
    // eslint-disable-next-line no-console
    console.log(
      `Egress(S3) env keys loaded: ${egressKeys
        .map((k) => {
          const v = process.env[k];
          const redacted =
            k.includes("SECRET") || k.includes("ACCESS_KEY") ? (v ? "***set***" : "—") : v || "—";
          return `${k}=${redacted}`;
        })
        .join(", ") || "none"}`
    );
    // eslint-disable-next-line no-console
    if (suspiciousKeys.length)
      console.log(`Egress(S3) WARNING: suspicious keys (whitespace): ${suspiciousKeys.join(", ")}`);

    // Auto-start outbound worker inside the main server process
    if (USE_DB) {
      outboundWorker.start();
      // eslint-disable-next-line no-console
      console.log("Outbound worker started (embedded in server)");
    }
  });
}

main();