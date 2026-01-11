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
const { nanoid } = require("nanoid");
const { z } = require("zod");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const pdfParse = require("pdf-parse");
const promClient = require("prom-client");
const { WebhookReceiver } = require("livekit-server-sdk");

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
const { roomService, createParticipantToken } = require("./livekit");
const { startCallEgress, stopEgress, getEgressInfo } = require("./egress");
const { getObject, headObject } = require("./s3");
const tw = require("./twilio");
const { getBillingConfig } = require("./billing/config");
const { assertCanStartWebCall, assertCanBuyNumber, assertCanUsePstn } = require("./billing/gating");
const { finalizeBillingForCall } = require("./billing/finalize");
const stripeBilling = require("./billing/stripe");
const { provisionBillingForWorkspace } = require("./billing/provision");
const { createBillingRouter } = require("./billing/routes");
const { registerStripeWebhookRoute } = require("./billing/stripeWebhook");

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

// --- LiveKit Webhooks (for billed participant-minutes) ---
// Must be registered BEFORE express.json middleware so we can access raw body bytes.
app.post("/api/livekit/webhook", express.raw({ type: "application/webhook+json" }), async (req, res) => {
  const receiver = livekitWebhookReceiver();
  if (!receiver) return res.status(503).send("LiveKit not configured");

  try {
    const bodyStr = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : String(req.body || "");
    const auth = req.get("Authorization") || req.get("Authorize") || "";
    const ev = await receiver.receive(bodyStr, auth);

    const roomName = String(ev?.room?.name || "").trim();
    if (!roomName) return res.status(200).json({ ok: true });

    // Map LiveKit room -> call record by room_name.
    const call = await findCallByRoomName(roomName);
    if (!call) return res.status(200).json({ ok: true });

    const nowMs = Date.now();
    const tsMs = Number(ev?.createdAt) > 0 ? Number(ev.createdAt) : nowMs;
    const identity = String(ev?.participant?.identity || "").trim();

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

    const eventName = String(ev?.event || "").trim();

    if ((eventName === "participant_joined" || eventName === "room_started") && identity) {
      const p = participants[identity] && typeof participants[identity] === "object" ? participants[identity] : {};
      if (!p.joinedAtMs) {
        participants[identity] = { ...p, joinedAtMs: tsMs, lastSeenAtMs: tsMs };
      } else {
        participants[identity] = { ...p, lastSeenAtMs: tsMs };
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
    }

    if (eventName === "room_finished") {
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
    console.warn("[livekit.webhook] failed:", e?.message || e);
    return res.status(400).send("Invalid webhook");
  }
});

const USE_DB = Boolean(process.env.DATABASE_URL);
const DEFAULT_WORKSPACE_ID = "rapidcallai";

// Stripe webhooks MUST be registered before express.json middleware (we need the raw request body).
registerStripeWebhookRoute(app, { store: USE_DB ? store : null, stripeBilling });

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

// Allow one or many origins. Use comma-separated list in CLIENT_ORIGIN, e.g.:
// CLIENT_ORIGIN=https://dashboard.rapidcallai.com,http://localhost:5173
const clientOrigins = String(process.env.CLIENT_ORIGIN || "http://localhost:5173")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, cb) {
      // Allow non-browser requests (no Origin header)
      if (!origin) return cb(null, true);
      if (clientOrigins.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    // Explicitly allow auth header; without this, browsers can block the GET after a successful preflight.
    allowedHeaders: ["authorization", "content-type", "x-agent-secret"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    exposedHeaders: ["content-range", "accept-ranges", "content-length"],
    optionsSuccessStatus: 204,
  })
);

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

function getBearerToken(req) {
  const h = String(req.headers.authorization || "").trim();
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  return m[1].trim();
}

async function requireAuth(req, res, next) {
  // Local JSON mode stays "demo" for now.
  if (!USE_DB) {
    req.user = null;
    req.workspace = await ensureDefaultWorkspace();
    return next();
  }

  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: "Missing Authorization header" });

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
  // Best-effort: ensure Stripe/OpenMeter identifiers exist for this workspace.
  // Never block auth if provisioning fails.
  try {
    await provisionBillingForWorkspace({ store, stripeBilling, workspace, user });
  } catch (e) {
    console.warn("[billing.provision] failed", e?.message || e);
  }

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
app.post("/api/auth/register", async (req, res) => {
  const schema = z.object({
    name: z.string().min(1).max(80),
    email: z.string().email().max(200),
    password: z.string().min(6).max(200),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

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
  const workspace = await store.ensureWorkspaceForUser({ user, nameHint: `${user.name || user.email} workspace` });

  return res.status(201).json({ token, user, workspace });
});

app.post("/api/auth/login", async (req, res) => {
  const schema = z.object({
    email: z.string().email().max(200),
    password: z.string().min(1).max(200),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });

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
  const workspace = await store.ensureWorkspaceForUser({ user, nameHint: `${user.name || user.email} workspace` });
  return res.json({ token, user, workspace });
});

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  if (USE_DB && req.sessionToken) await store.deleteSession(req.sessionToken);
  return res.json({ ok: true });
});

app.get("/api/me", requireAuth, async (req, res) => {
  return res.json({ user: req.user, workspace: req.workspace });
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

// Billing API routes (Trial credits + Stripe + OpenMeter)
app.use("/api/billing", requireAuth, createBillingRouter({ store: USE_DB ? store : null, stripeBilling }));

// --- Internal (used by the LiveKit agent to create/update call records) ---
app.post("/api/internal/telephony/inbound/start", requireAgentSecret, async (req, res) => {
  const schema = z.object({
    roomName: z.string().min(1).max(200),
    to: z.string().min(3).max(32), // trunk phone number (E.164)
    from: z.string().min(0).max(32).optional(), // caller phone number (E.164)
    twilioCallSid: z.string().min(0).max(64).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  if (!USE_DB) return res.status(400).json({ error: "Internal endpoints require Postgres mode" });

  const to = parsed.data.to.trim();
  const from = String(parsed.data.from || "").trim();
  const twilioCallSid = String(parsed.data.twilioCallSid || "").trim();

  // eslint-disable-next-line no-console
  console.log("[internal.telephony.inbound.start]", { roomName: parsed.data.roomName, to, from });

  const phoneRow = await store.getPhoneNumberByE164(to);
  if (!phoneRow) {
    // eslint-disable-next-line no-console
    console.log("[internal.telephony.inbound.start] phone number not found", { to });
    return res.status(404).json({ error: "Phone number not found" });
  }

  // Billing gating: PSTN is PAID only (unless TRIAL_ALLOW_PSTN is explicitly enabled).
  const ws = await store.getWorkspace(phoneRow.workspaceId);
  if (!ws) return res.status(404).json({ error: "Workspace not found" });
  try {
    assertCanUsePstn(ws, getBillingConfig());
  } catch (e) {
    return res.status(Number(e?.status || 402)).json({ error: e?.message || "Billing gating" });
  }

  const agentId = phoneRow.inboundAgentId;
  if (!agentId) {
    // eslint-disable-next-line no-console
    console.log("[internal.telephony.inbound.start] inbound agent not configured", { to, phoneNumberId: phoneRow.id });
    return res.status(400).json({ error: "Inbound agent not configured for this number" });
  }

  const agent = await store.getAgent(phoneRow.workspaceId, agentId);
  if (!agent) {
    // eslint-disable-next-line no-console
    console.log("[internal.telephony.inbound.start] inbound agent not found", { agentId, workspaceId: phoneRow.workspaceId });
    return res.status(404).json({ error: "Inbound agent not found" });
  }

  const promptDraft = agent.promptDraft ?? "";
  const promptPublished = agent.promptPublished ?? "";
  const promptUsed = (promptDraft && String(promptDraft).trim()) ? promptDraft : promptPublished;
  if (!promptUsed || String(promptUsed).trim().length === 0) {
    // eslint-disable-next-line no-console
    console.log("[internal.telephony.inbound.start] agent prompt empty", { agentId: agent.id });
    return res.status(400).json({ error: "Agent prompt is empty" });
  }

  const callId = `call_${nanoid(12)}`;
  const now = Date.now();
  callsStartedTotal.inc({ source: "telephony" });
  inProgressCallsGaugeValue += 1;
  const callRecord = {
    id: callId,
    workspaceId: phoneRow.workspaceId,
    agentId: agent.id,
    agentName: agent.name,
    to: from || "unknown",
    roomName: parsed.data.roomName,
    startedAt: now,
    endedAt: null,
    durationSec: null,
    outcome: "in_progress",
    costUsd: null,
    transcript: [],
    recording: null,
    metrics: {
      normalized: { source: "telephony" },
      telephony: {
        trunkNumber: to,
        callerNumber: from || "",
        twilioCallSid: twilioCallSid || undefined,
      },
    },
    createdAt: now,
    updatedAt: now,
  };

  await store.createCall(callRecord);

  // Start recording (egress) if configured.
  try {
    const e = await startCallEgress({ roomName: callRecord.roomName, callId });
    if (e && e.enabled) {
      const recording = {
        kind: "egress_s3",
        egressId: e.egressId,
        bucket: e.bucket,
        key: e.key,
        status: "recording",
        url: `/api/calls/${encodeURIComponent(callId)}/recording`,
      };
      await store.updateCall(callId, { recording });
    }
  } catch (e) {
    console.warn("[internal.telephony.inbound.start] failed to start egress", e?.message || e);
  }

  return res.status(201).json({
    callId,
    agent: { id: agent.id, name: agent.name },
    prompt: promptUsed,
    welcome: agent.welcome ?? {},
    voice: agent.voice ?? {},
    llmModel: String(agent.llmModel || ""),
    maxCallSeconds: Number(agent.maxCallSeconds || 0),
    knowledgeFolderIds: Array.isArray(agent.knowledgeFolderIds) ? agent.knowledgeFolderIds : [],
    phoneNumber: { id: phoneRow.id, e164: phoneRow.e164 },
  });
});

app.post("/api/internal/calls/:id/end", requireAgentSecret, async (req, res) => {
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
  if (!USE_DB) return res.status(400).json({ error: "Internal endpoints require Postgres mode" });

  const current = await store.getCallById(id);
  if (!current) return res.status(404).json({ error: "Call not found" });

  const now = Date.now();
  const endedAt = current.endedAt ?? now;
  const durationSec = Math.max(0, Math.round((endedAt - current.startedAt) / 1000));

  const outcomeToStore = parsed.data.outcome ?? (current.outcome === "in_progress" ? "completed" : current.outcome);
  const updated = await store.updateCall(id, {
    endedAt,
    durationSec,
    outcome: outcomeToStore,
    transcript: parsed.data.transcript ? parsed.data.transcript : current.transcript,
  });

  // Billing finalization (trial debit / OpenMeter event). Best-effort.
  try {
    await finalizeBillingForCall({ store, call: updated });
  } catch (e) {
    console.warn("[internal.calls.end] billing finalize failed", e?.message || e);
  }

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

      setTimeout(async () => {
        try {
          await stopEgress(egressId);
        } catch {
          // ignore
        }
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
                await store.updateCall(id, { recording: { ...c2.recording, status: "ready", sizeBytes } });
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

  return res.json({ call: updated });
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
  const cfg = getBillingConfig();
  const schema = z.object({
    name: z.string().min(1).max(60),
    promptDraft: z.string().max(PROMPT_MAX).optional(),
    promptPublished: z.string().max(PROMPT_MAX).optional(),
    welcome: WelcomeConfigSchema,
    voice: VoiceConfigSchema,
    llmModel: LlmModelSchema,
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
      llmModel: parsed.data.llmModel ?? cfg.defaultLlmModel,
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

app.put("/api/agents/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const schema = z.object({
    name: z.string().min(1).max(60).optional(),
    promptDraft: z.string().max(PROMPT_MAX).optional(),
    publish: z.boolean().optional(),
    welcome: WelcomeConfigSchema,
    voice: VoiceConfigSchema,
    llmModel: LlmModelSchema,
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
    const agent = await store.updateAgent(req.workspace.id, id, parsed.data);
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
    llmModel: parsed.data.llmModel ?? (current.llmModel ?? ""),
    knowledgeFolderIds: parsed.data.knowledgeFolderIds ?? (current.knowledgeFolderIds ?? []),
    maxCallSeconds:
      parsed.data.maxCallSeconds == null
        ? (current.maxCallSeconds ?? 0)
        : Math.max(0, Math.round(Number(parsed.data.maxCallSeconds || 0))),
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

  // Billing gating: phone number purchase always requires paid + payment method.
  if (USE_DB) {
    try {
      assertCanBuyNumber(ws, getBillingConfig());
    } catch (e) {
      return res.status(Number(e?.status || 402)).json({ error: e?.message || "Billing gating" });
    }
  }

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
    const { sid: subSid } = await tw.ensureSubaccount({
      friendlyName: `rapidcallai:${ws.name || ws.id}`,
      existingSid: ws.twilioSubaccountSid ?? null,
    });
    if (!ws.twilioSubaccountSid) {
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

    // Save as a phone number record.
    if (USE_DB) {
      const phoneNumber = await store.createPhoneNumber({
        workspaceId: ws.id,
        e164: purchased.phoneNumber,
        label: parsed.data.label ?? "",
        provider: "twilio",
        status: "unconfigured",
        twilioNumberSid: purchased.sid,
        allowedInboundCountries: ["all"],
        allowedOutboundCountries: ["all"],
      });

      // Keep Stripe phone-number monthly quantity in sync (best-effort).
      try {
        const wsLatest = await store.getWorkspace(ws.id);
        if (wsLatest?.stripeSubscriptionId && wsLatest?.stripePhoneNumbersItemId) {
          const all = await store.listPhoneNumbers(ws.id);
          await stripeBilling.updatePhoneNumbersQuantity({
            subscriptionId: wsLatest.stripeSubscriptionId,
            phoneNumbersItemId: wsLatest.stripePhoneNumbersItemId,
            quantity: all.length,
          });
        }
      } catch (e) {
        console.warn("[twilio.buy-number] failed to sync stripe quantity", e?.message || e);
      }
      return res.status(201).json({ phoneNumber, purchased });
    }

    const rows = readPhoneNumbers();
    const now = Date.now();
    const phoneNumber = {
      id: nanoid(10),
      workspaceId: ws.id,
      e164: purchased.phoneNumber,
      label: parsed.data.label ?? "",
      provider: "twilio",
      status: "unconfigured",
      twilioNumberSid: purchased.sid,
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
    // Billing gating: phone number creation requires paid + payment method.
    try {
      assertCanBuyNumber(req.workspace, getBillingConfig());
    } catch (e) {
      return res.status(Number(e?.status || 402)).json({ error: e?.message || "Billing gating" });
    }

    try {
      const phoneNumber = await store.createPhoneNumber({
        workspaceId,
        e164: parsed.data.e164,
        label: parsed.data.label ?? "",
        provider: parsed.data.provider ?? "twilio",
        status: "unconfigured",
        allowedInboundCountries: ["all"],
        allowedOutboundCountries: ["all"],
      });
      return res.status(201).json({ phoneNumber });
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
    await store.deletePhoneNumber(id);
    return res.json({ ok: true });
  }
  const rows = readPhoneNumbers().filter((p) => p.id !== id);
  writePhoneNumbers(rows);
  return res.json({ ok: true });
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

  let dest = `${to}@${sipEndpoint}`;
  if (!dest.startsWith("sip:")) dest = `sip:${dest}`;

  console.log("[twilio-inbound] dial", {
    twilioCallSid,
    to,
    from,
    dest,
    hasAuth: Boolean(sipUser && sipPass),
  });

  const dial = vr.dial({ answerOnBridge: true });
  // SIP auth is optional: it is recommended for Twilio Programmable Voice to prevent arbitrary calls hitting your SIP endpoint,
  // but LiveKit inbound trunks can also work without auth when configured by allowed numbers/dispatch rules.
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

// --- Start a voice session for an agent profile ---
app.post("/api/agents/:id/start", requireAuth, async (req, res) => {
  const { id } = req.params;
  const startSchema = z
    .object({
      welcome: WelcomeConfigSchema,
    })
    .optional();
  const startParsed = startSchema?.safeParse(req.body);
  if (startParsed && !startParsed.success) {
    return res.status(400).json({ error: "Validation failed", details: startParsed.error.flatten() });
  }

  // Trial gating (WEB only)
  if (USE_DB) {
    try {
      assertCanStartWebCall(req.workspace, getBillingConfig());
    } catch (e) {
      return res.status(Number(e?.status || 402)).json({ error: e?.message || "Billing gating" });
    }
  }

  const agent = USE_DB ? await store.getAgent(req.workspace.id, id) : readAgents().find((a) => a.id === id);
  if (!agent) return res.status(404).json({ error: "Agent not found" });
  const promptDraft = agent.promptDraft ?? agent.prompt ?? "";
  const promptPublished = agent.promptPublished ?? "";
  const promptUsed = (promptDraft && String(promptDraft).trim()) ? promptDraft : promptPublished;
  if (!promptUsed || String(promptUsed).trim().length === 0) {
    return res.status(400).json({ error: "Agent prompt is empty. Set a prompt before starting a session." });
  }

  const welcome = {
    mode: startParsed?.data?.welcome?.mode ?? agent.welcome?.mode ?? "user",
    aiMessageMode: startParsed?.data?.welcome?.aiMessageMode ?? agent.welcome?.aiMessageMode ?? "dynamic",
    aiMessageText: startParsed?.data?.welcome?.aiMessageText ?? agent.welcome?.aiMessageText ?? "",
    aiDelaySeconds: startParsed?.data?.welcome?.aiDelaySeconds ?? agent.welcome?.aiDelaySeconds ?? 0,
  };
  const voice = agent.voice ?? {};
  const llmModel = String(agent.llmModel || "").trim() || getBillingConfig().defaultLlmModel;
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
    metrics: { normalized: { source: "web" } },
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

  const rs = roomService();
  // When using named LiveKit Agents (agent_name), web rooms must explicitly request an agent dispatch.
  // Telephony dispatch rules only apply to inbound SIP calls; they won't start an agent for a normal web room.
  const webAgentName = String(process.env.LIVEKIT_WEB_AGENT_NAME || process.env.LIVEKIT_AGENT_NAME || "VoiceAgent").trim();
  // Create the room and embed the agent prompt in room metadata so the Python agent can read it.
  await rs.createRoom({
    name: roomName,
    metadata: JSON.stringify({
      call: { id: callId, to: "webtest" },
      agent: {
        id: agent.id,
        name: agent.name,
        prompt: promptUsed,
        voice,
        llmModel,
        maxCallSeconds,
        knowledgeFolderIds: Array.isArray(agent.knowledgeFolderIds) ? agent.knowledgeFolderIds : [],
      },
      welcome,
    }),
    agents: webAgentName
      ? [
          {
            agentName: webAgentName,
            metadata: JSON.stringify({ source: "webtest", callId, agentId: agent.id }),
          },
        ]
      : undefined,
    emptyTimeout: 10,
    maxParticipants: 2,
  });

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
    console.warn("Failed to start egress:", e?.message || e);
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
      calls: calls.map((c) => ({
        ...c,
        costUsd: typeof c.costUsd === "number" ? c.costUsd : null,
      })),
    });
  }
  const calls = readCalls();
  return res.json({
    calls: calls.map((c) => ({
      id: c.id,
      agentId: c.agentId,
      agentName: c.agentName,
      to: c.to,
      roomName: c.roomName,
      startedAt: c.startedAt,
      endedAt: c.endedAt,
      durationSec: c.durationSec,
      outcome: c.outcome,
      costUsd: typeof c.costUsd === "number" ? c.costUsd : null,
      recordingUrl: c.recording?.url ?? null,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
    })),
  });
});

app.get("/api/calls/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const call = USE_DB ? await store.getCall(req.workspace.id, id) : readCalls().find((c) => c.id === id);
  if (!call) return res.status(404).json({ error: "Call not found" });
  res.json({ call });
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
    console.warn("Recording stream failed:", e?.name || e?.message || e);
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
    console.warn("Recording playback stream failed:", e?.name || e?.message || e);
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

  const outcomeToStore = parsed.data.outcome ?? (current.outcome === "in_progress" ? "completed" : current.outcome);
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

  // Stop egress recording if it is running; finalize status in the background.
  if (next.recording && next.recording.kind === "egress_s3" && next.recording.egressId) {
    const egressId = next.recording.egressId;
    next.recording = { ...next.recording, status: "stopping" };

    // Background poll to update status to ready/failed.
    setTimeout(async () => {
      try {
        await stopEgress(egressId);
      } catch {
        // ignore
      }
      const started = Date.now();
      const maxMs = 90_000;
      const intervalMs = 2000;

      while (Date.now() - started < maxMs) {
        try {
          const info = await getEgressInfo(egressId);
          const status = info?.status;
          if (status === 3) {
            // EGRESS_COMPLETE
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
                await store.updateCall(id, { recording: { ...c.recording, status: "ready", sizeBytes } });
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
    const updated = await store.updateCall(id, {
      endedAt: next.endedAt,
      durationSec: next.durationSec,
      outcome: next.outcome,
      transcript: next.transcript,
      recording: next.recording ?? null,
    });

    // Billing finalization (trial debit / OpenMeter event). Best-effort.
    try {
      await finalizeBillingForCall({ store, call: updated });
    } catch (e) {
      console.warn("[calls.end] billing finalize failed", e?.message || e);
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

// KB uploads: smaller limit per PDF (text extraction + storage)
const kbUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
});

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
    console.warn("DATABASE_URL not set; falling back to local JSON storage (./data/*.json).");
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
  });
}

main();