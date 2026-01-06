// Ensure `server/.env` is always used (even if Windows/global env vars exist but are empty).
require("dotenv").config({
  path: require("path").join(__dirname, "..", ".env"),
  override: true,
});

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { nanoid } = require("nanoid");
const { z } = require("zod");
const path = require("path");
const fs = require("fs");
const multer = require("multer");

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
const { getObject } = require("./s3");
const tw = require("./twilio");

function numEnv(name) {
  const v = process.env[name];
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function computeCostUsdFromUsage(usage) {
  if (!usage) return null;
  const llmInPer1k = numEnv("LLM_INPUT_USD_PER_1K");
  const llmOutPer1k = numEnv("LLM_OUTPUT_USD_PER_1K");
  const sttPerMin = numEnv("STT_USD_PER_MIN");
  const ttsPer1kChars = numEnv("TTS_USD_PER_1K_CHARS");

  let total = 0;
  let any = false;

  if (llmInPer1k != null && llmOutPer1k != null) {
    const inTok = Number(usage.llm_prompt_tokens || 0);
    const outTok = Number(usage.llm_completion_tokens || 0);
    total += (inTok / 1000) * llmInPer1k + (outTok / 1000) * llmOutPer1k;
    any = true;
  }

  if (sttPerMin != null) {
    const sec = Number(usage.stt_audio_duration || 0);
    total += (sec / 60) * sttPerMin;
    any = true;
  }

  if (ttsPer1kChars != null) {
    const chars = Number(usage.tts_characters_count || 0);
    total += (chars / 1000) * ttsPer1kChars;
    any = true;
  }

  if (!any) return null;
  return Math.round(total * 10000) / 10000;
}

const app = express();
// Allow larger prompts (still bounded to protect the server).
app.use(express.json({ limit: "10mb" }));
// Twilio webhooks POST as application/x-www-form-urlencoded by default.
app.use(express.urlencoded({ extended: false }));
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
  })
);

const USE_DB = Boolean(process.env.DATABASE_URL);
const DEFAULT_WORKSPACE_ID = "rapidcallai";

app.get("/health", (_req, res) => res.json({ ok: true }));

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
  req.workspace = workspace;
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

// --- Internal (used by the LiveKit agent to create/update call records) ---
app.post("/api/internal/telephony/inbound/start", requireAgentSecret, async (req, res) => {
  const schema = z.object({
    roomName: z.string().min(1).max(200),
    to: z.string().min(3).max(32), // trunk phone number (E.164)
    from: z.string().min(0).max(32).optional(), // caller phone number (E.164)
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Validation failed", details: parsed.error.flatten() });
  if (!USE_DB) return res.status(400).json({ error: "Internal endpoints require Postgres mode" });

  const to = parsed.data.to.trim();
  const from = String(parsed.data.from || "").trim();

  const phoneRow = await store.getPhoneNumberByE164(to);
  if (!phoneRow) return res.status(404).json({ error: "Phone number not found" });

  const agentId = phoneRow.inboundAgentId;
  if (!agentId) return res.status(400).json({ error: "Inbound agent not configured for this number" });

  const agent = await store.getAgent(phoneRow.workspaceId, agentId);
  if (!agent) return res.status(404).json({ error: "Inbound agent not found" });

  const promptDraft = agent.promptDraft ?? "";
  const promptPublished = agent.promptPublished ?? "";
  const promptUsed = (promptDraft && String(promptDraft).trim()) ? promptDraft : promptPublished;
  if (!promptUsed || String(promptUsed).trim().length === 0) {
    return res.status(400).json({ error: "Agent prompt is empty" });
  }

  const callId = `call_${nanoid(12)}`;
  const now = Date.now();
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
    metrics: null,
    createdAt: now,
    updatedAt: now,
  };

  await store.createCall(callRecord);

  // Start recording (egress) if configured.
  try {
    const e = await startCallEgress({ roomName: callRecord.roomName, callId });
    if (e) {
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
  } catch {
    // ignore
  }

  return res.status(201).json({
    callId,
    agent: { id: agent.id, name: agent.name },
    prompt: promptUsed,
    welcome: agent.welcome ?? {},
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

  const updated = await store.updateCall(id, {
    endedAt,
    durationSec,
    outcome: parsed.data.outcome ?? (current.outcome === "in_progress" ? "completed" : current.outcome),
    transcript: parsed.data.transcript ? parsed.data.transcript : current.transcript,
  });
  return res.json({ call: updated });
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
    const agent = await store.createAgent({ ...parsed.data, workspaceId: req.workspace.id });
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
    welcome: {
      mode: parsed.data.welcome?.mode ?? "user",
      aiMessageMode: parsed.data.welcome?.aiMessageMode ?? "dynamic",
      aiMessageText: parsed.data.welcome?.aiMessageText ?? "",
      aiDelaySeconds: parsed.data.welcome?.aiDelaySeconds ?? 0,
    },
    createdAt: now,
    updatedAt: now,
  };
  agents.unshift(agent);
  writeAgents(agents);
  return res.status(201).json({ agent });
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
  if (sipUser && sipPass) dial.sip({ username: sipUser, password: sipPass }, dest);
  else dial.sip(dest);
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

  const roomName = `agent-${id}-${nanoid(6)}`;
  const identity = `user-${nanoid(8)}`;
  const callId = `call_${nanoid(12)}`;

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
    metrics: null,
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
  // Create the room and embed the agent prompt in room metadata so the Python agent can read it.
  await rs.createRoom({
    name: roomName,
    metadata: JSON.stringify({
      call: { id: callId, to: "webtest" },
      agent: { id: agent.id, name: agent.name, prompt: promptUsed },
      welcome,
    }),
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
    return res.json({ calls });
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
      costUsd: c.costUsd,
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

// Called by the Python agent to attach per-call metrics (tokens/latency/cost) to the call record.
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

  const current = USE_DB ? await store.getCallById(id) : readCalls().find((c) => c.id === id);
  if (!current) return res.status(404).json({ error: "Call not found" });
  const usage = parsed.data.usage ?? current.metrics?.usage ?? null;
  const latency = parsed.data.latency ?? current.metrics?.latency ?? null;

  const costUsd = computeCostUsdFromUsage(usage) ?? current.costUsd ?? null;

  const llmIn = Number(usage?.llm_prompt_tokens || 0);
  const llmOut = Number(usage?.llm_completion_tokens || 0);
  const tokensTotal = llmIn + llmOut;

  const next = {
    ...current,
    costUsd,
    metrics: {
      usage,
      latency,
      tokensTotal,
    },
    updatedAt: Date.now(),
  };

  if (USE_DB) {
    const updated = await store.updateCall(id, { costUsd, metrics: next.metrics });
    // eslint-disable-next-line no-console
    console.log(
      `Metrics saved for ${id}: tokens=${updated?.metrics?.tokensTotal ?? "—"} latencyMs=${updated?.metrics?.latency?.agent_turn_latency_ms_avg ?? "—"} costUsd=${updated?.costUsd ?? "—"}`
    );
    return res.json({ call: updated });
  }

  const calls = readCalls();
  const idx = calls.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ error: "Call not found" });
  calls[idx] = next;
  writeCalls(calls);
  // eslint-disable-next-line no-console
  console.log(`Metrics saved for ${id}: tokens=${next.metrics?.tokensTotal ?? "—"} latencyMs=${next.metrics?.latency?.agent_turn_latency_ms_avg ?? "—"} costUsd=${next.costUsd ?? "—"}`);
  return res.json({ call: next });
});

// --- Analytics ---
app.get("/api/analytics", requireAuth, async (req, res) => {
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
        SUM(cost_usd) FILTER (WHERE ended_at IS NOT NULL AND cost_usd IS NOT NULL) AS total_cost_usd,
        SUM((metrics->>'tokensTotal')::BIGINT)
          FILTER (WHERE ended_at IS NOT NULL AND metrics IS NOT NULL AND (metrics->>'tokensTotal') IS NOT NULL) AS total_tokens
      FROM calls
      WHERE workspace_id=$1
    `,
      [req.workspace.id]
    );

    const r = rows[0] || {};
    const avgDurationSec = r.avg_duration_sec == null ? null : Math.round(Number(r.avg_duration_sec));
    const avgLatencyMs = r.avg_latency_ms == null ? null : Math.round(Number(r.avg_latency_ms));
    const totalCostUsd = r.total_cost_usd == null ? null : Math.round(Number(r.total_cost_usd) * 10000) / 10000;
    const totalTokens = r.total_tokens == null ? null : Number(r.total_tokens);

    return res.json({
      totals: {
        callCount: Number(r.call_count || 0),
        completedCallCount: Number(r.completed_call_count || 0),
        avgDurationSec,
        avgLatencyMs,
        totalCostUsd,
        totalTokens,
      },
    });
  }

  const calls = readCalls();
  const completed = calls.filter((c) => c.endedAt);
  const count = calls.length;
  const completedCount = completed.length;

  const avgDurationSec =
    completedCount === 0 ? null : Math.round(completed.reduce((a, c) => a + (c.durationSec || 0), 0) / completedCount);

  const latencyValues = completed
    .map((c) => c.metrics?.latency?.agent_turn_latency_ms_avg)
    .filter((v) => typeof v === "number" && Number.isFinite(v));
  const avgLatencyMs =
    latencyValues.length === 0 ? null : Math.round(latencyValues.reduce((a, v) => a + v, 0) / latencyValues.length);

  const costValues = completed.map((c) => c.costUsd).filter((v) => typeof v === "number" && Number.isFinite(v));
  const totalCostUsd = costValues.length ? Math.round(costValues.reduce((a, v) => a + v, 0) * 10000) / 10000 : null;

  const tokenValues = completed
    .map((c) => c.metrics?.tokensTotal)
    .filter((v) => typeof v === "number" && Number.isFinite(v));
  const totalTokens = tokenValues.length ? tokenValues.reduce((a, v) => a + v, 0) : null;

  return res.json({
    totals: {
      callCount: count,
      completedCallCount: completedCount,
      avgDurationSec,
      avgLatencyMs,
      totalCostUsd,
      totalTokens,
    },
  });
});

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
        SUM(cost_usd) FILTER (WHERE ended_at IS NOT NULL AND cost_usd IS NOT NULL) AS total_cost_usd,
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
        cost_usd,
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
    const totalCostUsd = r.total_cost_usd == null ? null : Math.round(Number(r.total_cost_usd) * 10000) / 10000;
    const totalTokens = r.total_tokens == null ? null : Number(r.total_tokens);

    const latest = latestRows[0] || null;

    return res.json({
      agentId: id,
      totals: {
        callCount: Number(r.call_count || 0),
        completedCallCount: Number(r.completed_call_count || 0),
        avgDurationSec,
        avgLatencyMs,
        totalCostUsd,
        totalTokens,
      },
      latest: latest
        ? {
            callId: latest.id,
            endedAt: latest.ended_at,
            durationSec: latest.duration_sec,
            costUsd: latest.cost_usd ?? null,
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

  const costValues = completed.map((c) => c.costUsd).filter((v) => typeof v === "number" && Number.isFinite(v));
  const totalCostUsd = costValues.length ? Math.round(costValues.reduce((a, v) => a + v, 0) * 10000) / 10000 : null;

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
      totalCostUsd,
      totalTokens,
    },
    latest: latest
      ? {
          callId: latest.id,
          endedAt: latest.endedAt,
          durationSec: latest.durationSec,
          costUsd: latest.costUsd ?? null,
          tokensTotal: latest.metrics?.tokensTotal ?? null,
          latencyMs: latest.metrics?.latency?.agent_turn_latency_ms_avg ?? null,
        }
      : null,
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

app.post("/api/calls/:id/end", requireAuth, async (req, res) => {
  const { id } = req.params;
  const schema = z.object({
    outcome: z.string().min(1).max(80).optional(),
    costUsd: z.number().min(0).optional(),
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

  const next = {
    ...current,
    endedAt,
    durationSec,
    outcome: parsed.data.outcome ?? (current.outcome === "in_progress" ? "completed" : current.outcome),
    costUsd: typeof parsed.data.costUsd === "number" ? parsed.data.costUsd : current.costUsd,
    transcript: parsed.data.transcript ? parsed.data.transcript : current.transcript,
    updatedAt: now,
  };

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
              if (c?.recording?.kind === "egress_s3") await store.updateCall(id, { recording: { ...c.recording, status: "ready" } });
            } else {
              const calls3 = readCalls();
              const idx3 = calls3.findIndex((c) => c.id === id);
              if (idx3 !== -1 && calls3[idx3].recording?.kind === "egress_s3") {
                calls3[idx3] = {
                  ...calls3[idx3],
                  recording: { ...calls3[idx3].recording, status: "ready" },
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
      costUsd: next.costUsd,
      transcript: next.transcript,
      recording: next.recording ?? null,
    });
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