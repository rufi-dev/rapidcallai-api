// Ensure `server/.env` is always used (even if Windows/global env vars exist but are empty).
require("dotenv").config({
  path: require("path").join(__dirname, "..", ".env"),
  override: true,
});

const express = require("express");
const cors = require("cors");
const { nanoid } = require("nanoid");
const { z } = require("zod");
const path = require("path");
const fs = require("fs");
const multer = require("multer");

const { readAgents, writeAgents, readCalls, writeCalls } = require("./storage");
const { roomService, createParticipantToken } = require("./livekit");
const { startCallEgress, stopEgress, getEgressInfo } = require("./egress");
const { getObject } = require("./s3");

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
app.use(express.json({ limit: "2mb" }));
const PROMPT_MAX = 20000;
const WELCOME_TEXT_MAX = 400;

const WelcomeConfigSchema = z
  .object({
    mode: z.enum(["ai", "user"]).optional(), // ai speaks first / user speaks first
    aiMessageMode: z.enum(["dynamic", "custom"]).optional(),
    aiMessageText: z.string().max(WELCOME_TEXT_MAX).optional(),
    aiDelaySeconds: z.number().min(0).max(10).optional(),
  })
  .optional();

const clientOrigin = process.env.CLIENT_ORIGIN || "http://localhost:5173";
app.use(
  cors({
    origin: clientOrigin,
    credentials: true,
  })
);

app.get("/health", (_req, res) => res.json({ ok: true }));

// Serve uploaded call recordings (web-test recordings)
const RECORDINGS_DIR = path.join(__dirname, "..", "recordings");
if (!fs.existsSync(RECORDINGS_DIR)) fs.mkdirSync(RECORDINGS_DIR, { recursive: true });
app.use("/recordings", express.static(RECORDINGS_DIR));

// --- Agent profiles (stored locally in ./data/agents.json) ---
app.get("/api/agents", (_req, res) => {
  res.json({ agents: readAgents() });
});

app.post("/api/agents", (req, res) => {
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
  res.status(201).json({ agent });
});

app.get("/api/agents/:id", (req, res) => {
  const { id } = req.params;
  const agents = readAgents();
  const agent = agents.find((a) => a.id === id);
  if (!agent) return res.status(404).json({ error: "Agent not found" });
  res.json({ agent });
});

app.put("/api/agents/:id", (req, res) => {
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

app.delete("/api/agents/:id", (req, res) => {
  const { id } = req.params;
  const agents = readAgents();
  const next = agents.filter((a) => a.id !== id);
  writeAgents(next);
  res.json({ ok: true });
});

// --- Start a voice session for an agent profile ---
app.post("/api/agents/:id/start", async (req, res) => {
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

  const agents = readAgents();
  const agent = agents.find((a) => a.id === id);
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
  const calls = readCalls();
  const now = Date.now();
  calls.unshift({
    id: callId,
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
    createdAt: now,
    updatedAt: now,
  });
  writeCalls(calls);

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
      const calls2 = readCalls();
      const idx = calls2.findIndex((c) => c.id === callId);
      if (idx !== -1) {
        calls2[idx] = {
          ...calls2[idx],
          recording: {
            kind: "egress_s3",
            egressId: e.egressId,
            bucket: e.bucket,
            key: e.key,
            status: "recording",
            url: `/api/calls/${callId}/recording`,
          },
          updatedAt: Date.now(),
        };
        writeCalls(calls2);
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
app.get("/api/calls", (_req, res) => {
  const calls = readCalls();
  res.json({
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

app.get("/api/calls/:id", (req, res) => {
  const { id } = req.params;
  const calls = readCalls();
  const call = calls.find((c) => c.id === id);
  if (!call) return res.status(404).json({ error: "Call not found" });
  res.json({ call });
});

// Called by the Python agent to attach per-call metrics (tokens/latency/cost) to the call record.
app.post("/api/calls/:id/metrics", (req, res) => {
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

  const calls = readCalls();
  const idx = calls.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ error: "Call not found" });

  const current = calls[idx];
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

  calls[idx] = next;
  writeCalls(calls);
  // eslint-disable-next-line no-console
  console.log(`Metrics saved for ${id}: tokens=${next.metrics?.tokensTotal ?? "—"} latencyMs=${next.metrics?.latency?.agent_turn_latency_ms_avg ?? "—"} costUsd=${next.costUsd ?? "—"}`);
  res.json({ call: next });
});

// --- Analytics ---
app.get("/api/analytics", (_req, res) => {
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

  res.json({
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

app.get("/api/agents/:id/analytics", (req, res) => {
  const { id } = req.params;
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
app.get("/api/calls/:id/recording", async (req, res) => {
  const { id } = req.params;
  const calls = readCalls();
  const call = calls.find((c) => c.id === id);
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

app.post("/api/calls/:id/end", (req, res) => {
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

  const calls = readCalls();
  const idx = calls.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ error: "Call not found" });

  const current = calls[idx];
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
            return;
          }
          if (status === 4 || status === 5) {
            // EGRESS_FAILED / EGRESS_ABORTED
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
            return;
          }
        } catch {
          // ignore and keep polling
        }
        await new Promise((r) => setTimeout(r, intervalMs));
      }
    }, 0);
  }

  calls[idx] = next;
  writeCalls(calls);
  res.json({ call: next });
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
});

app.post("/api/calls/:id/recording", upload.single("file"), (req, res) => {
  const { id } = req.params;
  const calls = readCalls();
  const idx = calls.findIndex((c) => c.id === id);
  if (idx === -1) return res.status(404).json({ error: "Call not found" });
  if (!req.file) return res.status(400).json({ error: "Missing file" });

  const ext = req.file.mimetype.includes("webm") ? "webm" : req.file.mimetype.includes("ogg") ? "ogg" : "bin";
  const filename = `${id}.${ext}`;
  const abs = path.join(RECORDINGS_DIR, filename);
  fs.writeFileSync(abs, req.file.buffer);

  const url = `/recordings/${filename}`;
  const now = Date.now();
  const next = {
    ...calls[idx],
    recording: {
      filename,
      mime: req.file.mimetype,
      sizeBytes: req.file.size,
      url,
    },
    updatedAt: now,
  };
  calls[idx] = next;
  writeCalls(calls);
  res.json({ ok: true, recordingUrl: url, call: next });
});

const port = Number(process.env.PORT || 8787);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Server listening on http://localhost:${port}`);
  // eslint-disable-next-line no-console
  console.log(`CORS origin: ${clientOrigin}`);
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
  if (suspiciousKeys.length) console.log(`Egress(S3) WARNING: suspicious keys (whitespace): ${suspiciousKeys.join(", ")}`);
});