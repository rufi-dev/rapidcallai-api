// Ensure server/.env is loaded for the worker process.
require("dotenv").config({
  path: require("path").join(__dirname, "..", ".env"),
  override: true,
});

const { nanoid } = require("./id");
const { logger } = require("./logger");
const store = require("./store_pg");
const { roomService, agentDispatchService, sipClient } = require("./livekit");

const USE_DB = Boolean(process.env.DATABASE_URL);
const WORKER_ID = `outbound-worker-${nanoid(6)}`;

function getMaxTotal() {
  const v = Number(process.env.OUTBOUND_MAX_TOTAL || 20);
  return Number.isFinite(v) && v > 0 ? Math.min(200, Math.max(1, v)) : 20;
}

function getPollIntervalMs() {
  const v = Number(process.env.OUTBOUND_POLL_INTERVAL_MS || 2000);
  return Number.isFinite(v) && v > 0 ? Math.min(60_000, Math.max(500, v)) : 2000;
}

function getOutboundTrunkId(phoneRow) {
  // Priority: phone number config → env var
  const fromRow = phoneRow?.livekitOutboundTrunkId || null;
  if (fromRow) return fromRow;
  return String(process.env.SIP_OUTBOUND_TRUNK_ID || "").trim() || null;
}

function getAgentName() {
  return String(
    process.env.LIVEKIT_OUTBOUND_AGENT_NAME ||
    process.env.LIVEKIT_WEB_AGENT_NAME ||
    process.env.LIVEKIT_AGENT_NAME ||
    ""
  ).trim();
}

async function ensureRoomWithMetadata({ roomName, job, agent, callId }) {
  const rs = roomService();
  const promptDraft = agent.promptDraft ?? agent.prompt ?? "";
  const promptPublished = agent.promptPublished ?? "";
  const promptUsed = (promptDraft && String(promptDraft).trim()) ? promptDraft : promptPublished;
  if (!promptUsed || String(promptUsed).trim().length === 0) {
    throw new Error("Agent prompt is empty. Set a prompt before dialing.");
  }

  const metadata = {
    call: { id: callId, to: job.phoneE164, direction: "outbound", jobId: job.id },
    agent: {
      id: agent.id,
      name: agent.name,
      prompt: promptUsed,
      voice: agent.voice ?? {},
      llmModel: String(agent.llmModel || "").trim(),
      maxCallSeconds: Number(agent.maxCallSeconds || 0),
      knowledgeFolderIds: Array.isArray(agent.knowledgeFolderIds) ? agent.knowledgeFolderIds : [],
    },
    welcome: agent.welcome ?? {},
    outbound: {
      leadName: job.leadName ?? "",
      timezone: job.timezone ?? "UTC",
      metadata: job.metadata ?? {},
    },
  };

  try {
    await rs.createRoom({
      name: roomName,
      metadata: JSON.stringify(metadata),
      emptyTimeout: 60,
      maxParticipants: 3,
    });
  } catch (e) {
    const msg = String(e?.message || e);
    if (!/already exists/i.test(msg)) throw e;
  }
}

async function createCallRecord({ workspaceId, job, callId, roomName, agent }) {
  const existing = await store.getCallById(callId);
  const now = Date.now();
  if (existing) {
    await store.updateCall(callId, { updatedAt: now });
    return;
  }

  const callRecord = {
    id: callId,
    workspaceId,
    agentId: agent.id,
    agentName: agent.name,
    to: job.phoneE164,
    roomName,
    startedAt: now,
    endedAt: null,
    durationSec: null,
    outcome: "in_progress",
    costUsd: null,
    transcript: [],
    recording: null,
    metrics: { normalized: { source: "outbound" }, outbound: { jobId: job.id } },
    createdAt: now,
    updatedAt: now,
  };
  await store.createCall(callRecord);
}

async function handleJob(workspace, job) {
  const now = Date.now();
  const workspaceId = workspace.id;

  // DNC check
  if (job.dnc) {
    await store.updateOutboundJob(workspaceId, job.id, { status: "canceled", lastError: "DNC enabled" });
    await store.addOutboundJobLog(workspaceId, job.id, {
      level: "warn",
      message: "Job canceled due to DNC",
    });
    return;
  }

  // Resolve agent
  const agent = await store.getAgent(workspaceId, job.agentId);
  if (!agent) {
    await store.updateOutboundJob(workspaceId, job.id, { status: "failed", lastError: "Agent not found" });
    await store.addOutboundJobLog(workspaceId, job.id, { level: "error", message: "Agent not found" });
    return;
  }

  // Resolve outbound phone number + trunk ID
  const phoneNumbers = await store.listPhoneNumbers(workspaceId);
  const phoneRow =
    phoneNumbers.find((p) => p.outboundAgentId === job.agentId) ||
    phoneNumbers.find((p) => p.outboundAgentId) ||
    phoneNumbers[0];
  const fromNumber = phoneRow?.e164 || "";
  if (!phoneRow || !fromNumber) {
    await store.updateOutboundJob(workspaceId, job.id, { status: "failed", lastError: "No outbound phone number configured" });
    await store.addOutboundJobLog(workspaceId, job.id, { level: "error", message: "No outbound phone number configured" });
    return;
  }

  const trunkId = getOutboundTrunkId(phoneRow);
  if (!trunkId) {
    await store.updateOutboundJob(workspaceId, job.id, { status: "failed", lastError: "No SIP outbound trunk ID configured" });
    await store.addOutboundJobLog(workspaceId, job.id, { level: "error", message: "No SIP outbound trunk ID. Set it on the phone number or SIP_OUTBOUND_TRUNK_ID env." });
    return;
  }

  const roomName = job.roomName || `out-${job.id}`;
  const callId = job.callId || `out_${job.id}`;

  try {
    // 1) Create room with agent metadata
    await ensureRoomWithMetadata({ roomName, job, agent, callId });

    // 2) Create call record
    await createCallRecord({ workspaceId, job, callId, roomName, agent });

    // 3) Update job with room/call info (already 'dialing' from claimOutboundJobs)
    await store.updateOutboundJob(workspaceId, job.id, {
      roomName,
      callId,
      lastError: "",
    });

    // 4) Dispatch agent to room (so it's ready when callee picks up)
    const agentName = getAgentName();
    if (agentName) {
      try {
        const dc = agentDispatchService();
        await dc.createDispatch(roomName, agentName, {
          metadata: JSON.stringify({ source: "outbound", jobId: job.id, callId }),
        });
        logger.info({ jobId: job.id, roomName, agentName }, "[outbound] agent dispatched");
      } catch (e) {
        logger.warn({ err: String(e?.message || e), jobId: job.id }, "[outbound] agent dispatch failed");
      }
    }

    // 5) Dial the phone number via LiveKit SIP (CreateSIPParticipant)
    await store.addOutboundJobLog(workspaceId, job.id, {
      level: "info",
      message: "Dialing via LiveKit SIP",
      meta: { trunkId, roomName, from: fromNumber, to: job.phoneE164 },
    });

    const sip = sipClient();
    const sipParticipant = await sip.createSipParticipant(
      trunkId,
      job.phoneE164,
      roomName,
      {
        participantIdentity: `sip-${job.phoneE164}`,
        participantName: job.leadName || job.phoneE164,
        fromNumber: fromNumber,
        waitUntilAnswered: true,
      }
    );

    // If we get here, the call was answered
    logger.info({ jobId: job.id, participantId: sipParticipant?.sipParticipantId }, "[outbound] call answered");

    await store.updateOutboundJob(workspaceId, job.id, {
      status: "in_call",
      providerCallId: sipParticipant?.sipParticipantId || null,
      lastError: "",
    });
    await store.addOutboundJobLog(workspaceId, job.id, {
      level: "info",
      message: "Call answered",
      meta: { sipParticipantId: sipParticipant?.sipParticipantId },
    });

  } catch (e) {
    const errMsg = String(e?.message || e);
    const attempts = Number(job.attempts || 0);
    const maxAttempts = Number(job.maxAttempts || 3);

    // Extract SIP status if available (TwirpError from LiveKit)
    const sipStatus = e?.metadata?.sip_status_code || null;
    const sipMsg = e?.metadata?.sip_status || null;
    const fullError = sipStatus ? `SIP ${sipStatus}: ${sipMsg || errMsg}` : errMsg;

    logger.warn({ jobId: job.id, err: fullError, sipStatus }, "[outbound] call failed");

    if (attempts >= maxAttempts) {
      await store.updateOutboundJob(workspaceId, job.id, { status: "failed", lastError: fullError });
      await store.addOutboundJobLog(workspaceId, job.id, {
        level: "error",
        message: "Call failed (max attempts reached)",
        meta: { error: fullError, sipStatus },
      });
    } else {
      // Retry with exponential backoff
      const baseBackoffSec = Math.max(30, Number(process.env.OUTBOUND_BASE_BACKOFF_SEC || 60));
      const delayMs = baseBackoffSec * Math.pow(2, Math.max(0, attempts - 1)) * 1000;
      const nextAttemptAt = now + Math.min(delayMs, 24 * 60 * 60 * 1000);

      await store.updateOutboundJob(workspaceId, job.id, {
        status: "queued",
        lastError: fullError,
        nextAttemptAt,
      });
      await store.addOutboundJobLog(workspaceId, job.id, {
        level: "warn",
        message: "Call failed, will retry",
        meta: { error: fullError, sipStatus, nextAttemptAt },
      });
    }
  }
}

async function tick() {
  if (!USE_DB) {
    logger.warn({ workerId: WORKER_ID }, "[outbound.worker] DATABASE_URL not set; outbound disabled");
    return;
  }

  const maxTotal = getMaxTotal();
  const workspaces = await store.listWorkspaces();

  for (const ws of workspaces) {
    const activeOutbound = await store.countOutboundActive(ws.id);
    const activeCalls = await store.countInProgressCalls(ws.id);
    const capacity = Math.max(0, maxTotal - (activeOutbound + activeCalls));
    if (capacity <= 0) continue;

    const jobs = await store.claimOutboundJobs(ws.id, Date.now(), capacity, WORKER_ID);

    // Process jobs concurrently (each is independent)
    await Promise.allSettled(jobs.map((job) => handleJob(ws, job)));
  }
}

async function main() {
  logger.info({ workerId: WORKER_ID, useDb: USE_DB }, "[outbound.worker] starting");

  if (!USE_DB) {
    logger.error("[outbound.worker] DATABASE_URL not set, exiting");
    process.exit(1);
  }

  const intervalMs = getPollIntervalMs();
  logger.info({ intervalMs, maxTotal: getMaxTotal() }, "[outbound.worker] polling");

  // Run first tick immediately
  await tick();

  setInterval(() => {
    tick().catch((e) => {
      logger.error({ workerId: WORKER_ID, err: String(e?.message || e) }, "[outbound.worker] tick failed");
    });
  }, intervalMs);
}

main().catch((e) => {
  logger.error({ workerId: WORKER_ID, err: String(e?.message || e) }, "[outbound.worker] fatal");
  process.exit(1);
});
