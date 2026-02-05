const { nanoid } = require("nanoid");
const { logger } = require("./logger");
const store = require("./store_pg");
const { roomService } = require("./livekit");
const { scheduleNextAttempt } = require("./outbound_scheduler");
const { computeCapacity } = require("./outbound_queue_logic");
const { startOutboundCall } = require("./telephony/provider_twilio");

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
      emptyTimeout: 30,
      maxParticipants: 2,
    });
  } catch (e) {
    // If the room already exists, we can continue.
    const msg = String(e?.message || e);
    if (!/already exists/i.test(msg)) throw e;
  }
}

async function createOrUpdateCall({ workspaceId, job, callId, roomName, agent }) {
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

  if (job.dnc) {
    await store.updateOutboundJob(workspaceId, job.id, { status: "canceled", lastError: "DNC enabled" });
    await store.addOutboundJobLog(workspaceId, job.id, {
      level: "warn",
      message: "Job canceled due to DNC",
      meta: { jobId: job.id },
    });
    return;
  }

  const agent = await store.getAgent(workspaceId, job.agentId);
  if (!agent) {
    await store.updateOutboundJob(workspaceId, job.id, {
      status: "failed",
      lastError: "Agent not found",
    });
    await store.addOutboundJobLog(workspaceId, job.id, { level: "error", message: "Agent not found" });
    return;
  }

  const phoneNumbers = await store.listPhoneNumbers(workspaceId);
  const phoneRow =
    phoneNumbers.find((p) => p.outboundAgentId === job.agentId) ||
    phoneNumbers.find((p) => p.outboundAgentId) ||
    phoneNumbers[0];
  const outboundNumber = phoneRow?.e164 || "";
  if (!phoneRow || !outboundNumber) {
    await store.updateOutboundJob(workspaceId, job.id, {
      status: "failed",
      lastError: "No outbound phone number configured",
    });
    await store.addOutboundJobLog(workspaceId, job.id, { level: "error", message: "No outbound phone number configured" });
    return;
  }

  const roomName = job.roomName || `out-${job.id}`;
  const callId = job.callId || `out_${job.id}`;

  try {
    await ensureRoomWithMetadata({ roomName, job, agent, callId });
    await createOrUpdateCall({ workspaceId, job, callId, roomName, agent });

    await store.updateOutboundJob(workspaceId, job.id, { roomName, callId });

    const sipEndpoint = String(process.env.LIVEKIT_SIP_ENDPOINT || "").trim();
    const statusCallbackUrl = (() => {
      const base = String(process.env.PUBLIC_API_BASE_URL || "").trim();
      return base ? `${base.replace(/\/$/, "")}/webhooks/telephony` : null;
    })();
    if (!statusCallbackUrl) {
      logger.warn({ jobId: job.id }, "[outbound.worker] PUBLIC_API_BASE_URL not set; telephony events disabled");
    }

    const { providerCallId } = await startOutboundCall({
      job: { ...job, roomName },
      workspace,
      fromNumber: outboundNumber,
      sipEndpoint,
      sipUser: String(phoneRow.livekitSipUsername || "").trim(),
      sipPass: String(phoneRow.livekitSipPassword || "").trim(),
      statusCallbackUrl,
    });

    await store.updateOutboundJob(workspaceId, job.id, {
      status: "dialing",
      providerCallId,
      lastError: "",
      nextAttemptAt: null,
      lockedAt: now,
      lockedBy: WORKER_ID,
    });
    await store.addOutboundJobLog(workspaceId, job.id, {
      level: "info",
      message: "Outbound call started",
      meta: { providerCallId, roomName, from: outboundNumber, to: job.phoneE164 },
    });
  } catch (e) {
    const errMsg = String(e?.message || e);
    const attempts = Number(job.attempts || 0);
    const maxAttempts = Number(job.maxAttempts || 3);
    if (attempts >= maxAttempts) {
      await store.updateOutboundJob(workspaceId, job.id, { status: "failed", lastError: errMsg });
      await store.addOutboundJobLog(workspaceId, job.id, {
        level: "error",
        message: "Outbound call failed (max attempts reached)",
        meta: { error: errMsg },
      });
      return;
    }
    const nextAttemptAt = scheduleNextAttempt({ nowMs: now, attempts, timezone: job.timezone });
    await store.updateOutboundJob(workspaceId, job.id, {
      status: "queued",
      lastError: errMsg,
      nextAttemptAt,
    });
    await store.addOutboundJobLog(workspaceId, job.id, {
      level: "warn",
      message: "Outbound call failed, will retry",
      meta: { error: errMsg, nextAttemptAt },
    });
  }
}

async function tick() {
  if (!USE_DB) {
    logger.warn({ workerId: WORKER_ID }, "[outbound.worker] DATABASE_URL not set; outbound disabled");
    return;
  }

  const workspaces = await store.listWorkspaces();
  const maxTotal = getMaxTotal();

  for (const ws of workspaces) {
    const activeOutbound = await store.countOutboundActive(ws.id);
    const activeCalls = await store.countInProgressCalls(ws.id);
    const capacity = computeCapacity(maxTotal, activeOutbound + activeCalls);
    if (capacity <= 0) continue;

    const jobs = await store.claimOutboundJobs(ws.id, Date.now(), capacity, WORKER_ID);
    for (const job of jobs) {
      await handleJob(ws, job);
    }
  }
}

async function main() {
  logger.info({ workerId: WORKER_ID }, "[outbound.worker] starting");
  const intervalMs = getPollIntervalMs();
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
