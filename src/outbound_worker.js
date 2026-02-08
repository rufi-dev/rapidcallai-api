// When run directly (npm run outbound:worker), load .env for standalone mode.
if (require.main === module) {
  require("dotenv").config({
    path: require("path").join(__dirname, "..", ".env"),
    override: true,
  });
}

const { nanoid } = require("./id");
const { logger } = require("./logger");
const store = require("./store_pg");
const { roomService, agentDispatchService, sipClient, addNumberToOutboundTrunk, createOutboundTrunkForWorkspace, ensureOutboundTrunkUsesTls, ensureOutboundTrunkTransport } = require("./livekit");
const tw = require("./twilio");

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

/**
 * Ensure the workspace has a fully provisioned outbound SIP trunk.
 * Creates the Twilio SIP trunk, termination credentials, associates the phone number,
 * and creates a LiveKit outbound trunk — all automatically.
 * Returns the LiveKit outbound trunk ID, or null if provisioning failed.
 */
async function ensureWorkspaceOutboundTrunk(workspace, phoneRow) {
  if (!workspace.twilioSubaccountSid) return null;
  if (!phoneRow?.twilioNumberSid) return null;

  const subSid = workspace.twilioSubaccountSid;
  const wsId = workspace.id;

  // 1) Ensure Twilio SIP trunk on the subaccount.
  logger.info({ wsId, subSid, existingTrunkSid: workspace.twilioSipTrunkSid }, "[outbound] step 1: ensuring Twilio SIP trunk");
  const { trunkSid, domainName, secure } = await tw.ensureSipTrunk({
    subaccountSid: subSid,
    existingTrunkSid: workspace.twilioSipTrunkSid,
    workspaceId: wsId,
  });
  const isSecure = Boolean(secure);
  logger.info({ wsId, trunkSid, domainName, secure: isSecure }, "[outbound] step 1 done: Twilio SIP trunk ready");

  // 2) Ensure termination credentials.
  logger.info({ wsId, trunkSid, hasExistingCreds: Boolean(workspace.twilioSipCredUsername) }, "[outbound] step 2: ensuring SIP credentials");
  const { credUsername, credPassword } = await tw.ensureSipTrunkTerminationCreds({
    subaccountSid: subSid,
    trunkSid,
    existingUsername: workspace.twilioSipCredUsername,
    existingPassword: workspace.twilioSipCredPassword,
  });
  logger.info({ wsId, trunkSid, credUsername }, "[outbound] step 2 done: SIP credentials ready");

  // 3) Associate the phone number with the Twilio trunk (idempotent).
  logger.info({ wsId, trunkSid, numberSid: phoneRow.twilioNumberSid, e164: phoneRow.e164 }, "[outbound] step 3: associating number with Twilio trunk");
  try {
    await tw.associateNumberWithSipTrunk({
      subaccountSid: subSid,
      trunkSid,
      numberSid: phoneRow.twilioNumberSid,
    });
    logger.info({ wsId, trunkSid, e164: phoneRow.e164 }, "[outbound] step 3 done: number associated");
  } catch (e) {
    if (!String(e?.message || "").includes("already associated")) {
      logger.warn({ err: String(e?.message || e) }, "[outbound] step 3: associate number failed");
    } else {
      logger.info({ wsId, e164: phoneRow.e164 }, "[outbound] step 3: number already associated (ok)");
    }
  }

  // 3b) Ensure Origination URI → LiveKit SIP endpoint (required for inbound calls).
  const sipEndpoint = String(process.env.LIVEKIT_SIP_ENDPOINT || "").trim();
  if (sipEndpoint) {
    try {
      await tw.ensureSipTrunkOriginationUri({ subaccountSid: subSid, trunkSid, sipEndpoint, secure: isSecure });
      logger.info({ wsId, trunkSid, sipEndpoint, secure: isSecure }, "[outbound] step 3b done: origination URI ensured");
    } catch (e) {
      logger.warn({ err: String(e?.message || e) }, "[outbound] step 3b: origination URI failed (best-effort)");
    }
  }

  // 4) Create or reuse LiveKit outbound trunk.
  let lkTrunkId = workspace.livekitOutboundTrunkId;
  if (!lkTrunkId) {
    logger.info({ wsId, domainName, e164: phoneRow.e164, secure: isSecure }, "[outbound] step 4: creating LiveKit outbound trunk");
    const result = await createOutboundTrunkForWorkspace({
      workspaceId: wsId,
      twilioSipDomainName: domainName,
      credUsername,
      credPassword,
      numbers: [phoneRow.e164],
      secure: isSecure,
    });
    lkTrunkId = result.trunkId;
    // Explicitly ensure transport is correct (createOutboundTrunkForWorkspace should set it, but double-check)
    try {
      await ensureOutboundTrunkTransport(lkTrunkId, isSecure);
      logger.info({ wsId, lkTrunkId, secure: isSecure }, "[outbound] step 4a: ensured transport on new trunk");
    } catch (e) {
      logger.warn({ wsId, lkTrunkId, err: String(e?.message || e) }, "[outbound] step 4a: failed to ensure transport on new trunk (best-effort)");
    }
    logger.info({ wsId, lkTrunkId, domainName, secure: isSecure }, "[outbound] step 4 done: LiveKit outbound trunk created");
  } else {
    // Ensure existing trunk uses correct transport
    try {
      await ensureOutboundTrunkTransport(lkTrunkId, isSecure);
      logger.info({ wsId, lkTrunkId, secure: isSecure }, "[outbound] step 4a: ensured transport on existing trunk");
    } catch (e) {
      logger.warn({ wsId, lkTrunkId, err: String(e?.message || e) }, "[outbound] step 4a: failed to update trunk transport (best-effort)");
    }
    // Ensure the number is on the existing trunk.
    logger.info({ wsId, lkTrunkId, e164: phoneRow.e164 }, "[outbound] step 4: adding number to existing LiveKit outbound trunk");
    try {
      await addNumberToOutboundTrunk(lkTrunkId, phoneRow.e164);
    } catch {
      // May already be there.
    }
  }

  // 5) Persist everything.
  await store.updateWorkspace(wsId, {
    twilioSipTrunkSid: trunkSid,
    twilioSipDomainName: domainName,
    twilioSipCredUsername: credUsername,
    twilioSipCredPassword: credPassword,
    livekitOutboundTrunkId: lkTrunkId,
  });

  // Update the phone number record too.
  if (phoneRow.id) {
    await store.updatePhoneNumber(phoneRow.id, {
      livekitOutboundTrunkId: lkTrunkId,
    });
  }

  logger.info({ wsId, trunkSid, lkTrunkId, domainName, e164: phoneRow.e164 }, "[outbound] all steps done: outbound fully provisioned");
  return lkTrunkId;
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
  // Priority: metadata.fromNumber (user chose in UI) → agent-assigned number → first available
  const metaFromNumber = String(job.metadata?.fromNumber || "").trim();
  const phoneNumbers = await store.listPhoneNumbers(workspaceId);
  const phoneRow = metaFromNumber
    ? phoneNumbers.find((p) => p.e164 === metaFromNumber) || phoneNumbers[0]
    : phoneNumbers.find((p) => p.outboundAgentId === job.agentId) ||
      phoneNumbers.find((p) => p.outboundAgentId) ||
      phoneNumbers[0];
  const fromNumber = metaFromNumber || phoneRow?.e164 || "";
  if (!fromNumber) {
    await store.updateOutboundJob(workspaceId, job.id, { status: "failed", lastError: "No outbound phone number configured" });
    await store.addOutboundJobLog(workspaceId, job.id, { level: "error", message: "No outbound phone number configured" });
    return;
  }

  // Auto-provision: if workspace doesn't have a dedicated outbound trunk yet, create one now.
  // This repairs existing numbers that were bought before the auto-provisioning was added.
  let trunkId = getOutboundTrunkId(phoneRow);
  if (!trunkId || !workspace.livekitOutboundTrunkId) {
    try {
      const repaired = await ensureWorkspaceOutboundTrunk(workspace, phoneRow);
      if (repaired) {
        trunkId = repaired;
        logger.info({ workspaceId, trunkId }, "[outbound] auto-provisioned outbound trunk");
      }
    } catch (e) {
      logger.warn({ workspaceId, err: String(e?.message || e) }, "[outbound] auto-provision failed");
    }
  }

  if (!trunkId) {
    await store.updateOutboundJob(workspaceId, job.id, { status: "failed", lastError: "No SIP outbound trunk ID configured" });
    await store.addOutboundJobLog(workspaceId, job.id, { level: "error", message: "No SIP outbound trunk ID. Set it on the phone number or SIP_OUTBOUND_TRUNK_ID env." });
    return;
  }

  // Safety check: ensure correct transport is set on the trunk before dialing
  // Fetch secure status from Twilio trunk to determine correct transport
  try {
    let isSecure = false;
    if (workspace.twilioSipTrunkSid && workspace.twilioSubaccountSid) {
      try {
        const client = await tw.getSubaccountDirectClient(workspace.twilioSubaccountSid);
        const trunk = await client.trunking.v1.trunks(workspace.twilioSipTrunkSid).fetch();
        isSecure = Boolean(trunk.secure);
      } catch (e) {
        logger.warn({ workspaceId, err: String(e?.message || e) }, "[outbound] failed to fetch trunk secure status, defaulting to non-secure");
      }
    }
    await ensureOutboundTrunkTransport(trunkId, isSecure);
    logger.info({ workspaceId, trunkId, jobId: job.id, secure: isSecure }, "[outbound] ensured transport before dialing");
  } catch (e) {
    logger.warn({ workspaceId, trunkId, jobId: job.id, err: String(e?.message || e) }, "[outbound] failed to ensure transport before dialing (best-effort, may fail)");
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

// --- Instant trigger: call triggerNow() to run tick immediately (e.g. when a job is created) ---
let _tickPromise = null;

function triggerNow() {
  if (_tickPromise) return; // already running
  _tickPromise = tick()
    .catch((e) => {
      logger.error({ workerId: WORKER_ID, err: String(e?.message || e) }, "[outbound.worker] triggered tick failed");
    })
    .finally(() => {
      _tickPromise = null;
    });
}

// --- Start the worker loop (call once) ---
let _started = false;

function start() {
  if (_started) return;
  _started = true;

  if (!USE_DB) {
    logger.warn({ workerId: WORKER_ID }, "[outbound.worker] DATABASE_URL not set; outbound disabled");
    return;
  }

  const intervalMs = getPollIntervalMs();
  logger.info({ workerId: WORKER_ID, intervalMs, maxTotal: getMaxTotal() }, "[outbound.worker] started (embedded)");

  // Run first tick immediately
  triggerNow();

  setInterval(() => {
    triggerNow();
  }, intervalMs);
}

module.exports = { start, triggerNow };

// --- Standalone mode: npm run outbound:worker ---
if (require.main === module) {
  logger.info({ workerId: WORKER_ID, useDb: USE_DB }, "[outbound.worker] starting (standalone)");

  if (!USE_DB) {
    logger.error("[outbound.worker] DATABASE_URL not set, exiting");
    process.exit(1);
  }

  start();
}
