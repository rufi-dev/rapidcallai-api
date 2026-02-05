function mapTelephonyStatus(raw) {
  const v = String(raw || "").toLowerCase();
  if (v === "answered" || v === "in-progress") return "in_call";
  if (v === "ringing" || v === "queued" || v === "initiated") return "dialing";
  if (v === "completed") return "completed";
  if (v === "failed" || v === "busy" || v === "no-answer" || v === "canceled") return "failed";
  return "unknown";
}

async function handleTelephonyEvent({
  event,
  job,
  workspace,
  store,
  startCallEgress,
  dispatchAgent,
  waitForAgentJoin,
  hangupCall,
  scheduleNextAttempt,
  metrics,
  logger,
}) {
  const now = Date.now();
  const providerCallId = event.providerCallId;
  const rawStatus = event.rawStatus;
  const mapped = mapTelephonyStatus(rawStatus);

  if (mapped === "dialing") {
    if (metrics?.outboundJobsDialedTotal && job.status !== "dialing") metrics.outboundJobsDialedTotal.inc();
    await store.updateOutboundJob(job.workspaceId, job.id, { status: "dialing", updatedAt: now });
    await store.addOutboundJobLog(job.workspaceId, job.id, {
      level: "info",
      message: "Call ringing",
      meta: { providerCallId, status: rawStatus },
    });
    return { ok: true, status: "dialing" };
  }

  if (mapped === "in_call") {
    await store.updateOutboundJob(job.workspaceId, job.id, { status: "in_call", updatedAt: now });
    if (metrics?.outboundCallsAnsweredTotal) metrics.outboundCallsAnsweredTotal.inc();
    if (metrics?.outboundTimeToAnswerSeconds && job.lockedAt) {
      metrics.outboundTimeToAnswerSeconds.observe(Math.max(0, (now - Number(job.lockedAt || now)) / 1000));
    }
    await store.addOutboundJobLog(job.workspaceId, job.id, {
      level: "info",
      message: "Call answered",
      meta: { providerCallId },
    });

    if (job.recordingEnabled && job.roomName && job.callId && startCallEgress) {
      try {
        const e = await startCallEgress({ roomName: job.roomName, callId: job.callId });
        if (e.enabled) {
          const recording = {
            kind: "egress_s3",
            egressId: e.egressId,
            bucket: e.bucket,
            key: e.key,
            status: "recording",
            url: `/api/calls/${job.callId}/recording`,
          };
          await store.updateCall(job.callId, { recording });
        }
      } catch (e) {
        logger?.warn?.({ err: String(e?.message || e), jobId: job.id }, "[outbound] start egress failed");
      }
    }

    if (dispatchAgent && job.roomName) {
      try {
        await dispatchAgent(job);
      } catch (e) {
        logger?.warn?.({ err: String(e?.message || e), jobId: job.id }, "[outbound] dispatch failed");
      }
    }

    const joinTimeoutMs = Math.max(5_000, Math.min(60_000, Number(process.env.OUTBOUND_AGENT_JOIN_TIMEOUT_MS || 15_000)));
    const joined = job.roomName && waitForAgentJoin ? await waitForAgentJoin(job.roomName, joinTimeoutMs) : true;
    if (!joined) {
      await store.updateOutboundJob(job.workspaceId, job.id, {
        status: "failed",
        lastError: "Agent failed to join in time",
      });
      if (metrics?.outboundJobsFailedTotal) metrics.outboundJobsFailedTotal.inc({ reason: "agent_join_timeout" });
      await store.addOutboundJobLog(job.workspaceId, job.id, {
        level: "error",
        message: "Agent failed to join in time",
      });
      if (hangupCall) {
        try {
          await hangupCall({ workspace, providerCallId });
        } catch {
          // ignore
        }
      }
    }
    return { ok: true, status: "in_call" };
  }

  if (mapped === "completed") {
    await store.updateOutboundJob(job.workspaceId, job.id, { status: "completed", updatedAt: now });
    await store.addOutboundJobLog(job.workspaceId, job.id, {
      level: "info",
      message: "Call completed",
      meta: { providerCallId },
    });
    return { ok: true, status: "completed" };
  }

  if (mapped === "failed") {
    const attempts = Number(job.attempts || 0);
    const maxAttempts = Number(job.maxAttempts || 3);
    const shouldRetry = attempts < maxAttempts && !job.dnc;
    if (shouldRetry && scheduleNextAttempt) {
      const nextAttemptAt = scheduleNextAttempt({ nowMs: now, attempts, timezone: job.timezone });
      await store.updateOutboundJob(job.workspaceId, job.id, {
        status: "queued",
        lastError: `Call failed: ${rawStatus || "failed"}`,
        nextAttemptAt,
      });
    } else {
      await store.updateOutboundJob(job.workspaceId, job.id, {
        status: "failed",
        lastError: `Call failed: ${rawStatus || "failed"}`,
      });
      if (metrics?.outboundJobsFailedTotal) metrics.outboundJobsFailedTotal.inc({ reason: "call_failed" });
    }
    await store.addOutboundJobLog(job.workspaceId, job.id, {
      level: "warn",
      message: "Call failed",
      meta: { providerCallId, status: rawStatus },
    });
    return { ok: true, status: "failed" };
  }

  return { ok: true, status: "unknown" };
}

module.exports = { mapTelephonyStatus, handleTelephonyEvent };
