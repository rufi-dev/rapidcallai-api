const test = require("node:test");
const assert = require("node:assert/strict");
const { handleTelephonyEvent } = require("../src/outbound_events");

function createMockStore(job) {
  return {
    updateOutboundJob: async (_workspaceId, _id, patch) => {
      Object.assign(job, patch);
      job.updatedAt = Date.now();
      return job;
    },
    addOutboundJobLog: async () => null,
    updateCall: async () => null,
  };
}

test("handleTelephonyEvent marks job in_call on answered", async () => {
  const job = {
    id: "job1",
    workspaceId: "ws1",
    status: "dialing",
    attempts: 1,
    maxAttempts: 3,
    dnc: false,
    lockedAt: Date.now() - 4000,
    roomName: "room1",
    callId: "call1",
    recordingEnabled: false,
  };
  let dispatched = false;
  await handleTelephonyEvent({
    event: { providerCallId: "callSid", rawStatus: "answered" },
    job,
    workspace: { id: "ws1" },
    store: createMockStore(job),
    dispatchAgent: async () => {
      dispatched = true;
    },
    waitForAgentJoin: async () => true,
    metrics: {
      outboundCallsAnsweredTotal: { inc: () => {} },
      outboundTimeToAnswerSeconds: { observe: () => {} },
      outboundJobsFailedTotal: { inc: () => {} },
      outboundJobsDialedTotal: { inc: () => {} },
    },
  });
  assert.equal(job.status, "in_call");
  assert.ok(dispatched);
});

test("handleTelephonyEvent retries on failed when attempts remain", async () => {
  const job = {
    id: "job2",
    workspaceId: "ws1",
    status: "dialing",
    attempts: 1,
    maxAttempts: 3,
    dnc: false,
    timezone: "UTC",
  };
  await handleTelephonyEvent({
    event: { providerCallId: "callSid", rawStatus: "failed" },
    job,
    workspace: { id: "ws1" },
    store: createMockStore(job),
    scheduleNextAttempt: () => Date.now() + 60000,
    metrics: {
      outboundJobsFailedTotal: { inc: () => {} },
      outboundJobsDialedTotal: { inc: () => {} },
      outboundCallsAnsweredTotal: { inc: () => {} },
      outboundTimeToAnswerSeconds: { observe: () => {} },
    },
  });
  assert.equal(job.status, "queued");
  assert.ok(job.nextAttemptAt);
});

test("handleTelephonyEvent fails if agent never joins", async () => {
  const job = {
    id: "job3",
    workspaceId: "ws1",
    status: "dialing",
    attempts: 1,
    maxAttempts: 1,
    dnc: false,
    roomName: "room3",
    callId: "call3",
  };
  let hungUp = false;
  await handleTelephonyEvent({
    event: { providerCallId: "callSid", rawStatus: "answered" },
    job,
    workspace: { id: "ws1" },
    store: createMockStore(job),
    waitForAgentJoin: async () => false,
    hangupCall: async () => {
      hungUp = true;
    },
    metrics: {
      outboundJobsFailedTotal: { inc: () => {} },
      outboundCallsAnsweredTotal: { inc: () => {} },
      outboundTimeToAnswerSeconds: { observe: () => {} },
      outboundJobsDialedTotal: { inc: () => {} },
    },
  });
  assert.equal(job.status, "failed");
  assert.ok(hungUp);
});
