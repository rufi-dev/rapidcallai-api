const test = require("node:test");
const assert = require("node:assert/strict");
const { scheduleNextAttempt } = require("../src/outbound_scheduler");

test("scheduleNextAttempt uses exponential backoff only", () => {
  process.env.OUTBOUND_BASE_BACKOFF_SEC = "60";
  const now = Date.now();
  const next = scheduleNextAttempt({ nowMs: now, attempts: 1 });
  assert.ok(next >= now + 60 * 1000);
});
