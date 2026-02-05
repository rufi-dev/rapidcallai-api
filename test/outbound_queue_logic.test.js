const test = require("node:test");
const assert = require("node:assert/strict");
const { computeCapacity, isJobClaimable } = require("../src/outbound_queue_logic");

test("computeCapacity enforces max concurrent", () => {
  assert.equal(computeCapacity(5, 2), 3);
  assert.equal(computeCapacity(3, 5), 0);
});

test("isJobClaimable respects status, dnc, and nextAttemptAt", () => {
  const now = Date.now();
  assert.equal(isJobClaimable({ status: "queued", dnc: false, attempts: 0, maxAttempts: 3 }, now), true);
  assert.equal(isJobClaimable({ status: "dialing", dnc: false }, now), false);
  assert.equal(isJobClaimable({ status: "queued", dnc: true }, now), false);
  assert.equal(isJobClaimable({ status: "queued", dnc: false, attempts: 3, maxAttempts: 3 }, now), false);
  assert.equal(isJobClaimable({ status: "queued", dnc: false, nextAttemptAt: now + 60000 }, now), false);
});
