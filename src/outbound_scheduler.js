function clampInt(v, min, max) {
  const n = Math.round(Number(v || 0));
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function computeRetryDelayMs(attempts, baseSeconds) {
  const base = clampInt(baseSeconds ?? 60, 5, 3600);
  const exp = Math.max(0, Math.min(6, Number(attempts || 0) - 1));
  const delay = base * Math.pow(2, exp);
  return Math.min(delay, 24 * 60 * 60) * 1000;
}

function scheduleNextAttempt({ nowMs, attempts }) {
  const base = clampInt(process.env.OUTBOUND_BASE_BACKOFF_SEC ?? 60, 5, 3600);
  const delayMs = computeRetryDelayMs(attempts, base);
  return nowMs + delayMs;
}

module.exports = {
  computeRetryDelayMs,
  scheduleNextAttempt,
};
