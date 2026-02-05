function computeCapacity(maxConcurrent, active) {
  const max = Math.max(1, Math.floor(Number(maxConcurrent || 1)));
  const act = Math.max(0, Math.floor(Number(active || 0)));
  return Math.max(0, max - act);
}

function isJobClaimable(job, nowMs) {
  if (!job) return false;
  if (job.status !== "queued") return false;
  if (job.dnc) return false;
  if (typeof job.maxAttempts === "number" && typeof job.attempts === "number" && job.attempts >= job.maxAttempts) {
    return false;
  }
  if (job.nextAttemptAt != null && Number(job.nextAttemptAt) > Number(nowMs || 0)) return false;
  return true;
}

module.exports = { computeCapacity, isJobClaimable };
