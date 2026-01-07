// Fix corrupted call durations in Postgres.
// Many downstream billing calculations assume calls.duration_sec is in *seconds*.
// If a row accidentally stored milliseconds into duration_sec (or other corruption),
// minutes and costs become wildly inflated.
//
// This script recalculates duration_sec from ended_at - started_at and updates only rows
// that look clearly wrong.
//
// Usage:
//   node src/fix_call_durations.js --dry-run
//   node src/fix_call_durations.js --apply
//
// Optional:
//   --workspace <workspace_id>   (limit to one workspace)
//   --since-days <n>            (default: 3650)
//
// Notes:
// - Requires DATABASE_URL.
// - Does NOT touch cost_usd; it only corrects duration_sec.

const { Pool } = require("pg");

function hasFlag(flag) {
  return process.argv.includes(flag);
}

function getArg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return null;
  return process.argv[idx + 1] ?? null;
}

function roundInt(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0;
  return Math.round(x);
}

function normalizeDurationSec({ durationSecStored, startedAtMs, endedAtMs }) {
  const started = Number(startedAtMs || 0);
  const ended = Number(endedAtMs || 0);
  const derived = started > 0 && ended > 0 && ended >= started ? Math.max(0, Math.round((ended - started) / 1000)) : 0;

  const storedRaw = Number(durationSecStored);
  const storedOk = Number.isFinite(storedRaw) && storedRaw >= 0;
  const stored = storedOk ? Math.round(storedRaw) : null;

  const MAX_REASONABLE_SEC = 6 * 60 * 60; // 6h
  let use = stored != null ? stored : derived;
  let source = stored != null ? "stored" : "derived";
  const flags = [];

  if (stored != null) {
    if (stored > MAX_REASONABLE_SEC && derived > 0 && derived <= MAX_REASONABLE_SEC) {
      flags.push("stored_too_large_using_derived");
      use = derived;
      source = "derived";
    } else if (derived > 0) {
      const ratio = stored / Math.max(1, derived);
      if (ratio >= 10 || ratio <= 0.1) {
        flags.push("stored_mismatch_using_derived");
        use = derived;
        source = "derived";
      }
    } else if (stored > MAX_REASONABLE_SEC) {
      flags.push("stored_too_large_no_derived");
    }
  }

  if (!Number.isFinite(use) || use < 0) {
    use = 0;
    source = "derived";
    flags.push("invalid_duration_clamped");
  }

  return {
    durationSec: use,
    derivedSec: derived,
    storedSec: stored,
    source,
    flags,
  };
}

async function main() {
  const dryRun = hasFlag("--dry-run") || !hasFlag("--apply");
  const workspaceId = getArg("--workspace");
  const sinceDays = roundInt(getArg("--since-days") ?? 3650);
  const sinceMs = Date.now() - sinceDays * 24 * 60 * 60 * 1000;

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("Missing DATABASE_URL.");
    process.exit(1);
  }

  const sslEnabled = String(process.env.DATABASE_SSL ?? "true").toLowerCase() !== "false";
  const pool = new Pool({ connectionString, ssl: sslEnabled ? { rejectUnauthorized: false } : false });

  const where = [`ended_at IS NOT NULL`, `started_at >= $1`];
  const params = [sinceMs];
  if (workspaceId) {
    where.push(`workspace_id = $2`);
    params.push(workspaceId);
  }

  const q = `
    SELECT id, workspace_id, started_at, ended_at, duration_sec
    FROM calls
    WHERE ${where.join(" AND ")}
    ORDER BY started_at DESC
  `;

  const { rows } = await pool.query(q, params);
  console.log(`Scanned ${rows.length} calls (sinceDays=${sinceDays}${workspaceId ? ` workspace=${workspaceId}` : ""}).`);

  let toFix = [];
  for (const r of rows) {
    const n = normalizeDurationSec({
      durationSecStored: r.duration_sec,
      startedAtMs: r.started_at,
      endedAtMs: r.ended_at,
    });
    const stored = n.storedSec;
    const derived = n.derivedSec;

    // Decide if we should update:
    // - if stored is null but derived exists
    // - if normalizeDurationSec chooses derived AND derived differs from stored
    const should =
      (stored == null && derived > 0) ||
      (n.source === "derived" && stored != null && derived > 0 && stored !== derived);

    if (should) {
      toFix.push({
        id: r.id,
        workspaceId: r.workspace_id,
        storedSec: stored,
        derivedSec: derived,
        flags: n.flags,
      });
    }
  }

  console.log(`Will fix ${toFix.length} calls. Mode: ${dryRun ? "DRY RUN" : "APPLY"}.`);

  // Print a sample for sanity
  const sample = toFix.slice(0, 15);
  if (sample.length) {
    console.log("Sample fixes (first 15):");
    for (const s of sample) {
      console.log(`- ${s.id} ws=${s.workspaceId} stored=${s.storedSec} derived=${s.derivedSec} flags=${s.flags.join(",")}`);
    }
  }

  if (!dryRun && toFix.length) {
    // Apply in batches.
    const batchSize = 200;
    let updated = 0;
    for (let i = 0; i < toFix.length; i += batchSize) {
      const batch = toFix.slice(i, i + batchSize);
      const ids = batch.map((b) => b.id);

      // Build a CASE expression for per-row duration.
      const cases = batch.map((b, idx) => `WHEN id = $${idx + 2} THEN $${idx + 2 + batch.length}::int`).join(" ");
      const values = [];
      for (const b of batch) values.push(b.id);
      for (const b of batch) values.push(b.derivedSec);

      const sql = `
        UPDATE calls
        SET duration_sec = CASE ${cases} ELSE duration_sec END
        WHERE id = ANY($1::text[])
      `;
      await pool.query(sql, [ids, ...values]);
      updated += batch.length;
      console.log(`Updated ${updated}/${toFix.length}...`);
    }
    console.log(`Done. Updated ${updated} call rows.`);
  }

  await pool.end();
}

main().catch((e) => {
  console.error("fix_call_durations failed:", e?.message || e);
  process.exit(1);
});


