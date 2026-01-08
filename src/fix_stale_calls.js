// Fix calls that were incorrectly "auto-ended" at read-time (stale cleanup) with endedAt=now,
// which can create hours/days of phantom minutes when the agent never posted /end.
//
// This script finds suspicious "completed" calls that:
// - have ended_at set
// - have little/no metrics + empty transcript
// - have duration_sec much larger than the configured stale timeout
// and converts them to outcome='stale_timeout' and caps duration to the stale timeout.
//
// Usage:
//   node src/fix_stale_calls.js --dry-run
//   node src/fix_stale_calls.js --apply
//
// Optional:
//   --workspace <workspace_id>
//   --stale-seconds <n>     (default: 900)
//   --min-duration-seconds <n> (default: 1800) only fix if duration exceeds this

const { Pool } = require("pg");

function hasFlag(flag) {
  return process.argv.includes(flag);
}

function getArg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return null;
  return process.argv[idx + 1] ?? null;
}

function intArg(name, def) {
  const v = getArg(name);
  const n = v == null ? NaN : Number(v);
  return Number.isFinite(n) ? Math.round(n) : def;
}

async function main() {
  const dryRun = hasFlag("--dry-run") || !hasFlag("--apply");
  const workspaceId = getArg("--workspace");
  const staleSeconds = intArg("--stale-seconds", 15 * 60);
  const minDurationSeconds = intArg("--min-duration-seconds", 30 * 60);

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.error("Missing DATABASE_URL.");
    process.exit(1);
  }
  const sslEnabled = String(process.env.DATABASE_SSL ?? "true").toLowerCase() !== "false";
  const pool = new Pool({ connectionString, ssl: sslEnabled ? { rejectUnauthorized: false } : false });

  const where = [
    `ended_at IS NOT NULL`,
    `outcome = 'completed'`,
    `(duration_sec IS NOT NULL AND duration_sec >= $1)`,
    // metrics either null or missing usage/latency/cost blocks
    `(metrics IS NULL OR (jsonb_typeof(metrics) = 'object' AND (metrics->'usage' IS NULL) AND (metrics->'cost' IS NULL)))`,
    // transcript empty
    `(transcript IS NULL OR transcript = '[]'::jsonb)`,
  ];
  const params = [minDurationSeconds];
  if (workspaceId) {
    where.push(`workspace_id = $2`);
    params.push(workspaceId);
  }

  const q = `
    SELECT id, workspace_id, started_at, ended_at, duration_sec
    FROM calls
    WHERE ${where.join(" AND ")}
    ORDER BY duration_sec DESC
  `;

  const { rows } = await pool.query(q, params);
  console.log(`Found ${rows.length} suspicious completed calls. Mode: ${dryRun ? "DRY RUN" : "APPLY"}.`);

  const sample = rows.slice(0, 15);
  if (sample.length) {
    console.log("Sample (first 15):");
    for (const r of sample) {
      console.log(`- ${r.id} ws=${r.workspace_id} duration_sec=${r.duration_sec} started_at=${r.started_at} ended_at=${r.ended_at}`);
    }
  }

  if (!dryRun && rows.length) {
    const batchSize = 200;
    let updated = 0;
    for (let i = 0; i < rows.length; i += batchSize) {
      const batch = rows.slice(i, i + batchSize);
      const ids = batch.map((b) => b.id);

      // Set ended_at = started_at + staleSeconds*1000 and duration_sec = staleSeconds
      const sql = `
        UPDATE calls
        SET outcome='stale_timeout',
            ended_at = started_at + $2::bigint,
            duration_sec = $3::int,
            updated_at = $4::bigint
        WHERE id = ANY($1::text[])
      `;
      await pool.query(sql, [ids, staleSeconds * 1000, staleSeconds, Date.now()]);
      updated += batch.length;
      console.log(`Updated ${updated}/${rows.length}...`);
    }
    console.log(`Done. Updated ${updated} calls to stale_timeout and capped duration to ${staleSeconds}s.`);
  }

  await pool.end();
}

main().catch((e) => {
  console.error("fix_stale_calls failed:", e?.message || e);
  process.exit(1);
});


