const { Pool, types } = require("pg");

// Parse BIGINT as number
types.setTypeParser(20, (v) => (v === null ? null : Number(v)));

function getDbConfig() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) return null;

  const sslEnabled = String(process.env.DATABASE_SSL ?? "true").toLowerCase() !== "false";

  return {
    connectionString,
    ssl: sslEnabled ? { rejectUnauthorized: false } : false,
    max: Number(process.env.DATABASE_POOL_MAX || 10),
  };
}

let pool = null;

function getPool() {
  if (pool) return pool;
  const cfg = getDbConfig();
  if (!cfg) return null;
  pool = new Pool(cfg);
  return pool;
}

async function initSchema() {
  const p = getPool();
  if (!p) return false;

  await p.query(`
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      prompt_draft TEXT NOT NULL DEFAULT '',
      prompt_published TEXT NOT NULL DEFAULT '',
      published_at BIGINT NULL,
      welcome JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS calls (
      id TEXT PRIMARY KEY,
      agent_id TEXT NULL,
      agent_name TEXT NOT NULL,
      "to" TEXT NOT NULL,
      room_name TEXT NOT NULL,
      started_at BIGINT NOT NULL,
      ended_at BIGINT NULL,
      duration_sec INT NULL,
      outcome TEXT NOT NULL,
      cost_usd DOUBLE PRECISION NULL,
      transcript JSONB NOT NULL DEFAULT '[]'::jsonb,
      recording JSONB NULL,
      metrics JSONB NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  await p.query(`CREATE INDEX IF NOT EXISTS calls_agent_started_idx ON calls(agent_id, started_at DESC);`);

  return true;
}

module.exports = { getPool, initSchema };


