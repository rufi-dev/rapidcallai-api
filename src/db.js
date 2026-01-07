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
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL DEFAULT '',
      password_hash TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL
    );
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS workspaces (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      user_id TEXT NULL,
      twilio_subaccount_sid TEXT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  // Backward-compatible schema upgrades (when table already exists)
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS user_id TEXT NULL;`);

  await p.query(`
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NULL,
      name TEXT NOT NULL,
      prompt_draft TEXT NOT NULL DEFAULT '',
      prompt_published TEXT NOT NULL DEFAULT '',
      published_at BIGINT NULL,
      welcome JSONB NOT NULL DEFAULT '{}'::jsonb,
      voice JSONB NOT NULL DEFAULT '{}'::jsonb,
      llm_model TEXT NOT NULL DEFAULT '',
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS workspace_id TEXT NULL;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS voice JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS llm_model TEXT NOT NULL DEFAULT '';`);
  await p.query(`CREATE INDEX IF NOT EXISTS agents_workspace_idx ON agents(workspace_id, created_at DESC);`);

  await p.query(`
    CREATE TABLE IF NOT EXISTS calls (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NULL,
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

  await p.query(`ALTER TABLE calls ADD COLUMN IF NOT EXISTS workspace_id TEXT NULL;`);

  await p.query(`CREATE INDEX IF NOT EXISTS calls_agent_started_idx ON calls(agent_id, started_at DESC);`);
  await p.query(`CREATE INDEX IF NOT EXISTS calls_workspace_started_idx ON calls(workspace_id, started_at DESC);`);

  await p.query(`
    CREATE TABLE IF NOT EXISTS phone_numbers (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      e164 TEXT NOT NULL,
      label TEXT NOT NULL DEFAULT '',
      provider TEXT NOT NULL DEFAULT 'twilio',
      status TEXT NOT NULL DEFAULT 'unconfigured',
      twilio_number_sid TEXT NULL,
      livekit_inbound_trunk_id TEXT NULL,
      livekit_outbound_trunk_id TEXT NULL,
      livekit_sip_username TEXT NULL,
      livekit_sip_password TEXT NULL,
      inbound_agent_id TEXT NULL,
      outbound_agent_id TEXT NULL,
      allowed_inbound_countries JSONB NOT NULL DEFAULT '["all"]'::jsonb,
      allowed_outbound_countries JSONB NOT NULL DEFAULT '["all"]'::jsonb,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  // Backward-compatible schema upgrades (when table already exists)
  await p.query(`ALTER TABLE phone_numbers ADD COLUMN IF NOT EXISTS livekit_inbound_trunk_id TEXT NULL;`);
  await p.query(`ALTER TABLE phone_numbers ADD COLUMN IF NOT EXISTS livekit_outbound_trunk_id TEXT NULL;`);
  await p.query(`ALTER TABLE phone_numbers ADD COLUMN IF NOT EXISTS livekit_sip_username TEXT NULL;`);
  await p.query(`ALTER TABLE phone_numbers ADD COLUMN IF NOT EXISTS livekit_sip_password TEXT NULL;`);

  await p.query(`CREATE INDEX IF NOT EXISTS phone_numbers_workspace_idx ON phone_numbers(workspace_id, created_at DESC);`);
  await p.query(`CREATE UNIQUE INDEX IF NOT EXISTS phone_numbers_workspace_e164_uniq ON phone_numbers(workspace_id, e164);`);

  return true;
}

module.exports = { getPool, initSchema };


