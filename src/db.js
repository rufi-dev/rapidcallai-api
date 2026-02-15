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
      is_trial BOOLEAN NOT NULL DEFAULT true,
      trial_credit_usd DOUBLE PRECISION NOT NULL DEFAULT 20.0,
      trial_credit_granted_at BIGINT NULL,
      stripe_customer_id TEXT NULL,
      stripe_subscription_id TEXT NULL,
      stripe_phone_numbers_item_id TEXT NULL,
      openmeter_customer_id TEXT NULL,
      openmeter_credit_grant_id TEXT NULL,
      openmeter_credit_granted_at BIGINT NULL,
      has_payment_method BOOLEAN NOT NULL DEFAULT false,
      is_paid BOOLEAN NOT NULL DEFAULT false,
      telephony_enabled BOOLEAN NOT NULL DEFAULT false,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  // Backward-compatible schema upgrades (when table already exists)
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS user_id TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS is_trial BOOLEAN NOT NULL DEFAULT true;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS trial_credit_usd DOUBLE PRECISION NOT NULL DEFAULT 20.0;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS trial_credit_granted_at BIGINT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS stripe_phone_numbers_item_id TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS openmeter_customer_id TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS openmeter_credit_grant_id TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS openmeter_credit_granted_at BIGINT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS has_payment_method BOOLEAN NOT NULL DEFAULT false;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS is_paid BOOLEAN NOT NULL DEFAULT false;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS telephony_enabled BOOLEAN NOT NULL DEFAULT false;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS twilio_sip_trunk_sid TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS twilio_sip_domain_name TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS twilio_sip_cred_username TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS twilio_sip_cred_password TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS livekit_outbound_trunk_id TEXT NULL;`);
  await p.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS livekit_inbound_trunk_id TEXT NULL;`);

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
      auto_eval_enabled BOOLEAN NOT NULL DEFAULT false,
      knowledge_folder_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
      max_call_seconds INT NOT NULL DEFAULT 0,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);

  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS workspace_id TEXT NULL;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS voice JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS llm_model TEXT NOT NULL DEFAULT '';`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS auto_eval_enabled BOOLEAN NOT NULL DEFAULT false;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS knowledge_folder_ids JSONB NOT NULL DEFAULT '[]'::jsonb;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS max_call_seconds INT NOT NULL DEFAULT 0;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS default_dynamic_variables JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS call_settings JSONB NULL;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS fallback_voice JSONB NULL;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS post_call_extraction JSONB NULL;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS post_call_extraction_model TEXT NULL;`);
  await p.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS webhook_url TEXT NULL;`);

  await p.query(`ALTER TABLE calls ADD COLUMN IF NOT EXISTS analysis_status TEXT NULL;`);
  await p.query(`ALTER TABLE calls ADD COLUMN IF NOT EXISTS post_call_extraction_results JSONB NULL;`);
  await p.query(`CREATE INDEX IF NOT EXISTS agents_workspace_idx ON agents(workspace_id, created_at DESC);`);

  await p.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      created_at BIGINT NOT NULL,
      last_used_at BIGINT NULL
    );
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS api_keys_workspace_idx ON api_keys(workspace_id);`);
  await p.query(`CREATE INDEX IF NOT EXISTS api_keys_key_hash_idx ON api_keys(key_hash);`);

  // Knowledge Base (folders + documents)
  await p.query(`
    CREATE TABLE IF NOT EXISTS kb_folders (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      name TEXT NOT NULL,
      parent_id TEXT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS kb_folders_workspace_idx ON kb_folders(workspace_id, created_at DESC);`);
  await p.query(`CREATE INDEX IF NOT EXISTS kb_folders_parent_idx ON kb_folders(workspace_id, parent_id);`);

  await p.query(`
    CREATE TABLE IF NOT EXISTS kb_docs (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      folder_id TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'text', -- text | pdf
      title TEXT NOT NULL DEFAULT '',
      content_text TEXT NOT NULL DEFAULT '',
      source_filename TEXT NULL,
      mime TEXT NULL,
      size_bytes INT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS kb_docs_workspace_idx ON kb_docs(workspace_id, created_at DESC);`);
  await p.query(`CREATE INDEX IF NOT EXISTS kb_docs_folder_idx ON kb_docs(workspace_id, folder_id, created_at DESC);`);

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

  // Outbound call jobs (queue + state machine)
  await p.query(`
    CREATE TABLE IF NOT EXISTS outbound_jobs (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL,
      status TEXT NOT NULL,
      lead_name TEXT NOT NULL DEFAULT '',
      phone_e164 TEXT NOT NULL,
      timezone TEXT NOT NULL DEFAULT 'UTC',
      attempts INT NOT NULL DEFAULT 0,
      max_attempts INT NOT NULL DEFAULT 3,
      next_attempt_at BIGINT NULL,
      last_error TEXT NOT NULL DEFAULT '',
      room_name TEXT NULL,
      agent_id TEXT NOT NULL,
      recording_enabled BOOLEAN NOT NULL DEFAULT false,
      dnc BOOLEAN NOT NULL DEFAULT false,
      dnc_reason TEXT NOT NULL DEFAULT '',
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      provider_call_id TEXT NULL,
      call_id TEXT NULL,
      locked_at BIGINT NULL,
      locked_by TEXT NULL
    );
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS outbound_jobs_workspace_idx ON outbound_jobs(workspace_id, created_at DESC);`);
  await p.query(`CREATE INDEX IF NOT EXISTS outbound_jobs_status_idx ON outbound_jobs(status, next_attempt_at);`);
  await p.query(`CREATE INDEX IF NOT EXISTS outbound_jobs_call_idx ON outbound_jobs(call_id);`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT '';`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS updated_at BIGINT NOT NULL DEFAULT 0;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'queued';`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS lead_name TEXT NOT NULL DEFAULT '';`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS phone_e164 TEXT NOT NULL DEFAULT '';`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'UTC';`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS max_attempts INT NOT NULL DEFAULT 3;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS next_attempt_at BIGINT NULL;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '';`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS room_name TEXT NULL;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS agent_id TEXT NOT NULL DEFAULT '';`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS recording_enabled BOOLEAN NOT NULL DEFAULT false;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS dnc BOOLEAN NOT NULL DEFAULT false;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS dnc_reason TEXT NOT NULL DEFAULT '';`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS provider_call_id TEXT NULL;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS call_id TEXT NULL;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS locked_at BIGINT NULL;`);
  await p.query(`ALTER TABLE outbound_jobs ADD COLUMN IF NOT EXISTS locked_by TEXT NULL;`);

  // Outbound job logs
  await p.query(`
    CREATE TABLE IF NOT EXISTS outbound_job_logs (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      job_id TEXT NOT NULL,
      level TEXT NOT NULL DEFAULT 'info',
      message TEXT NOT NULL,
      meta JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at BIGINT NOT NULL
    );
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS outbound_job_logs_job_idx ON outbound_job_logs(job_id, created_at DESC);`);
  await p.query(`ALTER TABLE outbound_job_logs ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT '';`);
  await p.query(`ALTER TABLE outbound_job_logs ADD COLUMN IF NOT EXISTS level TEXT NOT NULL DEFAULT 'info';`);
  await p.query(`ALTER TABLE outbound_job_logs ADD COLUMN IF NOT EXISTS meta JSONB NOT NULL DEFAULT '{}'::jsonb;`);

  // Agent variants (A/B prompt testing)
  await p.query(`
    CREATE TABLE IF NOT EXISTS agent_variants (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      workspace_id TEXT NOT NULL,
      name TEXT NOT NULL,
      prompt TEXT NOT NULL,
      traffic_percent INT NOT NULL DEFAULT 0,
      enabled BOOLEAN NOT NULL DEFAULT true,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS agent_variants_agent_idx ON agent_variants(agent_id, created_at DESC);`);

  // Call evaluations (QA / grading)
  await p.query(`
    CREATE TABLE IF NOT EXISTS call_evaluations (
      id TEXT PRIMARY KEY,
      call_id TEXT NOT NULL,
      workspace_id TEXT NOT NULL,
      score INT NOT NULL,
      source TEXT NOT NULL DEFAULT 'manual',
      notes TEXT NOT NULL DEFAULT '',
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);
  await p.query(`ALTER TABLE call_evaluations ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual';`);
  await p.query(`ALTER TABLE call_evaluations ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb;`);
  await p.query(`CREATE INDEX IF NOT EXISTS call_evaluations_call_idx ON call_evaluations(call_id, created_at DESC);`);

  // Call labels / tags
  await p.query(`
    CREATE TABLE IF NOT EXISTS call_labels (
      id TEXT PRIMARY KEY,
      call_id TEXT NOT NULL,
      workspace_id TEXT NOT NULL,
      label TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS call_labels_call_idx ON call_labels(call_id, created_at DESC);`);

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

  // Contacts / CRM
  await p.query(`
    CREATE TABLE IF NOT EXISTS contacts (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      phone_e164 TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '',
      company TEXT NOT NULL DEFAULT '',
      tags JSONB NOT NULL DEFAULT '[]'::jsonb,
      notes TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL DEFAULT 'manual',
      total_calls INT NOT NULL DEFAULT 0,
      last_call_at BIGINT NULL,
      last_call_outcome TEXT NOT NULL DEFAULT '',
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);
  await p.query(`CREATE INDEX IF NOT EXISTS contacts_workspace_idx ON contacts(workspace_id, created_at DESC);`);
  await p.query(`CREATE INDEX IF NOT EXISTS contacts_phone_idx ON contacts(workspace_id, phone_e164);`);
  await p.query(`CREATE UNIQUE INDEX IF NOT EXISTS contacts_workspace_phone_uniq ON contacts(workspace_id, phone_e164);`);

  return true;
}

module.exports = { getPool, initSchema };


