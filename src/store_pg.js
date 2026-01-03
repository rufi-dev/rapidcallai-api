const { nanoid } = require("nanoid");
const { getPool } = require("./db");

function rowToAgent(r) {
  return {
    id: r.id,
    name: r.name,
    promptDraft: r.prompt_draft ?? "",
    promptPublished: r.prompt_published ?? "",
    publishedAt: r.published_at ?? null,
    welcome: r.welcome ?? {},
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function rowToCall(r) {
  return {
    id: r.id,
    agentId: r.agent_id,
    agentName: r.agent_name,
    to: r.to,
    roomName: r.room_name,
    startedAt: r.started_at,
    endedAt: r.ended_at,
    durationSec: r.duration_sec,
    outcome: r.outcome,
    costUsd: r.cost_usd,
    transcript: r.transcript ?? [],
    recording: r.recording ?? null,
    metrics: r.metrics ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function listAgents() {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM agents ORDER BY created_at DESC`);
  return rows.map(rowToAgent);
}

async function createAgent({ name, promptDraft = "", promptPublished = "", welcome = null }) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);
  const pubAt = promptPublished && String(promptPublished).trim() ? now : null;

  const w = welcome || {};
  const welcomeNorm = {
    mode: w.mode ?? "user",
    aiMessageMode: w.aiMessageMode ?? "dynamic",
    aiMessageText: w.aiMessageText ?? "",
    aiDelaySeconds: w.aiDelaySeconds ?? 0,
  };

  const { rows } = await p.query(
    `
    INSERT INTO agents (id, name, prompt_draft, prompt_published, published_at, welcome, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
    RETURNING *
  `,
    [id, name, promptDraft ?? "", promptPublished ?? "", pubAt, JSON.stringify(welcomeNorm), now, now]
  );
  return rowToAgent(rows[0]);
}

async function getAgent(id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM agents WHERE id=$1`, [id]);
  return rows[0] ? rowToAgent(rows[0]) : null;
}

async function updateAgent(id, { name, promptDraft, publish, welcome }) {
  const p = getPool();
  const current = await getAgent(id);
  if (!current) return null;

  const nextDraft = promptDraft ?? current.promptDraft ?? "";
  const shouldPublish = Boolean(publish);
  const nextPublished = shouldPublish ? nextDraft : current.promptPublished ?? "";
  const publishedAt = shouldPublish ? Date.now() : current.publishedAt ?? null;

  const w = welcome ? { ...(current.welcome ?? {}), ...welcome } : current.welcome ?? {};
  const welcomeNorm = {
    mode: w.mode ?? "user",
    aiMessageMode: w.aiMessageMode ?? "dynamic",
    aiMessageText: w.aiMessageText ?? "",
    aiDelaySeconds: w.aiDelaySeconds ?? 0,
  };

  const updatedAt = Date.now();
  const { rows } = await p.query(
    `
    UPDATE agents
    SET name=COALESCE($2,name),
        prompt_draft=$3,
        prompt_published=$4,
        published_at=$5,
        welcome=$6,
        updated_at=$7
    WHERE id=$1
    RETURNING *
  `,
    [id, name ?? null, nextDraft, nextPublished, publishedAt, JSON.stringify(welcomeNorm), updatedAt]
  );
  return rows[0] ? rowToAgent(rows[0]) : null;
}

async function deleteAgent(id) {
  const p = getPool();
  await p.query(`DELETE FROM agents WHERE id=$1`, [id]);
}

async function createCall(call) {
  const p = getPool();
  const c = {
    ...call,
    transcript: call.transcript ?? [],
    recording: call.recording ?? null,
    metrics: call.metrics ?? null,
  };
  await p.query(
    `
    INSERT INTO calls
      (id, agent_id, agent_name, "to", room_name, started_at, ended_at, duration_sec, outcome, cost_usd, transcript, recording, metrics, created_at, updated_at)
    VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
  `,
    [
      c.id,
      c.agentId,
      c.agentName,
      c.to,
      c.roomName,
      c.startedAt,
      c.endedAt,
      c.durationSec,
      c.outcome,
      c.costUsd,
      JSON.stringify(c.transcript),
      c.recording ? JSON.stringify(c.recording) : null,
      c.metrics ? JSON.stringify(c.metrics) : null,
      c.createdAt,
      c.updatedAt,
    ]
  );
}

async function updateCall(callId, patch) {
  const p = getPool();
  // Fetch existing to merge JSON fields safely.
  const existing = await getCall(callId);
  if (!existing) return null;

  const next = { ...existing, ...patch, updatedAt: Date.now() };

  await p.query(
    `
    UPDATE calls
    SET agent_id=$2,
        agent_name=$3,
        "to"=$4,
        room_name=$5,
        started_at=$6,
        ended_at=$7,
        duration_sec=$8,
        outcome=$9,
        cost_usd=$10,
        transcript=$11,
        recording=$12,
        metrics=$13,
        updated_at=$14
    WHERE id=$1
  `,
    [
      callId,
      next.agentId,
      next.agentName,
      next.to,
      next.roomName,
      next.startedAt,
      next.endedAt,
      next.durationSec,
      next.outcome,
      next.costUsd,
      JSON.stringify(next.transcript ?? []),
      next.recording ? JSON.stringify(next.recording) : null,
      next.metrics ? JSON.stringify(next.metrics) : null,
      next.updatedAt,
    ]
  );

  return await getCall(callId);
}

async function listCalls() {
  const p = getPool();
  const { rows } = await p.query(
    `
    SELECT id, agent_id, agent_name, "to", room_name, started_at, ended_at, duration_sec, outcome, cost_usd,
           (recording->>'url') AS recording_url,
           created_at, updated_at
    FROM calls
    ORDER BY started_at DESC
  `
  );
  return rows.map((r) => ({
    id: r.id,
    agentId: r.agent_id,
    agentName: r.agent_name,
    to: r.to,
    roomName: r.room_name,
    startedAt: r.started_at,
    endedAt: r.ended_at,
    durationSec: r.duration_sec,
    outcome: r.outcome,
    costUsd: r.cost_usd,
    recordingUrl: r.recording_url ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

async function getCall(id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM calls WHERE id=$1`, [id]);
  return rows[0] ? rowToCall(rows[0]) : null;
}

async function upsertAgentForMigration(agent) {
  const p = getPool();
  const a = agent;
  await p.query(
    `
    INSERT INTO agents (id, name, prompt_draft, prompt_published, published_at, welcome, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
    ON CONFLICT (id) DO UPDATE SET
      name=EXCLUDED.name,
      prompt_draft=EXCLUDED.prompt_draft,
      prompt_published=EXCLUDED.prompt_published,
      published_at=EXCLUDED.published_at,
      welcome=EXCLUDED.welcome,
      updated_at=EXCLUDED.updated_at
  `,
    [
      a.id,
      a.name,
      a.promptDraft ?? a.prompt_draft ?? "",
      a.promptPublished ?? a.prompt_published ?? "",
      a.publishedAt ?? a.published_at ?? null,
      JSON.stringify(a.welcome ?? {}),
      a.createdAt ?? a.created_at ?? Date.now(),
      a.updatedAt ?? a.updated_at ?? Date.now(),
    ]
  );
}

async function upsertCallForMigration(call) {
  const p = getPool();
  const c = call;
  await p.query(
    `
    INSERT INTO calls
      (id, agent_id, agent_name, "to", room_name, started_at, ended_at, duration_sec, outcome, cost_usd, transcript, recording, metrics, created_at, updated_at)
    VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
    ON CONFLICT (id) DO UPDATE SET
      agent_id=EXCLUDED.agent_id,
      agent_name=EXCLUDED.agent_name,
      "to"=EXCLUDED."to",
      room_name=EXCLUDED.room_name,
      started_at=EXCLUDED.started_at,
      ended_at=EXCLUDED.ended_at,
      duration_sec=EXCLUDED.duration_sec,
      outcome=EXCLUDED.outcome,
      cost_usd=EXCLUDED.cost_usd,
      transcript=EXCLUDED.transcript,
      recording=EXCLUDED.recording,
      metrics=EXCLUDED.metrics,
      updated_at=EXCLUDED.updated_at
  `,
    [
      c.id,
      c.agentId ?? c.agent_id ?? null,
      c.agentName ?? c.agent_name ?? "Agent",
      c.to ?? c["to"] ?? "webtest",
      c.roomName ?? c.room_name ?? "",
      c.startedAt ?? c.started_at ?? Date.now(),
      c.endedAt ?? c.ended_at ?? null,
      c.durationSec ?? c.duration_sec ?? null,
      c.outcome ?? "in_progress",
      typeof c.costUsd === "number" ? c.costUsd : c.cost_usd ?? null,
      JSON.stringify(c.transcript ?? []),
      c.recording ? JSON.stringify(c.recording) : null,
      c.metrics ? JSON.stringify(c.metrics) : null,
      c.createdAt ?? c.created_at ?? Date.now(),
      c.updatedAt ?? c.updated_at ?? Date.now(),
    ]
  );
}

module.exports = {
  listAgents,
  createAgent,
  getAgent,
  updateAgent,
  deleteAgent,
  createCall,
  updateCall,
  listCalls,
  getCall,
  upsertAgentForMigration,
  upsertCallForMigration,
};


