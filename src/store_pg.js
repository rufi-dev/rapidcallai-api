const { nanoid } = require("nanoid");
const { getPool } = require("./db");

function rowToUser(r) {
  return {
    id: r.id,
    email: r.email,
    name: r.name ?? "",
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function rowToAgent(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id ?? null,
    name: r.name,
    promptDraft: r.prompt_draft ?? "",
    promptPublished: r.prompt_published ?? "",
    publishedAt: r.published_at ?? null,
    welcome: r.welcome ?? {},
    voice: r.voice ?? {},
    llmModel: r.llm_model ?? "",
    knowledgeFolderIds: Array.isArray(r.knowledge_folder_ids) ? r.knowledge_folder_ids : (r.knowledge_folder_ids ?? []),
    maxCallSeconds: Number(r.max_call_seconds || 0),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function rowToCall(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id ?? null,
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

function rowToWorkspace(r) {
  return {
    id: r.id,
    name: r.name,
    userId: r.user_id ?? null,
    twilioSubaccountSid: r.twilio_subaccount_sid ?? null,
    isTrial: Boolean(r.is_trial),
    trialCreditUsd: typeof r.trial_credit_usd === "number" ? r.trial_credit_usd : Number(r.trial_credit_usd || 0),
    trialCreditGrantedAt: r.trial_credit_granted_at ?? null,
    stripeCustomerId: r.stripe_customer_id ?? null,
    stripeSubscriptionId: r.stripe_subscription_id ?? null,
    stripePhoneNumbersItemId: r.stripe_phone_numbers_item_id ?? null,
    openmeterCustomerId: r.openmeter_customer_id ?? null,
    openmeterCreditGrantId: r.openmeter_credit_grant_id ?? null,
    openmeterCreditGrantedAt: r.openmeter_credit_granted_at ?? null,
    hasPaymentMethod: Boolean(r.has_payment_method),
    isPaid: Boolean(r.is_paid),
    telephonyEnabled: Boolean(r.telephony_enabled),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function rowToPhoneNumber(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    e164: r.e164,
    label: r.label ?? "",
    provider: r.provider ?? "twilio",
    status: r.status ?? "unconfigured",
    twilioNumberSid: r.twilio_number_sid ?? null,
    livekitInboundTrunkId: r.livekit_inbound_trunk_id ?? null,
    livekitOutboundTrunkId: r.livekit_outbound_trunk_id ?? null,
    livekitSipUsername: r.livekit_sip_username ?? null,
    livekitSipPassword: r.livekit_sip_password ?? null,
    inboundAgentId: r.inbound_agent_id ?? null,
    outboundAgentId: r.outbound_agent_id ?? null,
    allowedInboundCountries: r.allowed_inbound_countries ?? ["all"],
    allowedOutboundCountries: r.allowed_outbound_countries ?? ["all"],
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function listWorkspaces() {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM workspaces ORDER BY created_at DESC`);
  return rows.map(rowToWorkspace);
}

async function getWorkspace(id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM workspaces WHERE id=$1`, [id]);
  return rows[0] ? rowToWorkspace(rows[0]) : null;
}

async function createWorkspace({ id, name, userId = null }) {
  const p = getPool();
  const now = Date.now();
  const wsId = id || nanoid(10);
  const trialCreditUsdRaw = process.env.TRIAL_CREDIT_USD;
  const trialCreditUsd = trialCreditUsdRaw != null && trialCreditUsdRaw !== "" ? Number(trialCreditUsdRaw) : 20.0;
  const { rows } = await p.query(
    `
    INSERT INTO workspaces (
      id,
      name,
      user_id,
      twilio_subaccount_sid,
      is_trial,
      trial_credit_usd,
      trial_credit_granted_at,
      stripe_customer_id,
      stripe_subscription_id,
      stripe_phone_numbers_item_id,
      openmeter_customer_id,
      openmeter_credit_grant_id,
      openmeter_credit_granted_at,
      has_payment_method,
      is_paid,
      telephony_enabled,
      created_at,
      updated_at
    )
    VALUES ($1,$2,$3,NULL,true,$4,$5,NULL,NULL,NULL,NULL,NULL,NULL,false,false,false,$6,$7)
    RETURNING *
  `,
    [wsId, name, userId, trialCreditUsd, now, now, now]
  );
  return rowToWorkspace(rows[0]);
}

async function updateWorkspace(id, patch) {
  const p = getPool();
  const current = await getWorkspace(id);
  if (!current) return null;
  const next = { ...current, ...patch, updatedAt: Date.now() };
  const { rows } = await p.query(
    `
    UPDATE workspaces
    SET name=COALESCE($2,name),
        user_id=COALESCE($3,user_id),
        twilio_subaccount_sid=$4,
        is_trial=COALESCE($5,is_trial),
        trial_credit_usd=COALESCE($6,trial_credit_usd),
        trial_credit_granted_at=COALESCE($7,trial_credit_granted_at),
        stripe_customer_id=COALESCE($8,stripe_customer_id),
        stripe_subscription_id=COALESCE($9,stripe_subscription_id),
        stripe_phone_numbers_item_id=COALESCE($10,stripe_phone_numbers_item_id),
        openmeter_customer_id=COALESCE($11,openmeter_customer_id),
        openmeter_credit_grant_id=COALESCE($12,openmeter_credit_grant_id),
        openmeter_credit_granted_at=COALESCE($13,openmeter_credit_granted_at),
        has_payment_method=COALESCE($14,has_payment_method),
        is_paid=COALESCE($15,is_paid),
        telephony_enabled=COALESCE($16,telephony_enabled),
        updated_at=$17
    WHERE id=$1
    RETURNING *
  `,
    [
      id,
      next.name ?? null,
      next.userId ?? null,
      next.twilioSubaccountSid ?? null,
      typeof next.isTrial === "boolean" ? next.isTrial : null,
      typeof next.trialCreditUsd === "number" ? next.trialCreditUsd : null,
      typeof next.trialCreditGrantedAt === "number" ? next.trialCreditGrantedAt : null,
      next.stripeCustomerId ?? null,
      next.stripeSubscriptionId ?? null,
      next.stripePhoneNumbersItemId ?? null,
      next.openmeterCustomerId ?? null,
      next.openmeterCreditGrantId ?? null,
      typeof next.openmeterCreditGrantedAt === "number" ? next.openmeterCreditGrantedAt : null,
      typeof next.hasPaymentMethod === "boolean" ? next.hasPaymentMethod : null,
      typeof next.isPaid === "boolean" ? next.isPaid : null,
      typeof next.telephonyEnabled === "boolean" ? next.telephonyEnabled : null,
      next.updatedAt,
    ]
  );
  return rows[0] ? rowToWorkspace(rows[0]) : null;
}

async function debitTrialCreditUsd(workspaceId, debitUsd) {
  const p = getPool();
  const amt = Number(debitUsd || 0);
  if (!Number.isFinite(amt) || amt <= 0) return await getWorkspace(workspaceId);
  const now = Date.now();
  const { rows } = await p.query(
    `
    UPDATE workspaces
    SET trial_credit_usd=GREATEST(0, trial_credit_usd - $2),
        updated_at=$3
    WHERE id=$1
    RETURNING *
  `,
    [workspaceId, amt, now]
  );
  return rows[0] ? rowToWorkspace(rows[0]) : null;
}

async function ensureDefaultWorkspace() {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM workspaces ORDER BY created_at ASC LIMIT 1`);
  if (rows[0]) return rowToWorkspace(rows[0]);
  return await createWorkspace({ id: "rapidcallai", name: "rapidcallai" });
}

async function createUser({ email, name = "", passwordHash }) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(12);
  const { rows } = await p.query(
    `
    INSERT INTO users (id, email, name, password_hash, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6)
    RETURNING *
  `,
    [id, String(email).toLowerCase(), name ?? "", passwordHash, now, now]
  );
  return rowToUser(rows[0]);
}

async function getUserByEmail(email) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM users WHERE email=$1`, [String(email).toLowerCase()]);
  return rows[0] ? { ...rowToUser(rows[0]), passwordHash: rows[0].password_hash } : null;
}

async function getUserById(id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM users WHERE id=$1`, [id]);
  return rows[0] ? rowToUser(rows[0]) : null;
}

async function countUsers() {
  const p = getPool();
  const { rows } = await p.query(`SELECT COUNT(*)::int AS n FROM users`);
  return Number(rows[0]?.n || 0);
}

async function createSession({ userId, ttlDays = 30, token }) {
  const p = getPool();
  const now = Date.now();
  const expiresAt = now + ttlDays * 24 * 60 * 60 * 1000;
  await p.query(
    `INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES ($1,$2,$3,$4)`,
    [token, userId, expiresAt, now]
  );
  return { token, userId, expiresAt, createdAt: now };
}

async function getSession(token) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM sessions WHERE token=$1`, [token]);
  if (!rows[0]) return null;
  return {
    token: rows[0].token,
    userId: rows[0].user_id,
    expiresAt: rows[0].expires_at,
    createdAt: rows[0].created_at,
  };
}

async function deleteSession(token) {
  const p = getPool();
  await p.query(`DELETE FROM sessions WHERE token=$1`, [token]);
}

async function getWorkspaceForUser(userId) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM workspaces WHERE user_id=$1 ORDER BY created_at ASC LIMIT 1`, [userId]);
  return rows[0] ? rowToWorkspace(rows[0]) : null;
}

async function ensureWorkspaceForUser({ user, nameHint }) {
  const p = getPool();
  const existing = await getWorkspaceForUser(user.id);
  if (existing) return existing;

  // One-time migration: if this is the first user ever created, claim the legacy workspace + attach legacy rows.
  const nUsers = await countUsers();
  if (nUsers <= 1) {
    const { rows } = await p.query(`SELECT * FROM workspaces WHERE user_id IS NULL ORDER BY created_at ASC LIMIT 1`);
    if (rows[0]) {
      const legacy = rowToWorkspace(rows[0]);
      const now = Date.now();
      const { rows: claimedRows } = await p.query(
        `UPDATE workspaces SET user_id=$2, name=COALESCE($4,name), updated_at=$3 WHERE id=$1 RETURNING *`,
        [legacy.id, user.id, now, (nameHint || user.name || user.email || "Workspace").trim()]
      );

      const claimed = claimedRows[0] ? rowToWorkspace(claimedRows[0]) : legacy;

      // Attach any old rows that didn't have workspace_id (pre-multitenant schema)
      await p.query(`UPDATE agents SET workspace_id=$1 WHERE workspace_id IS NULL`, [claimed.id]);
      await p.query(`UPDATE calls SET workspace_id=$1 WHERE workspace_id IS NULL`, [claimed.id]);

      return claimed;
    }
  }

  const wsName = (nameHint || user.name || user.email || "Workspace").trim();
  return await createWorkspace({ name: wsName, userId: user.id });
}

async function listPhoneNumbers(workspaceId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT * FROM phone_numbers WHERE workspace_id=$1 ORDER BY created_at DESC`,
    [workspaceId]
  );
  return rows.map(rowToPhoneNumber);
}

async function getPhoneNumber(id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM phone_numbers WHERE id=$1`, [id]);
  return rows[0] ? rowToPhoneNumber(rows[0]) : null;
}

async function getPhoneNumberByE164(e164) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM phone_numbers WHERE e164=$1 ORDER BY created_at DESC LIMIT 1`, [e164]);
  return rows[0] ? rowToPhoneNumber(rows[0]) : null;
}

async function createPhoneNumber(input) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);

  const allowedIn = Array.isArray(input.allowedInboundCountries) ? input.allowedInboundCountries : ["all"];
  const allowedOut = Array.isArray(input.allowedOutboundCountries) ? input.allowedOutboundCountries : ["all"];

  const { rows } = await p.query(
    `
    INSERT INTO phone_numbers
      (id, workspace_id, e164, label, provider, status, twilio_number_sid, livekit_inbound_trunk_id, livekit_outbound_trunk_id,
       livekit_sip_username, livekit_sip_password,
       inbound_agent_id, outbound_agent_id,
       allowed_inbound_countries, allowed_outbound_countries, created_at, updated_at)
    VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
    RETURNING *
  `,
    [
      id,
      input.workspaceId,
      input.e164,
      input.label ?? "",
      input.provider ?? "twilio",
      input.status ?? "unconfigured",
      input.twilioNumberSid ?? null,
      input.livekitInboundTrunkId ?? null,
      input.livekitOutboundTrunkId ?? null,
      input.livekitSipUsername ?? null,
      input.livekitSipPassword ?? null,
      input.inboundAgentId ?? null,
      input.outboundAgentId ?? null,
      JSON.stringify(allowedIn),
      JSON.stringify(allowedOut),
      now,
      now,
    ]
  );
  return rowToPhoneNumber(rows[0]);
}

async function updatePhoneNumber(id, patch) {
  const p = getPool();
  const existing = await getPhoneNumber(id);
  if (!existing) return null;

  // Ignore undefined patch fields so partial updates don't erase existing values.
  const safePatch = Object.fromEntries(Object.entries(patch || {}).filter(([, v]) => v !== undefined));
  const next = { ...existing, ...safePatch, updatedAt: Date.now() };
  const allowedIn = Array.isArray(next.allowedInboundCountries) ? next.allowedInboundCountries : ["all"];
  const allowedOut = Array.isArray(next.allowedOutboundCountries) ? next.allowedOutboundCountries : ["all"];

  const { rows } = await p.query(
    `
    UPDATE phone_numbers
    SET label=$2,
        status=$3,
        twilio_number_sid=$4,
        livekit_inbound_trunk_id=$5,
        livekit_outbound_trunk_id=$6,
        livekit_sip_username=$7,
        livekit_sip_password=$8,
        inbound_agent_id=$9,
        outbound_agent_id=$10,
        allowed_inbound_countries=$11,
        allowed_outbound_countries=$12,
        updated_at=$13
    WHERE id=$1
    RETURNING *
  `,
    [
      id,
      next.label ?? "",
      next.status ?? "unconfigured",
      next.twilioNumberSid ?? null,
      next.livekitInboundTrunkId ?? null,
      next.livekitOutboundTrunkId ?? null,
      next.livekitSipUsername ?? null,
      next.livekitSipPassword ?? null,
      next.inboundAgentId ?? null,
      next.outboundAgentId ?? null,
      JSON.stringify(allowedIn),
      JSON.stringify(allowedOut),
      next.updatedAt,
    ]
  );
  return rows[0] ? rowToPhoneNumber(rows[0]) : null;
}

async function deletePhoneNumber(id) {
  const p = getPool();
  await p.query(`DELETE FROM phone_numbers WHERE id=$1`, [id]);
}

async function listAgents(workspaceId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT * FROM agents WHERE workspace_id=$1 ORDER BY created_at DESC`,
    [workspaceId]
  );
  return rows.map(rowToAgent);
}

async function createAgent({
  workspaceId,
  name,
  promptDraft = "",
  promptPublished = "",
  welcome = null,
  voice = null,
  llmModel = "",
  knowledgeFolderIds = [],
  maxCallSeconds = 0,
}) {
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

  const v = voice || {};
  const voiceNorm = {
    provider: v.provider ?? null,
    model: v.model ?? null,
    voiceId: v.voiceId ?? null,
  };

  const { rows } = await p.query(
    `
    INSERT INTO agents (id, workspace_id, name, prompt_draft, prompt_published, published_at, welcome, voice, llm_model, knowledge_folder_ids, max_call_seconds, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    RETURNING *
  `,
    [
      id,
      workspaceId,
      name,
      promptDraft ?? "",
      promptPublished ?? "",
      pubAt,
      JSON.stringify(welcomeNorm),
      JSON.stringify(voiceNorm),
      String(llmModel || ""),
      JSON.stringify(Array.isArray(knowledgeFolderIds) ? knowledgeFolderIds : []),
      Math.max(0, Math.round(Number(maxCallSeconds || 0))),
      now,
      now,
    ]
  );
  return rowToAgent(rows[0]);
}

async function getAgent(workspaceId, id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM agents WHERE workspace_id=$1 AND id=$2`, [workspaceId, id]);
  return rows[0] ? rowToAgent(rows[0]) : null;
}

async function updateAgent(workspaceId, id, { name, promptDraft, publish, welcome, voice, llmModel, knowledgeFolderIds, maxCallSeconds }) {
  const p = getPool();
  const current = await getAgent(workspaceId, id);
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

  const v = voice ? { ...(current.voice ?? {}), ...voice } : current.voice ?? {};
  const voiceNorm = {
    provider: v.provider ?? null,
    model: v.model ?? null,
    voiceId: v.voiceId ?? null,
  };

  const llmTrim = llmModel == null ? null : String(llmModel || "").trim();
  const nextLlmModel = llmTrim ? llmTrim : (current.llmModel ?? "");
  const nextKbFolderIds = Array.isArray(knowledgeFolderIds) ? knowledgeFolderIds : (current.knowledgeFolderIds ?? []);
  const nextMaxCallSeconds =
    maxCallSeconds == null ? Number(current.maxCallSeconds || 0) : Math.max(0, Math.round(Number(maxCallSeconds || 0)));

  const updatedAt = Date.now();
  const { rows } = await p.query(
    `
    UPDATE agents
    SET name=COALESCE($2,name),
        prompt_draft=$3,
        prompt_published=$4,
        published_at=$5,
        welcome=$6,
        voice=$7,
        llm_model=$8,
        knowledge_folder_ids=$9,
        max_call_seconds=$10,
        updated_at=$11
    WHERE workspace_id=$12 AND id=$1
    RETURNING *
  `,
    [
      id,
      name ?? null,
      nextDraft,
      nextPublished,
      publishedAt,
      JSON.stringify(welcomeNorm),
      JSON.stringify(voiceNorm),
      nextLlmModel,
      JSON.stringify(nextKbFolderIds),
      nextMaxCallSeconds,
      updatedAt,
      workspaceId,
    ]
  );
  return rows[0] ? rowToAgent(rows[0]) : null;
}

function rowToKbFolder(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    name: r.name,
    parentId: r.parent_id ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function rowToKbDoc(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    folderId: r.folder_id,
    kind: r.kind,
    title: r.title ?? "",
    contentText: r.content_text ?? "",
    sourceFilename: r.source_filename ?? null,
    mime: r.mime ?? null,
    sizeBytes: r.size_bytes ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function listKbFolders(workspaceId) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM kb_folders WHERE workspace_id=$1 ORDER BY created_at DESC`, [workspaceId]);
  return rows.map(rowToKbFolder);
}

async function createKbFolder(workspaceId, { name, parentId = null }) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);
  const { rows } = await p.query(
    `
    INSERT INTO kb_folders (id, workspace_id, name, parent_id, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6)
    RETURNING *
  `,
    [id, workspaceId, String(name || "").trim(), parentId ? String(parentId) : null, now, now]
  );
  return rows[0] ? rowToKbFolder(rows[0]) : null;
}

async function updateKbFolder(workspaceId, id, { name, parentId }) {
  const p = getPool();
  const now = Date.now();
  const { rows } = await p.query(
    `
    UPDATE kb_folders
    SET name=COALESCE($3,name),
        parent_id=$4,
        updated_at=$5
    WHERE workspace_id=$1 AND id=$2
    RETURNING *
  `,
    [workspaceId, id, name == null ? null : String(name || "").trim(), parentId == null ? null : String(parentId), now]
  );
  return rows[0] ? rowToKbFolder(rows[0]) : null;
}

async function deleteKbFolder(workspaceId, id) {
  const p = getPool();
  // Best-effort cascade: delete docs in folder, then folder. (Subfolders are user-managed for now.)
  await p.query(`DELETE FROM kb_docs WHERE workspace_id=$1 AND folder_id=$2`, [workspaceId, id]);
  await p.query(`DELETE FROM kb_folders WHERE workspace_id=$1 AND id=$2`, [workspaceId, id]);
}

async function listKbDocs(workspaceId, folderId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT * FROM kb_docs WHERE workspace_id=$1 AND folder_id=$2 ORDER BY created_at DESC`,
    [workspaceId, folderId]
  );
  return rows.map(rowToKbDoc);
}

async function createKbTextDoc(workspaceId, { folderId, title = "", contentText }) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);
  const { rows } = await p.query(
    `
    INSERT INTO kb_docs (id, workspace_id, folder_id, kind, title, content_text, created_at, updated_at)
    VALUES ($1,$2,$3,'text',$4,$5,$6,$7)
    RETURNING *
  `,
    [id, workspaceId, folderId, String(title || "").trim(), String(contentText || ""), now, now]
  );
  return rows[0] ? rowToKbDoc(rows[0]) : null;
}

async function createKbPdfDoc(workspaceId, { folderId, title = "", contentText, sourceFilename, mime, sizeBytes }) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);
  const { rows } = await p.query(
    `
    INSERT INTO kb_docs (id, workspace_id, folder_id, kind, title, content_text, source_filename, mime, size_bytes, created_at, updated_at)
    VALUES ($1,$2,$3,'pdf',$4,$5,$6,$7,$8,$9,$10)
    RETURNING *
  `,
    [id, workspaceId, folderId, String(title || "").trim(), String(contentText || ""), sourceFilename || null, mime || null, sizeBytes ?? null, now, now]
  );
  return rows[0] ? rowToKbDoc(rows[0]) : null;
}

async function deleteKbDoc(workspaceId, id) {
  const p = getPool();
  await p.query(`DELETE FROM kb_docs WHERE workspace_id=$1 AND id=$2`, [workspaceId, id]);
}

async function deleteAgent(workspaceId, id) {
  const p = getPool();
  await p.query(`DELETE FROM agents WHERE workspace_id=$1 AND id=$2`, [workspaceId, id]);
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
      (id, workspace_id, agent_id, agent_name, "to", room_name, started_at, ended_at, duration_sec, outcome, cost_usd, transcript, recording, metrics, created_at, updated_at)
    VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
  `,
    [
      c.id,
      c.workspaceId ?? null,
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

async function getCallById(id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM calls WHERE id=$1`, [id]);
  return rows[0] ? rowToCall(rows[0]) : null;
}

async function updateCall(callId, patch) {
  const p = getPool();
  // Fetch existing to merge JSON fields safely.
  const existing = await getCallById(callId);
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

  return await getCallById(callId);
}

async function listCalls(workspaceId) {
  const p = getPool();
  const { rows } = await p.query(
    `
    SELECT id, agent_id, agent_name, "to", room_name, started_at, ended_at, duration_sec, outcome, cost_usd,
           (recording->>'url') AS recording_url,
           created_at, updated_at, workspace_id
    FROM calls
    WHERE workspace_id=$1
    ORDER BY started_at DESC
  `,
    [workspaceId]
  );
  return rows.map((r) => ({
    id: r.id,
    workspaceId: r.workspace_id ?? null,
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

async function getCall(workspaceId, id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM calls WHERE workspace_id=$1 AND id=$2`, [workspaceId, id]);
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

function rowToAgentVariant(r) {
  return {
    id: r.id,
    agentId: r.agent_id,
    workspaceId: r.workspace_id,
    name: r.name,
    prompt: r.prompt,
    trafficPercent: Number(r.traffic_percent || 0),
    enabled: Boolean(r.enabled),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function listAgentVariants(workspaceId, agentId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT * FROM agent_variants WHERE workspace_id=$1 AND agent_id=$2 ORDER BY created_at DESC`,
    [workspaceId, agentId]
  );
  return rows.map(rowToAgentVariant);
}

async function createAgentVariant(workspaceId, agentId, { name, prompt, trafficPercent = 0, enabled = true }) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);
  const tp = Math.max(0, Math.min(100, Math.round(Number(trafficPercent || 0))));
  const { rows } = await p.query(
    `
    INSERT INTO agent_variants (id, agent_id, workspace_id, name, prompt, traffic_percent, enabled, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    RETURNING *
  `,
    [id, agentId, workspaceId, name, prompt, tp, Boolean(enabled), now, now]
  );
  return rowToAgentVariant(rows[0]);
}

async function updateAgentVariant(workspaceId, id, patch) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM agent_variants WHERE workspace_id=$1 AND id=$2`, [workspaceId, id]);
  if (!rows[0]) return null;
  const cur = rowToAgentVariant(rows[0]);
  const next = {
    name: patch.name ?? cur.name,
    prompt: patch.prompt ?? cur.prompt,
    trafficPercent:
      patch.trafficPercent == null ? cur.trafficPercent : Math.max(0, Math.min(100, Math.round(Number(patch.trafficPercent || 0)))),
    enabled: patch.enabled == null ? cur.enabled : Boolean(patch.enabled),
  };
  const updatedAt = Date.now();
  const { rows: rows2 } = await p.query(
    `
    UPDATE agent_variants
    SET name=$1, prompt=$2, traffic_percent=$3, enabled=$4, updated_at=$5
    WHERE workspace_id=$6 AND id=$7
    RETURNING *
  `,
    [next.name, next.prompt, next.trafficPercent, next.enabled, updatedAt, workspaceId, id]
  );
  return rows2[0] ? rowToAgentVariant(rows2[0]) : null;
}

async function deleteAgentVariant(workspaceId, id) {
  const p = getPool();
  await p.query(`DELETE FROM agent_variants WHERE workspace_id=$1 AND id=$2`, [workspaceId, id]);
}

function rowToCallEvaluation(r) {
  return {
    id: r.id,
    callId: r.call_id,
    workspaceId: r.workspace_id,
    score: Number(r.score || 0),
    notes: r.notes ?? "",
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function listCallEvaluations(workspaceId, callId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT * FROM call_evaluations WHERE workspace_id=$1 AND call_id=$2 ORDER BY created_at DESC`,
    [workspaceId, callId]
  );
  return rows.map(rowToCallEvaluation);
}

async function createCallEvaluation(workspaceId, callId, { score, notes }) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);
  const s = Math.max(0, Math.min(100, Math.round(Number(score || 0))));
  const { rows } = await p.query(
    `
    INSERT INTO call_evaluations (id, call_id, workspace_id, score, notes, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    RETURNING *
  `,
    [id, callId, workspaceId, s, String(notes || ""), now, now]
  );
  return rowToCallEvaluation(rows[0]);
}

function rowToCallLabel(r) {
  return {
    id: r.id,
    callId: r.call_id,
    workspaceId: r.workspace_id,
    label: r.label,
    createdAt: r.created_at,
  };
}

async function listCallLabels(workspaceId, callId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT * FROM call_labels WHERE workspace_id=$1 AND call_id=$2 ORDER BY created_at DESC`,
    [workspaceId, callId]
  );
  return rows.map(rowToCallLabel);
}

async function addCallLabel(workspaceId, callId, label) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);
  const { rows } = await p.query(
    `
    INSERT INTO call_labels (id, call_id, workspace_id, label, created_at)
    VALUES ($1,$2,$3,$4,$5)
    RETURNING *
  `,
    [id, callId, workspaceId, String(label || "").trim(), now]
  );
  return rowToCallLabel(rows[0]);
}

async function deleteCallLabel(workspaceId, callId, label) {
  const p = getPool();
  await p.query(`DELETE FROM call_labels WHERE workspace_id=$1 AND call_id=$2 AND label=$3`, [workspaceId, callId, label]);
}

module.exports = {
  // Auth
  createUser,
  getUserByEmail,
  getUserById,
  createSession,
  getSession,
  deleteSession,
  getWorkspaceForUser,
  ensureWorkspaceForUser,

  // Workspaces + phone numbers
  listWorkspaces,
  getWorkspace,
  createWorkspace,
  updateWorkspace,
  debitTrialCreditUsd,
  ensureDefaultWorkspace,
  listPhoneNumbers,
  getPhoneNumber,
  getPhoneNumberByE164,
  createPhoneNumber,
  updatePhoneNumber,
  deletePhoneNumber,

  listAgents,
  createAgent,
  getAgent,
  updateAgent,
  deleteAgent,
  // Knowledge Base
  listKbFolders,
  createKbFolder,
  updateKbFolder,
  deleteKbFolder,
  listKbDocs,
  createKbTextDoc,
  createKbPdfDoc,
  deleteKbDoc,
  createCall,
  updateCall,
  listCalls,
  getCall,
  getCallById,
  upsertAgentForMigration,
  upsertCallForMigration,

  // A/B variants
  listAgentVariants,
  createAgentVariant,
  updateAgentVariant,
  deleteAgentVariant,

  // Call evaluations
  listCallEvaluations,
  createCallEvaluation,

  // Call labels
  listCallLabels,
  addCallLabel,
  deleteCallLabel,
};


