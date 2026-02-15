const { nanoid } = require("./id");
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
  const voiceRaw = r.voice ?? {};
  const { backgroundAudio, enabledTools, toolConfigs, backchannelEnabled, ...voiceFields } = voiceRaw;
  return {
    id: r.id,
    workspaceId: r.workspace_id ?? null,
    name: r.name,
    promptDraft: r.prompt_draft ?? "",
    promptPublished: r.prompt_published ?? "",
    publishedAt: r.published_at ?? null,
    welcome: r.welcome ?? {},
    voice: voiceFields,
    backgroundAudio: backgroundAudio ?? {},
    enabledTools: Array.isArray(enabledTools) ? enabledTools : ["end_call"],
    toolConfigs: toolConfigs && typeof toolConfigs === "object" ? toolConfigs : {},
    backchannelEnabled: Boolean(backchannelEnabled),
    llmModel: r.llm_model ?? "",
    autoEvalEnabled: Boolean(r.auto_eval_enabled),
    knowledgeFolderIds: Array.isArray(r.knowledge_folder_ids) ? r.knowledge_folder_ids : (r.knowledge_folder_ids ?? []),
    maxCallSeconds: Number(r.max_call_seconds || 0),
    defaultDynamicVariables: r.default_dynamic_variables && typeof r.default_dynamic_variables === "object" ? r.default_dynamic_variables : {},
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

function rowToOutboundJob(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    status: r.status,
    leadName: r.lead_name ?? "",
    phoneE164: r.phone_e164,
    timezone: r.timezone ?? "UTC",
    attempts: Number(r.attempts || 0),
    maxAttempts: Number(r.max_attempts || 0),
    nextAttemptAt: r.next_attempt_at ?? null,
    lastError: r.last_error ?? "",
    roomName: r.room_name ?? null,
    agentId: r.agent_id,
    recordingEnabled: Boolean(r.recording_enabled),
    dnc: Boolean(r.dnc),
    dncReason: r.dnc_reason ?? "",
    metadata: r.metadata ?? {},
    providerCallId: r.provider_call_id ?? null,
    callId: r.call_id ?? null,
    lockedAt: r.locked_at ?? null,
    lockedBy: r.locked_by ?? null,
  };
}

function rowToOutboundJobLog(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    jobId: r.job_id,
    level: r.level ?? "info",
    message: r.message,
    meta: r.meta ?? {},
    createdAt: r.created_at,
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
    twilioSipTrunkSid: r.twilio_sip_trunk_sid ?? null,
    twilioSipDomainName: r.twilio_sip_domain_name ?? null,
    twilioSipCredUsername: r.twilio_sip_cred_username ?? null,
    twilioSipCredPassword: r.twilio_sip_cred_password ?? null,
    livekitOutboundTrunkId: r.livekit_outbound_trunk_id ?? null,
    livekitInboundTrunkId: r.livekit_inbound_trunk_id ?? null,
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
        twilio_sip_trunk_sid=COALESCE($18,twilio_sip_trunk_sid),
        twilio_sip_domain_name=COALESCE($19,twilio_sip_domain_name),
        twilio_sip_cred_username=COALESCE($20,twilio_sip_cred_username),
        twilio_sip_cred_password=COALESCE($21,twilio_sip_cred_password),
        livekit_outbound_trunk_id=COALESCE($22,livekit_outbound_trunk_id),
        livekit_inbound_trunk_id=COALESCE($23,livekit_inbound_trunk_id),
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
      next.twilioSipTrunkSid ?? null,
      next.twilioSipDomainName ?? null,
      next.twilioSipCredUsername ?? null,
      next.twilioSipCredPassword ?? null,
      next.livekitOutboundTrunkId ?? null,
      next.livekitInboundTrunkId ?? null,
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
  autoEvalEnabled = false,
  knowledgeFolderIds = [],
  maxCallSeconds = 0,
  defaultDynamicVariables = null,
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
    backgroundAudio: {},
  };

  const defVars = defaultDynamicVariables && typeof defaultDynamicVariables === "object" ? defaultDynamicVariables : {};

  const { rows } = await p.query(
    `
    INSERT INTO agents (id, workspace_id, name, prompt_draft, prompt_published, published_at, welcome, voice, llm_model, auto_eval_enabled, knowledge_folder_ids, max_call_seconds, default_dynamic_variables, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
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
      Boolean(autoEvalEnabled),
      JSON.stringify(Array.isArray(knowledgeFolderIds) ? knowledgeFolderIds : []),
      Math.max(0, Math.round(Number(maxCallSeconds || 0))),
      JSON.stringify(defVars),
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

async function updateAgent(
  workspaceId,
  id,
  { name, promptDraft, publish, welcome, voice, backgroundAudio, enabledTools, toolConfigs, backchannelEnabled, llmModel, autoEvalEnabled, knowledgeFolderIds, maxCallSeconds, defaultDynamicVariables }
) {
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
  const ba = backgroundAudio ? { ...(current.backgroundAudio ?? {}), ...backgroundAudio } : (current.backgroundAudio ?? {});
  const nextEnabledTools = enabledTools !== undefined ? (Array.isArray(enabledTools) ? enabledTools : ["end_call"]) : (current.enabledTools ?? ["end_call"]);
  const nextToolConfigs = toolConfigs !== undefined ? (toolConfigs && typeof toolConfigs === "object" ? toolConfigs : {}) : (current.toolConfigs ?? {});
  const nextBackchannel = backchannelEnabled !== undefined ? Boolean(backchannelEnabled) : Boolean(current.backchannelEnabled);
  const voiceNorm = {
    provider: v.provider ?? null,
    model: v.model ?? null,
    voiceId: v.voiceId ?? null,
    backgroundAudio: ba,
    enabledTools: nextEnabledTools,
    toolConfigs: nextToolConfigs,
    backchannelEnabled: nextBackchannel,
  };

  const llmTrim = llmModel == null ? null : String(llmModel || "").trim();
  const nextLlmModel = llmTrim ? llmTrim : (current.llmModel ?? "");
  const nextKbFolderIds = Array.isArray(knowledgeFolderIds) ? knowledgeFolderIds : (current.knowledgeFolderIds ?? []);
  const nextMaxCallSeconds =
    maxCallSeconds == null ? Number(current.maxCallSeconds || 0) : Math.max(0, Math.round(Number(maxCallSeconds || 0)));
  const nextAutoEvalEnabled = autoEvalEnabled == null ? Boolean(current.autoEvalEnabled) : Boolean(autoEvalEnabled);
  const nextDefaultVars =
    defaultDynamicVariables !== undefined
      ? (defaultDynamicVariables && typeof defaultDynamicVariables === "object" ? defaultDynamicVariables : {})
      : (current.defaultDynamicVariables ?? {});

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
        auto_eval_enabled=$9,
        knowledge_folder_ids=$10,
        max_call_seconds=$11,
        default_dynamic_variables=$12,
        updated_at=$13
    WHERE workspace_id=$14 AND id=$1
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
      nextAutoEvalEnabled,
      JSON.stringify(nextKbFolderIds),
      nextMaxCallSeconds,
      JSON.stringify(nextDefaultVars),
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
    source: r.source ?? "manual",
    notes: r.notes ?? "",
    details: r.details ?? {},
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

async function createCallEvaluation(workspaceId, callId, { score, notes, source = "manual", details = {} }) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);
  const s = Math.max(0, Math.min(100, Math.round(Number(score || 0))));
  const { rows } = await p.query(
    `
    INSERT INTO call_evaluations (id, call_id, workspace_id, score, source, notes, details, created_at, updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    RETURNING *
  `,
    [id, callId, workspaceId, s, String(source || "manual"), String(notes || ""), JSON.stringify(details || {}), now, now]
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

async function createOutboundJob(workspaceId, input) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(12);
  const {
    leadName = "",
    phoneE164,
    timezone = "UTC",
    maxAttempts = 3,
    agentId,
    recordingEnabled = false,
    metadata = {},
  } = input || {};
  const { rows } = await p.query(
    `
    INSERT INTO outbound_jobs (
      id, workspace_id, created_at, updated_at, status, lead_name, phone_e164, timezone,
      attempts, max_attempts, next_attempt_at, last_error, room_name, agent_id,
      recording_enabled, dnc, dnc_reason, metadata, provider_call_id, call_id, locked_at, locked_by
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
    RETURNING *
  `,
    [
      id,
      workspaceId,
      now,
      now,
      "queued",
      String(leadName || ""),
      String(phoneE164 || ""),
      String(timezone || "UTC"),
      0,
      Math.max(1, Math.round(Number(maxAttempts || 3))),
      now,
      "",
      null,
      String(agentId || ""),
      Boolean(recordingEnabled),
      false,
      "",
      JSON.stringify(metadata || {}),
      null,
      null,
      null,
      null,
    ]
  );
  return rowToOutboundJob(rows[0]);
}

async function getOutboundJob(workspaceId, id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM outbound_jobs WHERE workspace_id=$1 AND id=$2`, [workspaceId, id]);
  return rows[0] ? rowToOutboundJob(rows[0]) : null;
}

async function listOutboundJobs(workspaceId, { status, limit = 100, offset = 0 } = {}) {
  const p = getPool();
  const params = [workspaceId];
  let where = `WHERE workspace_id=$1`;
  if (status) {
    params.push(status);
    where += ` AND status=$${params.length}`;
  }
  params.push(Math.min(200, Math.max(1, Number(limit || 100))));
  params.push(Math.max(0, Number(offset || 0)));
  const { rows } = await p.query(
    `
    SELECT * FROM outbound_jobs
    ${where}
    ORDER BY created_at DESC
    LIMIT $${params.length - 1} OFFSET $${params.length}
  `,
    params
  );
  return rows.map(rowToOutboundJob);
}

async function getOutboundJobByProviderCallId(workspaceId, providerCallId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT * FROM outbound_jobs WHERE workspace_id=$1 AND provider_call_id=$2 ORDER BY created_at DESC LIMIT 1`,
    [workspaceId, providerCallId]
  );
  return rows[0] ? rowToOutboundJob(rows[0]) : null;
}

async function updateOutboundJob(workspaceId, id, patch) {
  const p = getPool();
  const current = await getOutboundJob(workspaceId, id);
  if (!current) return null;
  const next = {
    status: patch.status ?? current.status,
    leadName: patch.leadName ?? current.leadName,
    phoneE164: patch.phoneE164 ?? current.phoneE164,
    timezone: patch.timezone ?? current.timezone,
    attempts: patch.attempts == null ? current.attempts : Number(patch.attempts || 0),
    maxAttempts: patch.maxAttempts == null ? current.maxAttempts : Number(patch.maxAttempts || 0),
    nextAttemptAt: patch.nextAttemptAt == null ? current.nextAttemptAt : patch.nextAttemptAt,
    lastError: patch.lastError ?? current.lastError,
    roomName: patch.roomName ?? current.roomName,
    agentId: patch.agentId ?? current.agentId,
    recordingEnabled: patch.recordingEnabled == null ? current.recordingEnabled : Boolean(patch.recordingEnabled),
    dnc: patch.dnc == null ? current.dnc : Boolean(patch.dnc),
    dncReason: patch.dncReason ?? current.dncReason,
    metadata: patch.metadata == null ? current.metadata : patch.metadata,
    providerCallId: patch.providerCallId ?? current.providerCallId,
    callId: patch.callId ?? current.callId,
    lockedAt: patch.lockedAt == null ? current.lockedAt : patch.lockedAt,
    lockedBy: patch.lockedBy ?? current.lockedBy,
  };
  const updatedAt = Date.now();
  const { rows } = await p.query(
    `
    UPDATE outbound_jobs
    SET status=$3,
        lead_name=$4,
        phone_e164=$5,
        timezone=$6,
        attempts=$7,
        max_attempts=$8,
        next_attempt_at=$9,
        last_error=$10,
        room_name=$11,
        agent_id=$12,
        recording_enabled=$13,
        dnc=$14,
        dnc_reason=$15,
        metadata=$16,
        provider_call_id=$17,
        call_id=$18,
        locked_at=$19,
        locked_by=$20,
        updated_at=$21
    WHERE workspace_id=$1 AND id=$2
    RETURNING *
  `,
    [
      workspaceId,
      id,
      next.status,
      next.leadName,
      next.phoneE164,
      next.timezone,
      next.attempts,
      next.maxAttempts,
      next.nextAttemptAt,
      next.lastError,
      next.roomName,
      next.agentId,
      next.recordingEnabled,
      next.dnc,
      next.dncReason,
      JSON.stringify(next.metadata || {}),
      next.providerCallId,
      next.callId,
      next.lockedAt,
      next.lockedBy,
      updatedAt,
    ]
  );
  return rows[0] ? rowToOutboundJob(rows[0]) : null;
}

async function countOutboundActive(workspaceId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT COUNT(*)::int AS cnt FROM outbound_jobs WHERE workspace_id=$1 AND status IN ('dialing','in_call')`,
    [workspaceId]
  );
  return rows[0] ? Number(rows[0].cnt || 0) : 0;
}

async function countInProgressCalls(workspaceId) {
  const p = getPool();
  const { rows } = await p.query(
    `SELECT COUNT(*)::int AS cnt FROM calls WHERE workspace_id=$1 AND outcome='in_progress'`,
    [workspaceId]
  );
  return rows[0] ? Number(rows[0].cnt || 0) : 0;
}

async function claimOutboundJobs(workspaceId, nowMs, limit, workerId) {
  const p = getPool();
  const { rows } = await p.query(
    `
    WITH cte AS (
      SELECT id
      FROM outbound_jobs
      WHERE workspace_id=$1
        AND status='queued'
        AND dnc=false
        AND (next_attempt_at IS NULL OR next_attempt_at <= $2)
        AND attempts < max_attempts
      ORDER BY COALESCE(next_attempt_at, created_at) ASC, created_at ASC
      LIMIT $3
      FOR UPDATE SKIP LOCKED
    )
    UPDATE outbound_jobs
    SET status='dialing',
        attempts=attempts+1,
        locked_at=$2,
        locked_by=$4,
        updated_at=$2
    FROM cte
    WHERE outbound_jobs.id=cte.id
    RETURNING outbound_jobs.*
  `,
    [workspaceId, nowMs, Math.max(1, Number(limit || 1)), String(workerId || "")] 
  );
  return rows.map(rowToOutboundJob);
}

async function addOutboundJobLog(workspaceId, jobId, { level = "info", message, meta = {} }) {
  const p = getPool();
  const id = nanoid(12);
  const now = Date.now();
  const { rows } = await p.query(
    `
    INSERT INTO outbound_job_logs (id, workspace_id, job_id, level, message, meta, created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    RETURNING *
  `,
    [id, workspaceId, jobId, String(level || "info"), String(message || ""), JSON.stringify(meta || {}), now]
  );
  return rows[0] ? rowToOutboundJobLog(rows[0]) : null;
}

async function listOutboundJobLogs(workspaceId, jobId, limit = 200) {
  const p = getPool();
  const { rows } = await p.query(
    `
    SELECT * FROM outbound_job_logs
    WHERE workspace_id=$1 AND job_id=$2
    ORDER BY created_at DESC
    LIMIT $3
  `,
    [workspaceId, jobId, Math.min(300, Math.max(1, Number(limit || 200)))]
  );
  return rows.map(rowToOutboundJobLog);
}

// Contacts / CRM - re-exported from crm/store.js

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

  // Outbound jobs
  createOutboundJob,
  getOutboundJob,
  getOutboundJobByProviderCallId,
  listOutboundJobs,
  updateOutboundJob,
  countOutboundActive,
  countInProgressCalls,
  claimOutboundJobs,
  addOutboundJobLog,
  listOutboundJobLogs,

  // Contacts / CRM - re-exported from crm/store.js
  ...require("./crm/store"),
};


