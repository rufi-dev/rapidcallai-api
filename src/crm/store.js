const { nanoid } = require("../id");
const { getPool } = require("../db");

function rowToContact(r) {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    phoneE164: r.phone_e164,
    name: r.name ?? "",
    email: r.email ?? "",
    company: r.company ?? "",
    tags: Array.isArray(r.tags) ? r.tags : [],
    notes: r.notes ?? "",
    source: r.source ?? "manual",
    totalCalls: Number(r.total_calls || 0),
    lastCallAt: r.last_call_at ?? null,
    lastCallOutcome: r.last_call_outcome ?? "",
    metadata: r.metadata ?? {},
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

async function createContact(input) {
  const p = getPool();
  const now = Date.now();
  const id = nanoid(10);

  const tags = Array.isArray(input.tags) ? input.tags : [];
  const metadata = input.metadata ?? {};

  const { rows } = await p.query(
    `
    INSERT INTO contacts
      (id, workspace_id, phone_e164, name, email, company, tags, notes, source, metadata, created_at, updated_at)
    VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (workspace_id, phone_e164) DO UPDATE SET
      name = COALESCE(EXCLUDED.name, contacts.name),
      email = COALESCE(EXCLUDED.email, contacts.email),
      company = COALESCE(EXCLUDED.company, contacts.company),
      tags = COALESCE(EXCLUDED.tags, contacts.tags),
      notes = COALESCE(EXCLUDED.notes, contacts.notes),
      source = COALESCE(EXCLUDED.source, contacts.source),
      metadata = COALESCE(EXCLUDED.metadata, contacts.metadata),
      updated_at = $12
    RETURNING *
  `,
    [
      id,
      input.workspaceId,
      input.phoneE164,
      input.name ?? "",
      input.email ?? "",
      input.company ?? "",
      JSON.stringify(tags),
      input.notes ?? "",
      input.source ?? "manual",
      JSON.stringify(metadata),
      now,
      now,
    ]
  );
  return rowToContact(rows[0]);
}

async function getContact(id) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM contacts WHERE id=$1`, [id]);
  return rows[0] ? rowToContact(rows[0]) : null;
}

async function getContactByPhone(workspaceId, phoneE164) {
  const p = getPool();
  const { rows } = await p.query(`SELECT * FROM contacts WHERE workspace_id=$1 AND phone_e164=$2`, [
    workspaceId,
    phoneE164,
  ]);
  return rows[0] ? rowToContact(rows[0]) : null;
}

async function listContacts(workspaceId, { search, tag, source, limit = 100, offset = 0 } = {}) {
  const p = getPool();
  let query = `SELECT * FROM contacts WHERE workspace_id=$1`;
  const params = [workspaceId];
  let paramIdx = 2;

  if (search) {
    const searchLower = `%${String(search).toLowerCase()}%`;
    query += ` AND (
      LOWER(name) LIKE $${paramIdx} OR
      LOWER(phone_e164) LIKE $${paramIdx} OR
      LOWER(email) LIKE $${paramIdx}
    )`;
    params.push(searchLower);
    paramIdx++;
  }

  if (tag) {
    query += ` AND $${paramIdx} = ANY(tags)`;
    params.push(String(tag));
    paramIdx++;
  }

  if (source) {
    query += ` AND source=$${paramIdx}`;
    params.push(String(source));
    paramIdx++;
  }

  query += ` ORDER BY last_call_at DESC NULLS LAST, created_at DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(Number(limit), Number(offset));

  const { rows } = await p.query(query, params);
  return rows.map(rowToContact);
}

async function updateContact(id, patch) {
  const p = getPool();
  const existing = await getContact(id);
  if (!existing) return null;

  const safePatch = Object.fromEntries(Object.entries(patch || {}).filter(([, v]) => v !== undefined));
  const next = { ...existing, ...safePatch, updatedAt: Date.now() };

  const tags = Array.isArray(next.tags) ? next.tags : [];
  const metadata = next.metadata ?? {};

  // Build dynamic update query based on what fields are being updated
  const updates = [];
  const values = [id];
  let paramIdx = 2;

  if (safePatch.name !== undefined) {
    updates.push(`name=$${paramIdx++}`);
    values.push(next.name ?? "");
  }
  if (safePatch.email !== undefined) {
    updates.push(`email=$${paramIdx++}`);
    values.push(next.email ?? "");
  }
  if (safePatch.company !== undefined) {
    updates.push(`company=$${paramIdx++}`);
    values.push(next.company ?? "");
  }
  if (safePatch.tags !== undefined) {
    updates.push(`tags=$${paramIdx++}`);
    values.push(JSON.stringify(tags));
  }
  if (safePatch.notes !== undefined) {
    updates.push(`notes=$${paramIdx++}`);
    values.push(next.notes ?? "");
  }
  if (safePatch.source !== undefined) {
    updates.push(`source=$${paramIdx++}`);
    values.push(next.source ?? "manual");
  }
  if (safePatch.metadata !== undefined) {
    updates.push(`metadata=$${paramIdx++}`);
    values.push(JSON.stringify(metadata));
  }
  if (safePatch.totalCalls !== undefined) {
    updates.push(`total_calls=$${paramIdx++}`);
    values.push(Number(next.totalCalls || 0));
  }
  if (safePatch.lastCallAt !== undefined) {
    updates.push(`last_call_at=$${paramIdx++}`);
    values.push(next.lastCallAt ?? null);
  }
  if (safePatch.lastCallOutcome !== undefined) {
    updates.push(`last_call_outcome=$${paramIdx++}`);
    values.push(next.lastCallOutcome ?? "");
  }

  if (updates.length === 0) {
    return existing; // No changes
  }

  updates.push(`updated_at=$${paramIdx++}`);
  values.push(next.updatedAt);

  const { rows } = await p.query(
    `
    UPDATE contacts
    SET ${updates.join(", ")}
    WHERE id=$1
    RETURNING *
  `,
    values
  );
  return rows[0] ? rowToContact(rows[0]) : null;
}

async function deleteContact(id) {
  const p = getPool();
  await p.query(`DELETE FROM contacts WHERE id=$1`, [id]);
}

async function upsertContactFromCall(workspaceId, phoneE164, name, source) {
  const p = getPool();
  const now = Date.now();

  // Try to get existing contact
  const existing = await getContactByPhone(workspaceId, phoneE164);

  if (existing) {
    // Update: increment total_calls, set last_call_at, update name if provided
    const { rows } = await p.query(
      `
      UPDATE contacts
      SET total_calls = total_calls + 1,
          last_call_at = $1,
          name = CASE WHEN $2 != '' AND name = '' THEN $2 ELSE name END,
          updated_at = $1
      WHERE id = $3
      RETURNING *
    `,
      [now, name ?? "", existing.id]
    );
    return rows[0] ? rowToContact(rows[0]) : null;
  } else {
    // Create new contact
    const id = nanoid(10);
    const { rows } = await p.query(
      `
      INSERT INTO contacts
        (id, workspace_id, phone_e164, name, source, total_calls, last_call_at, created_at, updated_at)
      VALUES
        ($1, $2, $3, $4, $5, 1, $6, $6, $6)
      RETURNING *
    `,
      [id, workspaceId, phoneE164, name ?? "", source ?? "inbound", now]
    );
    return rows[0] ? rowToContact(rows[0]) : null;
  }
}

async function bulkCreateContacts(workspaceId, rows) {
  const p = getPool();
  const now = Date.now();
  const results = [];

  for (const row of rows) {
    const id = nanoid(10);
    const tags = Array.isArray(row.tags) ? row.tags : [];
    const metadata = row.metadata ?? {};

    try {
      const { rows: inserted } = await p.query(
        `
        INSERT INTO contacts
          (id, workspace_id, phone_e164, name, email, company, tags, notes, source, metadata, created_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (workspace_id, phone_e164) DO NOTHING
        RETURNING *
      `,
        [
          id,
          workspaceId,
          row.phoneE164,
          row.name ?? "",
          row.email ?? "",
          row.company ?? "",
          JSON.stringify(tags),
          row.notes ?? "",
          "import",
          JSON.stringify(metadata),
          now,
          now,
        ]
      );
      if (inserted.length > 0) {
        results.push(rowToContact(inserted[0]));
      }
    } catch (e) {
      // Skip invalid rows, continue with next
      console.warn(`[bulkCreateContacts] skipped row: ${e?.message || e}`);
    }
  }

  return results;
}

module.exports = {
  createContact,
  getContact,
  getContactByPhone,
  listContacts,
  updateContact,
  deleteContact,
  upsertContactFromCall,
  bulkCreateContacts,
};
