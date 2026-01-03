require("dotenv").config({
  path: require("path").join(__dirname, "..", ".env"),
  override: true,
});

const fs = require("fs");
const path = require("path");
const { initSchema } = require("./db");
const { upsertAgentForMigration, upsertCallForMigration } = require("./store_pg");

function readJsonArray(file) {
  if (!fs.existsSync(file)) return [];
  const raw = fs.readFileSync(file, "utf-8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function main() {
  const ok = await initSchema();
  if (!ok) {
    // eslint-disable-next-line no-console
    console.error("DATABASE_URL is not set; cannot migrate.");
    process.exit(1);
  }

  const dataDir = process.env.MIGRATE_DATA_DIR
    ? path.resolve(process.env.MIGRATE_DATA_DIR)
    : path.join(__dirname, "..", "data");

  const agentsFile = path.join(dataDir, "agents.json");
  const callsFile = path.join(dataDir, "calls.json");

  const agents = readJsonArray(agentsFile);
  const calls = readJsonArray(callsFile);

  // eslint-disable-next-line no-console
  console.log(`Migrating from ${dataDir}`);
  // eslint-disable-next-line no-console
  console.log(`Agents: ${agents.length}, Calls: ${calls.length}`);

  for (const a of agents) {
    await upsertAgentForMigration(a);
  }
  for (const c of calls) {
    await upsertCallForMigration(c);
  }

  // eslint-disable-next-line no-console
  console.log("Migration complete.");
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});


