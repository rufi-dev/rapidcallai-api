const fs = require("fs");
const path = require("path");

const DATA_DIR = path.join(__dirname, "..", "data");
const AGENTS_FILE = path.join(DATA_DIR, "agents.json");
const CALLS_FILE = path.join(DATA_DIR, "calls.json");
const WORKSPACES_FILE = path.join(DATA_DIR, "workspaces.json");
const PHONE_NUMBERS_FILE = path.join(DATA_DIR, "phone_numbers.json");

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(AGENTS_FILE)) fs.writeFileSync(AGENTS_FILE, "[]", "utf-8");
  if (!fs.existsSync(CALLS_FILE)) fs.writeFileSync(CALLS_FILE, "[]", "utf-8");
  if (!fs.existsSync(WORKSPACES_FILE)) fs.writeFileSync(WORKSPACES_FILE, "[]", "utf-8");
  if (!fs.existsSync(PHONE_NUMBERS_FILE)) fs.writeFileSync(PHONE_NUMBERS_FILE, "[]", "utf-8");
}

function readAgents() {
  ensureDataDir();
  const raw = fs.readFileSync(AGENTS_FILE, "utf-8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeAgents(agents) {
  ensureDataDir();
  fs.writeFileSync(AGENTS_FILE, JSON.stringify(agents, null, 2), "utf-8");
}

function readCalls() {
  ensureDataDir();
  const raw = fs.readFileSync(CALLS_FILE, "utf-8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeCalls(calls) {
  ensureDataDir();
  fs.writeFileSync(CALLS_FILE, JSON.stringify(calls, null, 2), "utf-8");
}

function readWorkspaces() {
  ensureDataDir();
  const raw = fs.readFileSync(WORKSPACES_FILE, "utf-8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeWorkspaces(workspaces) {
  ensureDataDir();
  fs.writeFileSync(WORKSPACES_FILE, JSON.stringify(workspaces, null, 2), "utf-8");
}

function readPhoneNumbers() {
  ensureDataDir();
  const raw = fs.readFileSync(PHONE_NUMBERS_FILE, "utf-8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writePhoneNumbers(rows) {
  ensureDataDir();
  fs.writeFileSync(PHONE_NUMBERS_FILE, JSON.stringify(rows, null, 2), "utf-8");
}

module.exports = {
  readAgents,
  writeAgents,
  readCalls,
  writeCalls,
  readWorkspaces,
  writeWorkspaces,
  readPhoneNumbers,
  writePhoneNumbers,
};


