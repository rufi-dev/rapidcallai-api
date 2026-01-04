const twilio = require("twilio");

function getMasterCreds() {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  if (!accountSid || !authToken) return null;
  return { accountSid, authToken };
}

function getMasterClient() {
  const creds = getMasterCreds();
  if (!creds) return null;
  return twilio(creds.accountSid, creds.authToken);
}

function getSubaccountClient(subaccountSid) {
  const creds = getMasterCreds();
  if (!creds) return null;
  // Twilio helper lib supports acting on a subaccount by setting `accountSid` option.
  return twilio(creds.accountSid, creds.authToken, { accountSid: subaccountSid });
}

async function ensureSubaccount({ friendlyName, existingSid }) {
  if (existingSid) return { sid: existingSid, created: false };
  const client = getMasterClient();
  if (!client) throw new Error("Twilio is not configured (missing TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN)");
  const acct = await client.api.accounts.create({ friendlyName: friendlyName || "rapidcallai workspace" });
  return { sid: acct.sid, created: true };
}

async function searchAvailableNumbers({ subaccountSid, country, type, contains, limit = 20 }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  const client = getSubaccountClient(subaccountSid);
  if (!client) throw new Error("Twilio is not configured (missing TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN)");

  const cc = String(country || "US").toUpperCase();
  const kind = String(type || "local").toLowerCase();
  const opts = { pageSize: Math.min(Number(limit) || 20, 50) };
  if (contains) opts.contains = String(contains);

  const available = kind === "tollfree"
    ? await client.availablePhoneNumbers(cc).tollFree.list(opts)
    : await client.availablePhoneNumbers(cc).local.list(opts);

  return available.map((n) => ({
    phoneNumber: n.phoneNumber,
    friendlyName: n.friendlyName ?? null,
    locality: n.locality ?? null,
    region: n.region ?? null,
    isoCountry: n.isoCountry ?? cc,
    capabilities: n.capabilities ?? null,
  }));
}

async function buyNumber({ subaccountSid, phoneNumber, friendlyName }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  const client = getSubaccountClient(subaccountSid);
  if (!client) throw new Error("Twilio is not configured (missing TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN)");

  const incoming = await client.incomingPhoneNumbers.create({
    phoneNumber,
    friendlyName: friendlyName || undefined,
  });

  return {
    sid: incoming.sid,
    phoneNumber: incoming.phoneNumber,
    friendlyName: incoming.friendlyName ?? null,
  };
}

module.exports = {
  getMasterCreds,
  ensureSubaccount,
  searchAvailableNumbers,
  buyNumber,
};


