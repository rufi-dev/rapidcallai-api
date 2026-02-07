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

/**
 * Configure a Twilio phone number to forward inbound calls to LiveKit SIP.
 * Sets the voice URL to a TwiML endpoint that dials sip:<number>@<sipEndpoint>.
 * Also sets the status callback URL for call events.
 *
 * @param {Object} opts
 * @param {string} opts.subaccountSid - Twilio subaccount SID
 * @param {string} opts.numberSid - The Twilio phone number SID (e.g. PNxxxxxx)
 * @param {string} opts.e164 - The phone number in E.164 format
 * @param {string} opts.sipEndpoint - LiveKit SIP endpoint (e.g. "25f6q0vix3k.sip.livekit.cloud")
 * @param {string} opts.sipUsername - Credential for LiveKit inbound trunk auth
 * @param {string} opts.sipPassword - Credential for LiveKit inbound trunk auth
 * @param {string} [opts.statusCallbackUrl] - Optional status callback URL
 */
async function configureNumberForSip({ subaccountSid, numberSid, e164, sipEndpoint, sipUsername, sipPassword, statusCallbackUrl }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  const client = getSubaccountClient(subaccountSid);
  if (!client) throw new Error("Twilio is not configured");

  if (!sipEndpoint) throw new Error("LIVEKIT_SIP_ENDPOINT is not set");

  // Build TwiML that forwards the call to LiveKit SIP.
  // Using a TwiML Bin style approach: we create a TwiML Application or use voiceUrl with inline TwiML.
  // Twilio doesn't support inline TwiML, so we use a webhook that returns TwiML.
  // However, we can use a "voiceUrl" pointing to our own server endpoint that generates TwiML.
  //
  // Simplest approach: use our server's /api/twilio/inbound endpoint which already exists.
  // That endpoint generates the correct TwiML to bridge to LiveKit SIP.

  const publicBaseUrl = String(process.env.PUBLIC_API_BASE_URL || "").trim().replace(/\/$/, "");
  if (!publicBaseUrl) throw new Error("PUBLIC_API_BASE_URL is not set — needed for Twilio voice URL");

  const voiceUrl = `${publicBaseUrl}/api/twilio/inbound`;
  const updates = {
    voiceUrl,
    voiceMethod: "POST",
    voiceFallbackUrl: voiceUrl,
    voiceFallbackMethod: "POST",
  };

  if (statusCallbackUrl) {
    updates.statusCallback = statusCallbackUrl;
    updates.statusCallbackMethod = "POST";
  }

  await client.incomingPhoneNumbers(numberSid).update(updates);

  return { voiceUrl };
}

/**
 * Ensure a Twilio Elastic SIP Trunk exists on the subaccount.
 * Creates the trunk + termination credentials + associates them if needed.
 * Returns { trunkSid, domainName, credUsername, credPassword }.
 */
async function ensureSipTrunk({ subaccountSid, existingTrunkSid, workspaceId }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  const client = getSubaccountClient(subaccountSid);
  if (!client) throw new Error("Twilio is not configured");

  // Re-use existing trunk if we have one.
  if (existingTrunkSid) {
    try {
      const trunk = await client.trunking.v1.trunks(existingTrunkSid).fetch();
      return {
        trunkSid: trunk.sid,
        domainName: trunk.domainName || null,
      };
    } catch {
      // Trunk may have been deleted; fall through to create a new one.
    }
  }

  // Generate a unique domain name (must end in .pstn.twilio.com).
  const slug = `rc-${(workspaceId || "ws").replace(/[^a-z0-9]/gi, "").slice(0, 16)}-${Date.now().toString(36)}`;
  const domainName = `${slug}.pstn.twilio.com`;

  const trunk = await client.trunking.v1.trunks.create({
    friendlyName: `RapidCall AI outbound (${workspaceId || "default"})`,
    domainName,
  });

  return {
    trunkSid: trunk.sid,
    domainName: trunk.domainName,
  };
}

/**
 * Ensure termination credentials exist on the Twilio SIP trunk.
 * Creates a credential list + credential and associates it with the trunk.
 * Returns { credUsername, credPassword }.
 */
async function ensureSipTrunkTerminationCreds({ subaccountSid, trunkSid, existingUsername, existingPassword }) {
  if (existingUsername && existingPassword) {
    return { credUsername: existingUsername, credPassword: existingPassword };
  }

  const client = getSubaccountClient(subaccountSid);
  if (!client) throw new Error("Twilio is not configured");

  const username = `rc_${Date.now().toString(36)}`;
  const crypto = require("crypto");
  // Twilio requires: min 12 chars, at least one uppercase, one lowercase, one number.
  // crypto.randomBytes hex is only lowercase+digits, so we build a proper password.
  const raw = crypto.randomBytes(24).toString("base64url").slice(0, 28);
  // Guarantee at least one of each required character class.
  const password = "Rc1" + raw;

  // Create credential list on the subaccount.
  const credList = await client.sip.credentialLists.create({
    friendlyName: `RapidCall AI SIP creds (${trunkSid})`,
  });

  // Add credential to the list.
  await client.sip.credentialLists(credList.sid).credentials.create({
    username,
    password,
  });

  // Associate credential list with the trunk for termination auth.
  await client.trunking.v1.trunks(trunkSid).credentialLists.create({
    credentialListSid: credList.sid,
  });

  return { credUsername: username, credPassword: password };
}

/**
 * Associate a phone number with a Twilio SIP trunk (required for outbound Caller ID).
 */
async function associateNumberWithSipTrunk({ subaccountSid, trunkSid, numberSid }) {
  const client = getSubaccountClient(subaccountSid);
  if (!client) throw new Error("Twilio is not configured");

  await client.trunking.v1.trunks(trunkSid).phoneNumbers.create({
    phoneNumberSid: numberSid,
  });
}

module.exports = {
  getMasterCreds,
  getSubaccountClient,
  ensureSubaccount,
  searchAvailableNumbers,
  buyNumber,
  configureNumberForSip,
  ensureSipTrunk,
  ensureSipTrunkTerminationCreds,
  associateNumberWithSipTrunk,
};


