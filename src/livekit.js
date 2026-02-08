const { AccessToken, RoomServiceClient, AgentDispatchClient, SipClient } = require("livekit-server-sdk");

function getLiveKitConfig() {
  const url = process.env.LIVEKIT_URL;
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  if (!url || !apiKey || !apiSecret) {
    throw new Error("Missing LIVEKIT_URL / LIVEKIT_API_KEY / LIVEKIT_API_SECRET in server environment");
  }

  // LIVEKIT_URL used by browser clients is typically wss://...
  // Server SDK clients (RoomService/Dispatch) must use an HTTP(S) endpoint.
  let apiUrl = String(url);
  if (apiUrl.startsWith("wss://")) apiUrl = `https://${apiUrl.slice("wss://".length)}`;
  if (apiUrl.startsWith("ws://")) apiUrl = `http://${apiUrl.slice("ws://".length)}`;

  return { url, apiUrl, apiKey, apiSecret };
}

function roomService() {
  const { apiUrl, apiKey, apiSecret } = getLiveKitConfig();
  return new RoomServiceClient(apiUrl, apiKey, apiSecret);
}

function agentDispatchService() {
  const { apiUrl, apiKey, apiSecret } = getLiveKitConfig();
  return new AgentDispatchClient(apiUrl, apiKey, apiSecret);
}

async function createParticipantToken({ roomName, identity, name, metadata }) {
  const { apiKey, apiSecret } = getLiveKitConfig();
  const at = new AccessToken(apiKey, apiSecret, { identity, name, metadata });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
  return await at.toJwt();
}

function sipClient() {
  const { apiUrl, apiKey, apiSecret } = getLiveKitConfig();
  return new SipClient(apiUrl, apiKey, apiSecret);
}

/**
 * Add a phone number to an existing LiveKit SIP inbound trunk.
 * Uses the updateSipInboundTrunkFields API with ListUpdate to add without replacing.
 */
async function addNumberToInboundTrunk(trunkId, phoneE164) {
  const { ListUpdate } = require("@livekit/protocol");
  const sip = sipClient();
  return await sip.updateSipInboundTrunkFields(trunkId, {
    numbers: new ListUpdate({ add: [phoneE164] }),
  });
}

/**
 * Add a phone number to an existing LiveKit SIP outbound trunk.
 * Uses the updateSipOutboundTrunkFields API with ListUpdate to add without replacing.
 */
async function addNumberToOutboundTrunk(trunkId, phoneE164) {
  const { ListUpdate } = require("@livekit/protocol");
  const sip = sipClient();
  return await sip.updateSipOutboundTrunkFields(trunkId, {
    numbers: new ListUpdate({ add: [phoneE164] }),
  });
}

/**
 * Remove a phone number from an existing LiveKit SIP inbound trunk.
 */
async function removeNumberFromInboundTrunk(trunkId, phoneE164) {
  const { ListUpdate } = require("@livekit/protocol");
  const sip = sipClient();
  return await sip.updateSipInboundTrunkFields(trunkId, {
    numbers: new ListUpdate({ remove: [phoneE164] }),
  });
}

/**
 * Remove a phone number from an existing LiveKit SIP outbound trunk.
 */
async function removeNumberFromOutboundTrunk(trunkId, phoneE164) {
  const { ListUpdate } = require("@livekit/protocol");
  const sip = sipClient();
  return await sip.updateSipOutboundTrunkFields(trunkId, {
    numbers: new ListUpdate({ remove: [phoneE164] }),
  });
}

/**
 * Ensure an existing LiveKit SIP outbound trunk uses TLS transport.
 * This is required when the Twilio trunk has secure: true.
 */
async function ensureOutboundTrunkUsesTls(trunkId) {
  const sip = sipClient();
  try {
    await sip.updateSipOutboundTrunkFields(trunkId, {
      transport: "tls",
    });
  } catch (e) {
    // Best-effort: if update fails, log but don't throw
    console.warn(`[ensureOutboundTrunkUsesTls] Failed to update trunk ${trunkId} to TLS: ${e?.message || e}`);
  }
}

/**
 * Create a new LiveKit SIP outbound trunk pointing to a Twilio SIP trunk.
 * Uses the subaccount's termination credentials so Caller ID is recognized.
 * Configures TLS transport for secure trunking (required when Twilio trunk has secure: true).
 */
async function createOutboundTrunkForWorkspace({ workspaceId, twilioSipDomainName, credUsername, credPassword, numbers }) {
  const sip = sipClient();
  const address = `${twilioSipDomainName}`;
  const trunk = await sip.createSipOutboundTrunk(
    `RapidCall AI outbound (${workspaceId || "default"})`,
    address,
    numbers || [],
    {
      authUsername: credUsername,
      authPassword: credPassword,
      transport: "tls", // Required for secure Twilio trunks (secure: true)
    }
  );
  return { trunkId: trunk.sipTrunkId };
}

module.exports = {
  roomService,
  agentDispatchService,
  createParticipantToken,
  sipClient,
  addNumberToInboundTrunk,
  addNumberToOutboundTrunk,
  removeNumberFromInboundTrunk,
  removeNumberFromOutboundTrunk,
  createOutboundTrunkForWorkspace,
  ensureOutboundTrunkUsesTls,
};


