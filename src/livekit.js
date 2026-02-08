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
 * Get the current state of a LiveKit SIP outbound trunk.
 * Note: This may not be available in all SDK versions - falls back to listing all trunks.
 */
async function getOutboundTrunkInfo(trunkId) {
  const sip = sipClient();
  try {
    // Try to get the specific trunk (if method exists)
    if (typeof sip.getSipOutboundTrunk === "function") {
      const trunk = await sip.getSipOutboundTrunk(trunkId);
      return trunk;
    }
    // Fallback: list all trunks and find the one we need
    if (typeof sip.listSipOutboundTrunk === "function") {
      const trunks = await sip.listSipOutboundTrunk();
      const trunk = trunks.find((t) => t.sipTrunkId === trunkId);
      if (trunk) return trunk;
    }
    // If we can't get the trunk info, return null (caller should handle)
    console.warn(`[getOutboundTrunkInfo] Cannot retrieve trunk ${trunkId} info - SDK method may not be available`);
    return null;
  } catch (e) {
    console.warn(`[getOutboundTrunkInfo] Failed to get trunk ${trunkId} info: ${e?.message || e}`);
    return null;
  }
}

/**
 * Ensure an existing LiveKit SIP outbound trunk uses TLS transport.
 * This is required when the Twilio trunk has secure: true.
 * 
 * IMPORTANT: The transport parameter must match what LiveKit SDK expects.
 * Common values: "tls", "TLS", or numeric enum (check SDK docs).
 */
async function ensureOutboundTrunkUsesTls(trunkId) {
  const sip = sipClient();
  try {
    // First, check current state (if possible)
    const current = await getOutboundTrunkInfo(trunkId);
    const currentTransport = current?.transport || "unknown";
    
    if (currentTransport === "tls" || currentTransport === "TLS" || currentTransport === 2) {
      console.log(`[ensureOutboundTrunkUsesTls] Trunk ${trunkId} already uses TLS transport (${currentTransport})`);
      return { updated: false, previousTransport: currentTransport };
    }

    console.log(`[ensureOutboundTrunkUsesTls] Updating trunk ${trunkId} from transport "${currentTransport}" to TLS`);
    console.log(`[ensureOutboundTrunkUsesTls] Trunk details:`, JSON.stringify({
      trunkId,
      currentTransport,
      address: current?.outboundAddress,
      numbers: current?.outboundNumbers?.length || 0,
    }, null, 2));
    
    // Try updating with "tls" string first (most common)
    try {
      await sip.updateSipOutboundTrunkFields(trunkId, {
        transport: "tls",
      });
      console.log(`[ensureOutboundTrunkUsesTls] Update call succeeded with transport="tls"`);
    } catch (e1) {
      // If "tls" fails, try "TLS" (uppercase)
      console.warn(`[ensureOutboundTrunkUsesTls] Update with "tls" failed: ${e1?.message || e1}, trying "TLS"`);
      try {
        await sip.updateSipOutboundTrunkFields(trunkId, {
          transport: "TLS",
        });
        console.log(`[ensureOutboundTrunkUsesTls] Update call succeeded with transport="TLS"`);
      } catch (e2) {
        // If both fail, try numeric enum value 2 (common for TLS)
        console.warn(`[ensureOutboundTrunkUsesTls] Update with "TLS" failed: ${e2?.message || e2}, trying numeric 2`);
        try {
          await sip.updateSipOutboundTrunkFields(trunkId, {
            transport: 2,
          });
          console.log(`[ensureOutboundTrunkUsesTls] Update call succeeded with transport=2`);
        } catch (e3) {
          throw new Error(`All transport update attempts failed. Last error: ${e3?.message || e3}. Previous: ${e2?.message || e2}, ${e1?.message || e1}`);
        }
      }
    }

    // Verify the update worked (if we can retrieve trunk info)
    const updated = await getOutboundTrunkInfo(trunkId);
    if (updated) {
      const newTransport = updated?.transport || "unknown";
      const isTls = newTransport === "tls" || newTransport === "TLS" || newTransport === 2;
      if (!isTls) {
        console.error(`[ensureOutboundTrunkUsesTls] WARNING: Transport update may have failed. Expected TLS, got: ${newTransport}`);
      } else {
        console.log(`[ensureOutboundTrunkUsesTls] Successfully verified trunk ${trunkId} uses TLS transport (${newTransport})`);
      }
    } else {
      console.warn(`[ensureOutboundTrunkUsesTls] Cannot verify transport update - trunk info retrieval not available`);
    }

    return { updated: true, previousTransport: currentTransport };
  } catch (e) {
    const errorMsg = `[ensureOutboundTrunkUsesTls] CRITICAL: Failed to update trunk ${trunkId} to TLS: ${e?.message || e}. Stack: ${e?.stack || "N/A"}`;
    console.error(errorMsg);
    // Throw the error so callers know it failed
    throw new Error(errorMsg);
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
  getOutboundTrunkInfo,
};


