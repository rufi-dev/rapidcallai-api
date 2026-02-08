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
 * Delete a LiveKit SIP outbound trunk.
 * Note: This may not be available in all SDK versions.
 */
async function deleteOutboundTrunk(trunkId) {
  const sip = sipClient();
  try {
    if (typeof sip.deleteSipOutboundTrunk === "function") {
      await sip.deleteSipOutboundTrunk(trunkId);
      console.log(`[deleteOutboundTrunk] Successfully deleted trunk ${trunkId}`);
      return true;
    } else {
      console.warn(`[deleteOutboundTrunk] deleteSipOutboundTrunk method not available in SDK`);
      return false;
    }
  } catch (e) {
    console.error(`[deleteOutboundTrunk] Failed to delete trunk ${trunkId}: ${e?.message || e}`);
    throw new Error(`Failed to delete trunk: ${e?.message || e}`);
  }
}

/**
 * Ensure an existing LiveKit SIP outbound trunk uses the correct transport.
 * Uses TLS (2) when secure trunking is enabled, TCP (1) when disabled.
 * 
 * CRITICAL: LiveKit SDK requires transport as numeric enum:
 * - 0 = UDP
 * - 1 = TCP
 * - 2 = TLS
 * 
 * String values fail with encoding errors.
 */
async function ensureOutboundTrunkTransport(trunkId, secure) {
  const sip = sipClient();
  const targetTransport = secure ? 2 : 1; // TLS (2) if secure, TCP (1) if not
  const targetName = secure ? 'TLS' : 'TCP';
  
  try {
    // First, check current state (if possible)
    const current = await getOutboundTrunkInfo(trunkId);
    const currentTransport = current?.transport ?? null;
    
    // Log what we found
    console.log(`[ensureOutboundTrunkTransport] Trunk ${trunkId} current transport: ${currentTransport} (0=UDP, 1=TCP, 2=TLS), target: ${targetTransport} (${targetName}), secure: ${secure}`);
    
    // Update to target transport
    const currentName = currentTransport === 1 ? 'TCP' : currentTransport === 0 ? 'UDP' : currentTransport === 2 ? 'TLS' : 'unknown';
    console.log(`[ensureOutboundTrunkTransport] Updating trunk ${trunkId} to ${targetName} (${targetTransport}) - current: ${currentTransport} (${currentName})`);
    
    // CRITICAL: Use numeric enum (not string) - strings fail to encode
    console.log(`[ensureOutboundTrunkTransport] Calling updateSipOutboundTrunkFields with transport: ${targetTransport}`);
    await sip.updateSipOutboundTrunkFields(trunkId, {
      transport: targetTransport, // Numeric enum: 2 = TLS, 1 = TCP
    });
    console.log(`[ensureOutboundTrunkTransport] Update call succeeded with transport=${targetTransport}`);

    // Wait longer for the change to propagate (LiveKit may need time to apply)
    console.log(`[ensureOutboundTrunkTransport] Waiting 3 seconds for change to propagate...`);
    await new Promise((resolve) => setTimeout(resolve, 3000));

    // Verify the update worked (if we can retrieve trunk info)
    console.log(`[ensureOutboundTrunkTransport] Verifying transport update...`);
    const updated = await getOutboundTrunkInfo(trunkId);
    if (updated) {
      const newTransport = updated?.transport ?? null;
      console.log(`[ensureOutboundTrunkTransport] Verified transport after update: ${newTransport} (0=UDP, 1=TCP, 2=TLS)`);
      if (newTransport !== targetTransport) {
        const errorMsg = `Transport update verification failed: expected ${targetTransport} (${targetName}), got ${newTransport} (${newTransport === 1 ? 'TCP' : newTransport === 0 ? 'UDP' : newTransport === 2 ? 'TLS' : 'unknown'})`;
        console.error(`[ensureOutboundTrunkTransport] WARNING: ${errorMsg}`);
        throw new Error(errorMsg);
      } else {
        console.log(`[ensureOutboundTrunkTransport] ✓ Successfully verified trunk ${trunkId} uses ${targetName} transport (${targetTransport})`);
      }
    } else {
      console.warn(`[ensureOutboundTrunkTransport] Cannot verify transport update - trunk info retrieval not available`);
    }

    return { updated: true, previousTransport: currentTransport, newTransport: targetTransport };
  } catch (e) {
    const errorMsg = `[ensureOutboundTrunkTransport] CRITICAL: Failed to update trunk ${trunkId} to ${targetName}: ${e?.message || e}. Stack: ${e?.stack || "N/A"}`;
    console.error(errorMsg);
    // Throw the error so callers know it failed
    throw new Error(errorMsg);
  }
}

// Backward compatibility alias
async function ensureOutboundTrunkUsesTls(trunkId) {
  return ensureOutboundTrunkTransport(trunkId, true);
}

/**
 * Create a new LiveKit SIP outbound trunk pointing to a Twilio SIP trunk.
 * Uses the subaccount's termination credentials so Caller ID is recognized.
 * Configures transport based on Twilio secure trunking setting (TLS if secure, TCP if not).
 */
async function createOutboundTrunkForWorkspace({ workspaceId, twilioSipDomainName, credUsername, credPassword, numbers, secure }) {
  const sip = sipClient();
  const address = `${twilioSipDomainName}`;
  
  // CRITICAL: LiveKit SDK requires transport as numeric enum, not string
  // - 2 = TLS (when secure trunking is enabled)
  // - 1 = TCP (when secure trunking is disabled)
  // String "tls" fails with: "cannot encode field livekit.SIPOutboundTrunkUpdate.transport to JSON"
  const transport = secure ? 2 : 1; // TLS (2) if secure, TCP (1) if not
  const transportName = secure ? 'TLS' : 'TCP';
  
  const trunk = await sip.createSipOutboundTrunk(
    `RapidCall AI outbound (${workspaceId || "default"})`,
    address,
    numbers || [],
    {
      authUsername: credUsername,
      authPassword: credPassword,
      transport: transport, // Numeric enum: 2 = TLS, 1 = TCP
    }
  );
  console.log(`[createOutboundTrunkForWorkspace] Created trunk ${trunk.sipTrunkId} with ${transportName} transport (${transport}), secure: ${secure}`);
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
  ensureOutboundTrunkTransport,
  getOutboundTrunkInfo,
  deleteOutboundTrunk,
};


