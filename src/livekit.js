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
 * Check if an error indicates the trunk doesn't exist in LiveKit.
 * @param {Error|string} error - The error to check
 * @returns {boolean} - True if the error indicates the trunk doesn't exist
 */
function isTrunkNotFoundError(error) {
  const errorMsg = String(error?.message || error || "").toLowerCase();
  return (
    errorMsg.includes("object cannot be found") ||
    errorMsg.includes("not found") ||
    errorMsg.includes("does not exist") ||
    errorMsg.includes("twirp error") && errorMsg.includes("not found") ||
    errorMsg.includes("404") ||
    errorMsg.includes("no such")
  );
}

/**
 * If LiveKit returns "Conflicting inbound SIP Trunks: ... and \"ST_xxx\" ...", the number
 * is already on an existing trunk. Parse and return that trunk ID so we can use it instead of creating.
 * @param {Error|string} error - The error from createSipInboundTrunk
 * @returns {string|null} - The existing trunk ID (e.g. ST_fcSgRLMVYMDQ) or null
 */
function parseConflictingInboundTrunkId(error) {
  const msg = String(error?.message || error || "");
  const match = msg.match(/ and "(ST_[A-Za-z0-9]+)"/);
  return match ? match[1] : null;
}

/**
 * Get the current state of a LiveKit SIP outbound trunk.
 * Note: This may not be available in all SDK versions - falls back to listing all trunks.
 * Throws a specific error if the trunk doesn't exist (so callers can recreate it).
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
      // Trunk not found in list - it doesn't exist
      const error = new Error(`Trunk ${trunkId} not found in LiveKit`);
      error.code = "TRUNK_NOT_FOUND";
      throw error;
    }
    // If we can't get the trunk info, return null (caller should handle)
    console.warn(`[getOutboundTrunkInfo] Cannot retrieve trunk ${trunkId} info - SDK method may not be available`);
    return null;
  } catch (e) {
    // Check if this is a "trunk not found" error
    if (isTrunkNotFoundError(e)) {
      const error = new Error(`LiveKit outbound trunk ${trunkId} does not exist: ${e?.message || e}`);
      error.code = "TRUNK_NOT_FOUND";
      error.originalError = e;
      console.warn(`[getOutboundTrunkInfo] Trunk ${trunkId} not found in LiveKit: ${e?.message || e}`);
      throw error;
    }
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
 * Ensure an existing LiveKit SIP outbound trunk address matches the Twilio termination URI.
 * If the address doesn't match, updates it to match Twilio's domain name.
 * If the trunk doesn't exist, throws an error with code "TRUNK_NOT_FOUND" so callers can recreate it.
 * 
 * @param {string} trunkId - LiveKit outbound trunk ID
 * @param {string} twilioTerminationUri - Twilio termination URI (domain name) that should match
 * @returns {Promise<{updated: boolean, previousAddress?: string, newAddress?: string}>}
 * @throws {Error} If trunk doesn't exist (error.code === "TRUNK_NOT_FOUND")
 */
async function ensureOutboundTrunkAddress(trunkId, twilioTerminationUri) {
  const sip = sipClient();
  
  if (!twilioTerminationUri) {
    console.warn(`[ensureOutboundTrunkAddress] No Twilio termination URI provided for trunk ${trunkId}`);
    return { updated: false };
  }
  
  try {
    const trunkInfo = await getOutboundTrunkInfo(trunkId);
    if (!trunkInfo) {
      console.warn(`[ensureOutboundTrunkAddress] Cannot retrieve trunk ${trunkId} info - cannot verify address`);
      return { updated: false };
    }
    
    const currentAddress = trunkInfo.outboundAddress || trunkInfo.address || null;
    const normalizedTwilioUri = String(twilioTerminationUri).trim();
    
    console.log(`[ensureOutboundTrunkAddress] Trunk ${trunkId} current address: ${currentAddress}, Twilio termination URI: ${normalizedTwilioUri}`);
    
    if (currentAddress === normalizedTwilioUri) {
      console.log(`[ensureOutboundTrunkAddress] ✓ Trunk ${trunkId} address already matches Twilio termination URI`);
      return { updated: false, previousAddress: currentAddress, newAddress: normalizedTwilioUri };
    }
    
    // Address doesn't match - update it
    // Note: LiveKit SDK uses "address" field (same as createSipOutboundTrunk)
    console.log(`[ensureOutboundTrunkAddress] Updating trunk ${trunkId} address from "${currentAddress}" to "${normalizedTwilioUri}"`);
    try {
      await sip.updateSipOutboundTrunkFields(trunkId, {
        address: normalizedTwilioUri, // Use "address" field (same as createSipOutboundTrunk)
      });
      console.log(`[ensureOutboundTrunkAddress] ✓ Updated trunk ${trunkId} address to "${normalizedTwilioUri}"`);
    } catch (e) {
      // If update fails (e.g., field not supported), we'll need to recreate the trunk
      console.warn(`[ensureOutboundTrunkAddress] Failed to update address via updateSipOutboundTrunkFields: ${e?.message || e}. Address updates may require recreating the trunk.`);
      throw new Error(`Cannot update trunk address - may need to recreate trunk: ${e?.message || e}`);
    }
    
    // Wait for change to propagate
    await new Promise((resolve) => setTimeout(resolve, 2000));
    
    // Verify the update
    const updatedInfo = await getOutboundTrunkInfo(trunkId);
    const verifiedAddress = updatedInfo?.outboundAddress || updatedInfo?.address || null;
    if (verifiedAddress === normalizedTwilioUri) {
      console.log(`[ensureOutboundTrunkAddress] ✓ Verified trunk ${trunkId} address matches Twilio termination URI`);
      return { updated: true, previousAddress: currentAddress, newAddress: normalizedTwilioUri };
    } else {
      console.warn(`[ensureOutboundTrunkAddress] WARNING: Address update verification failed. Expected "${normalizedTwilioUri}", got "${verifiedAddress}"`);
      return { updated: true, previousAddress: currentAddress, newAddress: verifiedAddress };
    }
  } catch (e) {
    console.error(`[ensureOutboundTrunkAddress] Failed to ensure trunk ${trunkId} address matches Twilio termination URI: ${e?.message || e}`);
    throw new Error(`Failed to ensure trunk address matches Twilio termination URI: ${e?.message || e}`);
  }
}

/**
 * Ensure an existing LiveKit SIP outbound trunk uses the correct transport.
 * Uses TLS (3) when secure trunking is enabled, TCP (2) when disabled.
 * 
 * CRITICAL: LiveKit SDK requires transport as numeric enum:
 * LiveKit SIPTransport protobuf enum:
 *   0 = SIP_TRANSPORT_AUTO
 *   1 = SIP_TRANSPORT_UDP
 *   2 = SIP_TRANSPORT_TCP
 *   3 = SIP_TRANSPORT_TLS
 * 
 * String values fail with encoding errors.
 * 
 * @throws {Error} If trunk doesn't exist (error.code === "TRUNK_NOT_FOUND")
 */
async function ensureOutboundTrunkTransport(trunkId, secure) {
  const sip = sipClient();
  const targetTransport = secure ? 3 : 2; // TLS (3) if secure, TCP (2) if not
  const targetName = secure ? 'TLS' : 'TCP';
  
  try {
    // First, check current state (if possible)
    const current = await getOutboundTrunkInfo(trunkId);
    // If getOutboundTrunkInfo throws TRUNK_NOT_FOUND, it will propagate up
    const currentTransport = current?.transport ?? null;
    
    // Log what we found
    const currentName = currentTransport === 3 ? 'TLS' : currentTransport === 2 ? 'TCP' : currentTransport === 1 ? 'UDP' : currentTransport === 0 ? 'AUTO' : 'unknown';
    console.log(`[ensureOutboundTrunkTransport] Trunk ${trunkId} current transport: ${currentTransport} (${currentName}), target: ${targetTransport} (${targetName}), secure: ${secure}`);
    
    // Skip update if transport already matches — avoids unnecessary 3s delay on every call
    if (currentTransport === targetTransport) {
      console.log(`[ensureOutboundTrunkTransport] ✓ Trunk ${trunkId} already uses ${targetName} transport (${targetTransport}), no update needed`);
      return { updated: false, previousTransport: currentTransport, newTransport: targetTransport };
    }
    
    // Update to target transport
    console.log(`[ensureOutboundTrunkTransport] Updating trunk ${trunkId} from ${currentName} (${currentTransport}) to ${targetName} (${targetTransport})`);
    
    // CRITICAL: Use numeric enum (not string) - strings fail to encode
    await sip.updateSipOutboundTrunkFields(trunkId, {
      transport: targetTransport, // Numeric enum: 3 = TLS, 2 = TCP
    });
    console.log(`[ensureOutboundTrunkTransport] Update call succeeded with transport=${targetTransport}`);

    // Wait for the change to propagate (LiveKit may need time to apply)
    console.log(`[ensureOutboundTrunkTransport] Waiting 3 seconds for change to propagate...`);
    await new Promise((resolve) => setTimeout(resolve, 3000));

    // Verify the update worked
    console.log(`[ensureOutboundTrunkTransport] Verifying transport update...`);
    const updated = await getOutboundTrunkInfo(trunkId);
    if (updated) {
      const newTransport = updated?.transport ?? null;
      console.log(`[ensureOutboundTrunkTransport] Verified transport after update: ${newTransport} (0=AUTO, 1=UDP, 2=TCP, 3=TLS)`);
      if (newTransport !== targetTransport) {
        const errorMsg = `Transport update verification failed: expected ${targetTransport} (${targetName}), got ${newTransport} (${newTransport === 3 ? 'TLS' : newTransport === 2 ? 'TCP' : newTransport === 1 ? 'UDP' : newTransport === 0 ? 'AUTO' : 'unknown'})`;
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
 * Create a new LiveKit SIP inbound trunk for a workspace.
 * Inbound trunks receive calls from Twilio and route them to LiveKit rooms.
 */
async function createInboundTrunkForWorkspace({ workspaceId, numbers }) {
  const sip = sipClient();
  
  // Create inbound trunk - no address needed (Twilio calls LiveKit, not the other way around)
  // Inbound trunks are identified by the phone numbers they accept
  const trunk = await sip.createSipInboundTrunk(
    `RapidCall AI inbound (${workspaceId || "default"})`,
    numbers || []
  );
  console.log(`[createInboundTrunkForWorkspace] Created inbound trunk ${trunk.sipTrunkId} for workspace ${workspaceId}`);
  return { trunkId: trunk.sipTrunkId };
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
  // LiveKit SIPTransport protobuf enum:
  //   0 = SIP_TRANSPORT_AUTO
  //   1 = SIP_TRANSPORT_UDP
  //   2 = SIP_TRANSPORT_TCP
  //   3 = SIP_TRANSPORT_TLS
  // String "tls" fails with: "cannot encode field livekit.SIPOutboundTrunkUpdate.transport to JSON"
  const transport = secure ? 3 : 2; // TLS (3) if secure, TCP (2) if not
  const transportName = secure ? 'TLS' : 'TCP';
  
  const trunk = await sip.createSipOutboundTrunk(
    `RapidCall AI outbound (${workspaceId || "default"})`,
    address,
    numbers || [],
    {
      authUsername: credUsername,
      authPassword: credPassword,
      transport: transport, // Numeric enum: 3 = TLS, 2 = TCP
    }
  );
  console.log(`[createOutboundTrunkForWorkspace] Created trunk ${trunk.sipTrunkId} with ${transportName} transport (${transport}), secure: ${secure}`);
  return { trunkId: trunk.sipTrunkId };
}

/**
 * Create a LiveKit SIP outbound trunk for an imported number (user's SIP carrier).
 * address = termination URI (host:port or domain) where we send outbound SIP.
 * transport: 'tcp' | 'udp' | 'tls' (default 'tcp').
 */
async function createOutboundTrunkForSipImport({ name, address, numbers, authUsername, authPassword, transport }) {
  const sip = sipClient();
  const transportLower = String(transport || "tcp").toLowerCase();
  const transportMap = { udp: 1, tcp: 2, tls: 3 };
  const transportEnum = transportMap[transportLower] ?? 2;

  const trunk = await sip.createSipOutboundTrunk(
    name || "Imported SIP",
    address,
    numbers || [],
    {
      authUsername: authUsername || undefined,
      authPassword: authPassword || undefined,
      transport: transportEnum,
    }
  );
  console.log(`[createOutboundTrunkForSipImport] Created trunk ${trunk.sipTrunkId} for ${address} transport=${transportLower}`);
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
  createInboundTrunkForWorkspace,
  createOutboundTrunkForWorkspace,
  createOutboundTrunkForSipImport,
  ensureOutboundTrunkUsesTls,
  ensureOutboundTrunkTransport,
  ensureOutboundTrunkAddress,
  getOutboundTrunkInfo,
  deleteOutboundTrunk,
  isTrunkNotFoundError,
  parseConflictingInboundTrunkId,
};


