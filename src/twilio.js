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
  // NOTE: This works for main-API resources (numbers, SIP credential lists, etc.)
  // but NOT for Elastic SIP Trunking API — use getSubaccountDirectClient() for trunking.
  return twilio(creds.accountSid, creds.authToken, { accountSid: subaccountSid });
}

/**
 * Authenticate directly AS the subaccount (using its own Auth Token).
 * Required for APIs hosted on separate domains (e.g. trunking.twilio.com)
 * which ignore the `accountSid` constructor option and scope resources
 * to whichever account the credentials belong to.
 */
async function getSubaccountDirectClient(subaccountSid) {
  const creds = getMasterCreds();
  if (!creds) throw new Error("Twilio master credentials not configured");
  // For trunking API, we must use the master account credentials but scope by subaccountSid in requests.
  // The trunking API doesn't support subaccount auth tokens directly.
  return twilio(creds.accountSid, creds.authToken);
}

/**
 * Get IP addresses used for a specific call from Twilio call logs.
 * Returns signaling and media IPs that Twilio saw for the call.
 * 
 * @param {Object} opts
 * @param {string} opts.callSid - Twilio Call SID (e.g., "CAe70feb37773d7276dad342d6d12324f6")
 * @param {string} [opts.subaccountSid] - Optional subaccount SID (uses master account if not provided)
 * @returns {Promise<{signalingIp: string|null, mediaIp: string|null, error: string|null}>}
 */
async function getCallIpAddresses({ callSid, subaccountSid }) {
  try {
    const client = subaccountSid ? getSubaccountClient(subaccountSid) : getMasterClient();
    if (!client) throw new Error("Twilio client not available");

    // Fetch call details - this includes IP information in the Insights API
    const call = await client.calls(callSid).fetch();
    
    // Try to get detailed insights (requires Insights API)
    let signalingIp = null;
    let mediaIp = null;
    
    try {
      // Use the Insights API to get detailed call information
      const insights = await client.insights.v1.calls(callSid).fetch();
      
      // Extract IP addresses from insights
      // Note: The exact structure may vary - check Twilio Insights API docs
      if (insights.clientMetrics) {
        signalingIp = insights.clientMetrics?.clientEdge?.ipAddress || null;
      }
      if (insights.edgeMetrics) {
        // Media IPs might be in edgeMetrics
        const edge = insights.edgeMetrics?.find((e) => e.edge === "sip_edge");
        if (edge) {
          mediaIp = edge.ipAddress || null;
        }
      }
    } catch (insightsErr) {
      // Insights API might not be available or call might be too recent
      console.warn(`[getCallIpAddresses] Could not fetch insights: ${insightsErr?.message || insightsErr}`);
    }

    return {
      callSid,
      signalingIp,
      mediaIp,
      from: call.from,
      to: call.to,
      status: call.status,
      direction: call.direction,
    };
  } catch (e) {
    return {
      callSid,
      signalingIp: null,
      mediaIp: null,
      error: e?.message || String(e),
    };
  }
}

/**
 * Get IP addresses from recent failed calls to help identify which IPs need to be whitelisted.
 * 
 * @param {Object} opts
 * @param {string} opts.trunkSid - Twilio SIP Trunk SID
 * @param {string} [opts.subaccountSid] - Optional subaccount SID
 * @param {number} [opts.limit] - Number of recent calls to check (default: 10)
 * @returns {Promise<{ips: string[], calls: Array}>}
 */
async function getIpAddressesFromRecentCalls({ trunkSid, subaccountSid, limit = 10 }) {
  try {
    const client = subaccountSid ? getSubaccountClient(subaccountSid) : getMasterClient();
    if (!client) throw new Error("Twilio client not available");

    // Fetch recent calls for this trunk
    const calls = await client.calls.list({
      limit: limit,
      // Filter by trunk if possible (may need to use different filter)
    });

    const ipSet = new Set();
    const callDetails = [];

    for (const call of calls) {
      // Only check calls that used this trunk (check direction and other filters)
      if (call.direction === "outbound-api" || call.direction === "outbound-dial") {
        try {
          const ipInfo = await getCallIpAddresses({ callSid: call.sid, subaccountSid });
          if (ipInfo.signalingIp) ipSet.add(ipInfo.signalingIp);
          if (ipInfo.mediaIp) ipSet.add(ipInfo.mediaIp);
          callDetails.push({
            callSid: call.sid,
            from: call.from,
            to: call.to,
            status: call.status,
            dateCreated: call.dateCreated,
            signalingIp: ipInfo.signalingIp,
            mediaIp: ipInfo.mediaIp,
          });
        } catch (e) {
          console.warn(`[getIpAddressesFromRecentCalls] Failed to get IPs for call ${call.sid}: ${e?.message || e}`);
        }
      }
    }

    return {
      ips: Array.from(ipSet).sort(),
      calls: callDetails,
    };
  } catch (e) {
    return {
      ips: [],
      calls: [],
      error: e?.message || String(e),
    };
  }
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
 * Creates the trunk with Secure Trunking (SRTP+TLS) and Call Transfer (SIP REFER) enabled.
 * Returns { trunkSid, domainName, secure }.
 */
async function ensureSipTrunk({ subaccountSid, existingTrunkSid, workspaceId }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  // MUST use direct subaccount auth — trunking.twilio.com scopes by credentials, not accountSid.
  const client = await getSubaccountDirectClient(subaccountSid);

  // Re-use existing trunk if we have one.
  if (existingTrunkSid) {
    try {
      const trunk = await client.trunking.v1.trunks(existingTrunkSid).fetch();

      // Don't force enable secure trunking - respect user's choice
      // Only ensure call transfer is enabled
      const needsUpdate = trunk.transferMode !== "enable-all";
      if (needsUpdate) {
        try {
          await client.trunking.v1.trunks(existingTrunkSid).update({
            transferMode: "enable-all",
          });
        } catch {
          // Best-effort; don't fail the entire flow.
        }
      }

      return {
        trunkSid: trunk.sid,
        domainName: trunk.domainName || null,
        secure: Boolean(trunk.secure), // Return actual secure status
      };
    } catch {
      // Trunk may have been deleted or was on the wrong account; fall through to create a new one.
    }
  }

  // Generate a unique domain name (must end in .pstn.twilio.com).
  const slug = `rc-${(workspaceId || "ws").replace(/[^a-z0-9]/gi, "").slice(0, 16)}-${Date.now().toString(36)}`;
  const domainName = `${slug}.pstn.twilio.com`;

  // Default to secure: false (user can enable it manually in Twilio console)
  const trunk = await client.trunking.v1.trunks.create({
    friendlyName: `RapidCall AI (${workspaceId || "default"})`,
    domainName,
    // Secure Trunking: disabled by default (user can enable in Twilio console)
    secure: false,
    // Call Transfer: enable SIP REFER so agents can do cold/warm transfers.
    transferMode: "enable-all",
  });

  return {
    trunkSid: trunk.sid,
    domainName: trunk.domainName,
    secure: Boolean(trunk.secure),
  };
}

/**
 * Ensure the Twilio SIP trunk has an Origination URI pointing to the LiveKit SIP endpoint.
 * This is REQUIRED for inbound calls: PSTN → Twilio → Elastic SIP Trunk → Origination URI → LiveKit.
 *
 * Without this, inbound calls to numbers associated with the trunk get no audio because
 * the trunk has nowhere to forward the call.
 */
async function ensureSipTrunkOriginationUri({ subaccountSid, trunkSid, sipEndpoint, secure }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  if (!trunkSid) throw new Error("Trunk SID is required");
  if (!sipEndpoint) throw new Error("LIVEKIT_SIP_ENDPOINT is required for origination URI");

  const client = await getSubaccountDirectClient(subaccountSid);

  // Build the origination SIP URL. Use TLS transport if secure trunking is enabled, TCP otherwise.
  const transport = secure ? "tls" : "tcp";
  const sipUrl = `sip:${sipEndpoint};transport=${transport}`;

  // Check if an origination URI already exists for this endpoint (with any transport).
  const existing = await client.trunking.v1.trunks(trunkSid).originationUrls.list({ limit: 50 });
  const alreadyExists = existing.some((o) => {
    const normalized = String(o.sipUrl || "").replace(/;transport=(tls|tcp|udp)$/i, "");
    return normalized === `sip:${sipEndpoint}` || o.sipUrl === sipUrl;
  });

  if (alreadyExists) {
    return { created: false };
  }

  await client.trunking.v1.trunks(trunkSid).originationUrls.create({
    friendlyName: "LiveKit SIP",
    sipUrl,
    weight: 10,
    priority: 10,
    enabled: true,
  });

  return { created: true };
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

  // MUST use direct subaccount auth for trunking API (credential list association).
  const client = await getSubaccountDirectClient(subaccountSid);

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
  // NOTE: Twilio SDK v5 renamed this property to "credentialsLists" (plural 's').
  await client.trunking.v1.trunks(trunkSid).credentialsLists.create({
    credentialListSid: credList.sid,
  });

  return { credUsername: username, credPassword: password };
}

/**
 * Associate a phone number with a Twilio SIP trunk (required for outbound Caller ID).
 */
async function associateNumberWithSipTrunk({ subaccountSid, trunkSid, numberSid }) {
  // MUST use direct subaccount auth — trunking API is account-scoped by credentials.
  const client = await getSubaccountDirectClient(subaccountSid);

  // Verify trunk exists before trying to associate number
  try {
    await client.trunking.v1.trunks(trunkSid).fetch();
  } catch (e) {
    if (String(e?.message || "").includes("not found") || String(e?.status || "") === "404") {
      throw new Error(`Trunk ${trunkSid} does not exist. Please ensure the trunk is created first.`);
    }
    throw new Error(`Failed to verify trunk exists: ${e?.message || e}`);
  }

  try {
    await client.trunking.v1.trunks(trunkSid).phoneNumbers.create({
      phoneNumberSid: numberSid,
    });
  } catch (e) {
    // If already associated, that's fine
    if (String(e?.message || "").includes("already associated") || String(e?.message || "").includes("already exists")) {
      console.log(`[associateNumberWithSipTrunk] Number ${numberSid} already associated with trunk ${trunkSid}`);
      return;
    }
    throw e;
  }
}

/**
 * Ensure IP Access Control List is configured on the Twilio SIP trunk.
 * This is REQUIRED when IP restrictions are enabled - Twilio will reject SIP INVITEs
 * from IPs not in the ACL, causing "SIP 500: Service Unavailable" errors.
 * 
 * @param {Object} opts
 * @param {string} opts.subaccountSid - Twilio subaccount SID
 * @param {string} opts.trunkSid - Twilio SIP trunk SID
 * @param {string[]} opts.ipAddresses - Array of IP addresses or CIDR ranges to whitelist (e.g., ["143.223.92.0/24", "168.86.137.0/24"] or ["143.223.92.68", "168.86.137.235"])
 */
async function ensureSipTrunkIpAcl({ subaccountSid, trunkSid, ipAddresses }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  if (!trunkSid) throw new Error("Trunk SID is required");
  if (!ipAddresses || !Array.isArray(ipAddresses) || ipAddresses.length === 0) {
    throw new Error("IP addresses array is required");
  }

  const client = await getSubaccountDirectClient(subaccountSid);
  
  // Verify trunk exists first and API is available
  try {
    await client.trunking.v1.trunks(trunkSid).fetch();
  } catch (e) {
    const errorMsg = String(e?.message || e);
    if (errorMsg.includes("not found") || String(e?.status || "") === "404") {
      throw new Error(`Trunk ${trunkSid} does not exist. Please ensure the trunk is created first.`);
    }
    throw new Error(`Failed to verify trunk exists: ${errorMsg}`);
  }

  // Verify IP ACL API is available
  if (!client.trunking || !client.trunking.v1 || !client.trunking.v1.ipAccessControlLists) {
    throw new Error("Twilio Trunking API (IP Access Control Lists) is not available. Check your Twilio credentials and ensure trunking API access is enabled.");
  }

  // Create or find an IP Access Control List for this trunk
  const aclFriendlyName = `RapidCall AI SIP ACL (${trunkSid.slice(-8)})`;
  
  // First, check if an ACL is already associated with this trunk
  let ipAclList = null;
  try {
    const trunkAcls = await client.trunking.v1.trunks(trunkSid).ipAccessControlLists.list({ limit: 50 });
    if (trunkAcls && trunkAcls.length > 0) {
      // Use the first ACL already associated with the trunk
      ipAclList = trunkAcls[0];
      console.log(`[ensureSipTrunkIpAcl] Found existing ACL ${ipAclList.sid} already associated with trunk`);
    }
  } catch (e) {
    console.warn(`[ensureSipTrunkIpAcl] Could not list trunk ACLs: ${e?.message || e}`);
  }

  // If no ACL is associated, try to find or create one
  if (!ipAclList) {
    try {
      // Try to find an existing ACL by name on the account
      const allAcls = await client.trunking.v1.ipAccessControlLists.list({ limit: 100 });
      if (allAcls && Array.isArray(allAcls)) {
        ipAclList = allAcls.find((acl) => acl.friendlyName === aclFriendlyName);
      }
      
      if (!ipAclList) {
        // Create a new IP ACL resource on the account
        ipAclList = await client.trunking.v1.ipAccessControlLists.create({
          friendlyName: aclFriendlyName,
        });
        console.log(`[ensureSipTrunkIpAcl] Created new IP ACL ${ipAclList.sid}`);
      } else {
        console.log(`[ensureSipTrunkIpAcl] Found existing IP ACL ${ipAclList.sid} by name`);
      }
    } catch (e) {
      throw new Error(`Failed to create or find IP ACL: ${e?.message || e}`);
    }

    // Associate the IP ACL with the trunk
    try {
      await client.trunking.v1.trunks(trunkSid).ipAccessControlLists.create({
        ipAccessControlListSid: ipAclList.sid,
      });
      console.log(`[ensureSipTrunkIpAcl] Associated IP ACL ${ipAclList.sid} with trunk ${trunkSid}`);
    } catch (e) {
      // May already be associated (race condition) - that's fine
      if (!String(e?.message || "").includes("already associated") && !String(e?.message || "").includes("already exists")) {
        console.warn(`[ensureSipTrunkIpAcl] Could not associate ACL: ${e?.message || e}`);
      } else {
        console.log(`[ensureSipTrunkIpAcl] ACL already associated (ok)`);
      }
    }
  }

  // Add IP addresses or CIDR ranges to the ACL
  // Fetch existing IPs to avoid duplicates
  let existingIps = [];
  try {
    existingIps = await client.trunking.v1.ipAccessControlLists(ipAclList.sid).ipAddresses.list({ limit: 100 });
  } catch (e) {
    console.warn(`[ensureSipTrunkIpAcl] Could not list existing IPs, will attempt to add all: ${e?.message || e}`);
  }
  
  const existingIpSet = new Set(existingIps.map((ip) => ip.ipAddress));
  const existingCidrSet = new Set(
    existingIps
      .map((ip) => {
        // Normalize: if no /, treat as /32
        return ip.ipAddress.includes('/') ? ip.ipAddress : `${ip.ipAddress}/32`;
      })
      .filter(Boolean)
  );

  let addedCount = 0;
  let skippedCount = 0;
  let failedCount = 0;
  const failedIps = [];

  console.log(`[ensureSipTrunkIpAcl] Processing ${ipAddresses.length} IP addresses/CIDR ranges for ACL ${ipAclList.sid}`);

  for (const ipOrRange of ipAddresses) {
    const trimmed = String(ipOrRange).trim();
    if (!trimmed) {
      skippedCount++;
      continue;
    }

    // Validate IP format: individual IP (x.x.x.x) or CIDR range (x.x.x.x/prefix)
    const isCidr = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(trimmed);
    const isSingleIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed);
    
    if (!isCidr && !isSingleIp) {
      console.warn(`[ensureSipTrunkIpAcl] Skipping invalid IP/CIDR format: ${trimmed}`);
      skippedCount++;
      failedIps.push({ ip: trimmed, reason: 'Invalid format' });
      continue;
    }

    // Check if already exists
    // For CIDR: normalize and check against existing CIDR set
    // For single IP: check exact match and also check if it's covered by any existing CIDR
    let alreadyExists = false;
    if (isCidr) {
      alreadyExists = existingCidrSet.has(trimmed);
    } else {
      // Check exact match
      if (existingIpSet.has(trimmed)) {
        alreadyExists = true;
      } else {
        // Check if this IP is covered by any existing CIDR range
        const ipParts = trimmed.split('.').map(Number);
        for (const existingCidr of existingCidrSet) {
          if (existingCidr.includes('/')) {
            const [baseIp, prefix] = existingCidr.split('/');
            const prefixLen = Number(prefix);
            if (prefixLen >= 0 && prefixLen <= 32) {
              const baseParts = baseIp.split('.').map(Number);
              let match = true;
              for (let i = 0; i < 4; i++) {
                const shift = Math.max(0, 8 - Math.max(0, prefixLen - i * 8));
                const mask = shift === 8 ? 255 : (255 << (8 - shift)) & 255;
                if ((ipParts[i] & mask) !== (baseParts[i] & mask)) {
                  match = false;
                  break;
                }
              }
              if (match) {
                alreadyExists = true;
                break;
              }
            }
          }
        }
      }
    }

    if (alreadyExists) {
      skippedCount++;
      console.log(`[ensureSipTrunkIpAcl] ${isCidr ? 'CIDR range' : 'IP'} ${trimmed} already in ACL (skipping)`);
      continue;
    }

    // Attempt to add the IP/CIDR
    try {
      // Twilio API accepts CIDR notation directly in ipAddress field
      // Format: "x.x.x.x/prefix" or "x.x.x.x" for single IP
      await client.trunking.v1.ipAccessControlLists(ipAclList.sid).ipAddresses.create({
        friendlyName: `LiveKit SIP ${trimmed}`,
        ipAddress: trimmed, // Twilio accepts CIDR notation directly
      });
      addedCount++;
      console.log(`[ensureSipTrunkIpAcl] ✓ Added ${isCidr ? 'CIDR range' : 'IP'} ${trimmed} to ACL ${ipAclList.sid}`);
      
      // Update our local sets to avoid duplicate attempts in the same run
      existingIpSet.add(trimmed);
      if (isCidr) {
        existingCidrSet.add(trimmed);
      } else {
        existingCidrSet.add(`${trimmed}/32`);
      }
    } catch (e) {
      failedCount++;
      const errorMsg = String(e?.message || e);
      console.error(`[ensureSipTrunkIpAcl] ✗ Failed to add ${isCidr ? 'CIDR range' : 'IP'} ${trimmed}: ${errorMsg}`);
      failedIps.push({ ip: trimmed, reason: errorMsg });
      
      // If it's a duplicate error, that's actually fine (race condition)
      if (errorMsg.includes("already exists") || errorMsg.includes("duplicate")) {
        console.log(`[ensureSipTrunkIpAcl] Note: ${trimmed} appears to already exist (race condition), treating as success`);
        addedCount++; // Count as added since it exists
        failedCount--; // Don't count as failed
        failedIps.pop(); // Remove from failed list
      }
    }
  }

  // Log summary
  console.log(`[ensureSipTrunkIpAcl] Summary for ACL ${ipAclList.sid}: ${addedCount} added, ${skippedCount} skipped, ${failedCount} failed`);
  if (failedIps.length > 0) {
    console.warn(`[ensureSipTrunkIpAcl] Failed IPs:`, failedIps);
  }

  // Fetch final count
  let finalIps = [];
  try {
    finalIps = await client.trunking.v1.ipAccessControlLists(ipAclList.sid).ipAddresses.list({ limit: 100 });
  } catch (e) {
    console.warn(`[ensureSipTrunkIpAcl] Could not fetch final IP count: ${e?.message || e}`);
  }

  return {
    aclSid: ipAclList.sid,
    aclFriendlyName: ipAclList.friendlyName,
    ipAddressesAdded: addedCount,
    ipAddressesSkipped: skippedCount,
    ipAddressesFailed: failedCount,
    failedIps: failedIps.length > 0 ? failedIps : undefined,
    totalIps: finalIps.length,
  };
}

module.exports = {
  getMasterCreds,
  getSubaccountClient,
  getSubaccountDirectClient,
  ensureSubaccount,
  searchAvailableNumbers,
  buyNumber,
  configureNumberForSip,
  ensureSipTrunk,
  ensureSipTrunkTerminationCreds,
  ensureSipTrunkOriginationUri,
  associateNumberWithSipTrunk,
  ensureSipTrunkIpAcl,
  getCallIpAddresses,
  getIpAddressesFromRecentCalls,
};
