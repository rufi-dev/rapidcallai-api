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
 * 
 * For Trunking API, we MUST use the subaccount's own credentials, not master account credentials.
 * Trunks created with master account credentials will be on the master account, not the subaccount.
 */
async function getSubaccountDirectClient(subaccountSid) {
  const masterCreds = getMasterCreds();
  if (!masterCreds) throw new Error("Twilio master credentials not configured");
  
  // Fetch the subaccount to get its auth token
  const masterClient = twilio(masterCreds.accountSid, masterCreds.authToken);
  try {
    const subaccount = await masterClient.api.accounts(subaccountSid).fetch();
    if (!subaccount || !subaccount.authToken) {
      throw new Error(`Subaccount ${subaccountSid} auth token not available`);
    }
    console.log(`[getSubaccountDirectClient] Using subaccount ${subaccountSid} credentials for Trunking API`);
    // Use subaccount's own credentials for trunking API
    // This ensures trunks are created on the subaccount, not the master account
    return twilio(subaccountSid, subaccount.authToken);
  } catch (e) {
    const errorMsg = String(e?.message || e);
    const status = String(e?.status || "");
    console.error(`[getSubaccountDirectClient] Failed to fetch subaccount credentials: ${errorMsg} (status: ${status})`);
    throw new Error(`Failed to get subaccount credentials for ${subaccountSid}: ${errorMsg}`);
  }
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
  const client = getMasterClient();
  if (!client) throw new Error("Twilio is not configured (missing TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN)");

  // If we have an existing subaccount, verify it's accessible from the current master account.
  // This handles the case where the user changed TWILIO_ACCOUNT_SID to a new master account.
  if (existingSid) {
    try {
      await client.api.accounts(existingSid).fetch();
      return { sid: existingSid, created: false };
    } catch (e) {
      console.warn(`[ensureSubaccount] Existing subaccount ${existingSid} is not accessible from current master account (${e?.message || e}). Will create a new one — old trunk/credential references will be stale.`);
      // Fall through to create a new subaccount under the current master
    }
  }

  const acct = await client.api.accounts.create({ friendlyName: friendlyName || "rapidcallai workspace" });
  console.log(`[ensureSubaccount] Created new subaccount ${acct.sid} under master ${getMasterCreds()?.accountSid}`);
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
  
  console.log(`[ensureSipTrunk] Starting trunk provisioning for workspace ${workspaceId}, subaccount ${subaccountSid}, existingTrunkSid: ${existingTrunkSid || 'none'}`);
  
  // MUST use direct subaccount auth — trunking.twilio.com scopes by credentials, not accountSid.
  let client;
  try {
    client = await getSubaccountDirectClient(subaccountSid);
    if (!client) {
      throw new Error("Failed to create Twilio client for subaccount");
    }
    console.log(`[ensureSipTrunk] Twilio client created successfully`);
  } catch (e) {
    const errorMsg = String(e?.message || e);
    console.error(`[ensureSipTrunk] Failed to create Twilio client: ${errorMsg}`);
    throw new Error(`Failed to initialize Twilio client: ${errorMsg}`);
  }

  // Verify trunking API is available
  if (!client.trunking || !client.trunking.v1 || !client.trunking.v1.trunks) {
    console.error(`[ensureSipTrunk] Twilio Trunking API is not available. client.trunking: ${!!client.trunking}, client.trunking.v1: ${!!client.trunking?.v1}, client.trunking.v1.trunks: ${!!client.trunking?.v1?.trunks}`);
    throw new Error("Twilio Trunking API is not available. Check your Twilio credentials and ensure trunking API access is enabled.");
  }

  // Re-use existing trunk if we have one.
  if (existingTrunkSid) {
    console.log(`[ensureSipTrunk] Attempting to fetch existing trunk ${existingTrunkSid}`);
    try {
      const trunk = await client.trunking.v1.trunks(existingTrunkSid).fetch();
      
      // CRITICAL: Always use the domain name from Twilio's API response, not from database
      const twilioDomainName = trunk.domainName || null;
      if (!twilioDomainName) {
        console.warn(`[ensureSipTrunk] WARNING: Trunk ${trunk.sid} has no domainName in Twilio response. This may cause issues.`);
      }
      
      console.log(`[ensureSipTrunk] ✓ Found existing trunk ${trunk.sid}, domain: ${twilioDomainName}, secure: ${trunk.secure}`);
      console.log(`[ensureSipTrunk] Using domain name from Twilio API: ${twilioDomainName}`);

      // IMPORTANT: Twilio "secure" flag controls SRTP (media encryption), NOT TLS signaling.
      // LiveKit Cloud does NOT support SRTP, so we MUST set secure=false on Twilio.
      // TLS signaling transport is configured separately on the LiveKit outbound trunk (transport=3).
      const needsUpdate = trunk.secure || trunk.transferMode !== "enable-all";
      if (needsUpdate) {
        try {
          await client.trunking.v1.trunks(existingTrunkSid).update({
            secure: false, // Disable SRTP requirement — LiveKit doesn't support SRTP
            transferMode: "enable-all",
          });
          console.log(`[ensureSipTrunk] ✓ Updated trunk ${trunk.sid}: secure=false (no SRTP), transferMode=enable-all`);
        } catch (e) {
          console.warn(`[ensureSipTrunk] Failed to update trunk settings (best-effort): ${e?.message || e}`);
        }
      }

      return {
        trunkSid: trunk.sid,
        domainName: twilioDomainName, // Always use Twilio's domain name
        secure: false, // No SRTP — LiveKit uses TLS signaling (transport=3) separately
      };
    } catch (e) {
      const errorMsg = String(e?.message || e);
      const status = String(e?.status || "");
      console.warn(`[ensureSipTrunk] Existing trunk ${existingTrunkSid} not found or inaccessible (${status}): ${errorMsg}. Will create a new one.`);
      // Trunk may have been deleted or was on the wrong account; fall through to create a new one.
    }
  }

  // Generate a unique domain name (must end in .pstn.twilio.com).
  const slug = `rc-${(workspaceId || "ws").replace(/[^a-z0-9]/gi, "").slice(0, 16)}-${Date.now().toString(36)}`;
  const domainName = `${slug}.pstn.twilio.com`;

  console.log(`[ensureSipTrunk] Creating new trunk with domain: ${domainName}`);

  // IMPORTANT: Twilio "secure" flag controls SRTP (media encryption).
  // LiveKit Cloud does NOT support SRTP, so we MUST set secure=false.
  // TLS signaling is handled separately via LiveKit outbound trunk transport=3.
  let trunk;
  try {
    trunk = await client.trunking.v1.trunks.create({
      friendlyName: `RapidCall AI (${workspaceId || "default"})`,
      domainName,
      // Secure Trunking: DISABLED — LiveKit doesn't support SRTP media encryption
      // TLS transport for SIP signaling is configured on the LiveKit side (transport=3)
      secure: false,
      // Call Transfer: enable SIP REFER so agents can do cold/warm transfers.
      transferMode: "enable-all",
    });
    console.log(`[ensureSipTrunk] ✓ Successfully created trunk ${trunk.sid}, domain: ${trunk.domainName}, secure: ${trunk.secure}`);
  } catch (e) {
    const errorMsg = String(e?.message || e);
    const status = String(e?.status || "");
    const code = String(e?.code || "");
    console.error(`[ensureSipTrunk] ✗ Failed to create trunk: ${errorMsg} (status: ${status}, code: ${code})`);
    
    // Provide more specific error messages
    if (errorMsg.includes("not authorized") || status === "401" || status === "403") {
      throw new Error(`Twilio API authorization failed. Check your TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN credentials. Error: ${errorMsg}`);
    }
    if (errorMsg.includes("not found") || status === "404") {
      throw new Error(`Twilio subaccount ${subaccountSid} not found. Verify the subaccount exists and credentials are correct. Error: ${errorMsg}`);
    }
    if (errorMsg.includes("domain") || errorMsg.includes("Domain")) {
      throw new Error(`Invalid domain name for trunk: ${domainName}. Error: ${errorMsg}`);
    }
    
    throw new Error(`Failed to create Twilio SIP trunk: ${errorMsg} (status: ${status}, code: ${code})`);
  }

  if (!trunk || !trunk.sid) {
    console.error(`[ensureSipTrunk] ✗ Trunk creation returned invalid response:`, trunk);
    throw new Error("Trunk creation succeeded but returned invalid trunk SID");
  }

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

  // Check existing origination URIs for this endpoint.
  const existing = await client.trunking.v1.trunks(trunkSid).originationUrls.list({ limit: 50 });
  
  // Find any existing URI for this SIP endpoint (regardless of transport)
  const matchingUri = existing.find((o) => {
    const normalized = String(o.sipUrl || "").replace(/;transport=(tls|tcp|udp)$/i, "");
    return normalized === `sip:${sipEndpoint}`;
  });

  if (matchingUri) {
    // Check if transport matches
    if (matchingUri.sipUrl === sipUrl) {
      console.log(`[ensureSipTrunkOriginationUri] ✓ Origination URI already correct: ${sipUrl}`);
      return { created: false };
    }
    // Transport mismatch — update the existing URI to use the correct transport
    console.log(`[ensureSipTrunkOriginationUri] Updating origination URI from ${matchingUri.sipUrl} to ${sipUrl}`);
    try {
      await client.trunking.v1.trunks(trunkSid).originationUrls(matchingUri.sid).update({
        sipUrl,
        friendlyName: "LiveKit SIP",
      });
      console.log(`[ensureSipTrunkOriginationUri] ✓ Updated origination URI to ${sipUrl}`);
      return { created: false, updated: true };
    } catch (e) {
      console.warn(`[ensureSipTrunkOriginationUri] Failed to update URI, will delete and recreate: ${e?.message || e}`);
      try {
        await client.trunking.v1.trunks(trunkSid).originationUrls(matchingUri.sid).remove();
      } catch (delErr) {
        console.warn(`[ensureSipTrunkOriginationUri] Failed to delete old URI: ${delErr?.message || delErr}`);
      }
    }
  }

  await client.trunking.v1.trunks(trunkSid).originationUrls.create({
    friendlyName: "LiveKit SIP",
    sipUrl,
    weight: 10,
    priority: 10,
    enabled: true,
  });
  console.log(`[ensureSipTrunkOriginationUri] ✓ Created origination URI: ${sipUrl}`);

  return { created: true };
}

/**
 * Ensure termination credentials exist on the Twilio SIP trunk.
 * Creates a credential list + credential and associates it with the trunk.
 * Returns { credUsername, credPassword }.
 */
async function ensureSipTrunkTerminationCreds({ subaccountSid, trunkSid, existingUsername, existingPassword }) {
  // MUST use direct subaccount auth for trunking API (credential list association).
  const client = await getSubaccountDirectClient(subaccountSid);
  console.log(`[ensureSipTrunkTerminationCreds] Using client for subaccount ${subaccountSid}, trunk ${trunkSid}`);

  // Verify trunk exists first
  try {
    const trunk = await client.trunking.v1.trunks(trunkSid).fetch();
    console.log(`[ensureSipTrunkTerminationCreds] ✓ Verified trunk ${trunkSid} exists on account ${trunk.accountSid}`);
  } catch (e) {
    const errorMsg = String(e?.message || e);
    const status = String(e?.status || "");
    console.error(`[ensureSipTrunkTerminationCreds] ✗ Failed to verify trunk: ${errorMsg} (status: ${status})`);
    if (errorMsg.includes("not found") || status === "404") {
      throw new Error(`Trunk ${trunkSid} does not exist. Please ensure the trunk is created first.`);
    }
    throw new Error(`Failed to verify trunk exists: ${errorMsg}`);
  }

  // ALWAYS check if a credential list is associated with the trunk
  // This is the #1 cause of SIP 500 errors — credentials exist but aren't associated
  try {
    const associatedCredLists = await client.trunking.v1.trunks(trunkSid).credentialsLists.list();
    console.log(`[ensureSipTrunkTerminationCreds] Found ${associatedCredLists.length} credential list(s) associated with trunk ${trunkSid}`);
    
    if (associatedCredLists.length > 0 && existingUsername && existingPassword) {
      // At least one credential list is associated and we have existing credentials
      console.log(`[ensureSipTrunkTerminationCreds] ✓ Credential list(s) already associated with trunk ${trunkSid}, using existing credentials`);
      return { credUsername: existingUsername, credPassword: existingPassword };
    }
    
    // No credential list associated with this trunk — MUST fix this
    if (associatedCredLists.length === 0) {
      console.log(`[ensureSipTrunkTerminationCreds] ⚠ No credential list associated with trunk ${trunkSid} — this causes SIP 500 errors!`);
      
      if (existingUsername) {
        // Try to find and re-associate the existing credential list
        console.log(`[ensureSipTrunkTerminationCreds] Searching for credential list containing username ${existingUsername}...`);
        const allCredLists = await client.sip.credentialLists.list();
        let foundCredList = null;
        
        for (const credList of allCredLists) {
          try {
            const creds = await client.sip.credentialLists(credList.sid).credentials.list();
            if (creds.find(c => c.username === existingUsername)) {
              foundCredList = credList;
              console.log(`[ensureSipTrunkTerminationCreds] ✓ Found credential list ${credList.sid} containing username ${existingUsername}`);
              break;
            }
          } catch (e) {
            continue;
          }
        }
        
        if (foundCredList) {
          try {
            await client.trunking.v1.trunks(trunkSid).credentialsLists.create({
              credentialListSid: foundCredList.sid,
            });
            console.log(`[ensureSipTrunkTerminationCreds] ✓ Re-associated credential list ${foundCredList.sid} with trunk ${trunkSid}`);
            return { credUsername: existingUsername, credPassword: existingPassword };
          } catch (e) {
            if (String(e?.message || "").includes("already associated") || String(e?.message || "").includes("already exists")) {
              console.log(`[ensureSipTrunkTerminationCreds] Credential list already associated (ok)`);
              return { credUsername: existingUsername, credPassword: existingPassword };
            }
            console.warn(`[ensureSipTrunkTerminationCreds] Failed to re-associate credential list: ${e?.message || e}. Will create new credentials.`);
          }
        } else {
          console.log(`[ensureSipTrunkTerminationCreds] No credential list found for username ${existingUsername}. Creating new credentials...`);
        }
      }
      // Fall through to create new credentials AND associate them
    }
  } catch (e) {
    console.warn(`[ensureSipTrunkTerminationCreds] Failed to check credential association: ${e?.message || e}. Will create new credentials.`);
    // Fall through to create new credentials
  }

  // Create new credentials (either no existing credentials, or existing ones aren't properly associated)
  const username = `rc_${Date.now().toString(36)}`;
  const crypto = require("crypto");
  // Twilio requires: min 12 chars, at least one uppercase, one lowercase, one number.
  // crypto.randomBytes hex is only lowercase+digits, so we build a proper password.
  const raw = crypto.randomBytes(24).toString("base64url").slice(0, 28);
  // Guarantee at least one of each required character class.
  const password = "Rc1" + raw;

  // Create credential list on the subaccount.
  console.log(`[ensureSipTrunkTerminationCreds] Creating credential list for trunk ${trunkSid}`);
  const credList = await client.sip.credentialLists.create({
    friendlyName: `RapidCall AI SIP creds (${trunkSid})`,
  });
  console.log(`[ensureSipTrunkTerminationCreds] ✓ Created credential list ${credList.sid}`);

  // Add credential to the list.
  console.log(`[ensureSipTrunkTerminationCreds] Adding credential to list ${credList.sid}`);
  await client.sip.credentialLists(credList.sid).credentials.create({
    username,
    password,
  });
  console.log(`[ensureSipTrunkTerminationCreds] ✓ Added credential ${username} to list ${credList.sid}`);

  // Associate credential list with the trunk for termination auth.
  // NOTE: Twilio SDK v5 renamed this property to "credentialsLists" (plural 's').
  console.log(`[ensureSipTrunkTerminationCreds] Associating credential list ${credList.sid} with trunk ${trunkSid}`);
  try {
    await client.trunking.v1.trunks(trunkSid).credentialsLists.create({
      credentialListSid: credList.sid,
    });
    console.log(`[ensureSipTrunkTerminationCreds] ✓ Associated credential list ${credList.sid} with trunk ${trunkSid}`);
  } catch (e) {
    // May already be associated (race condition) - that's fine
    if (!String(e?.message || "").includes("already associated") && !String(e?.message || "").includes("already exists")) {
      console.warn(`[ensureSipTrunkTerminationCreds] Could not associate credential list: ${e?.message || e}`);
      throw e;
    } else {
      console.log(`[ensureSipTrunkTerminationCreds] Credential list already associated (ok)`);
    }
  }

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
/**
 * Make a REST API request to Twilio Trunking API (for IP ACL operations not exposed in SDK)
 */
async function twilioTrunkingRequest({ subaccountSid, method, path, data }) {
  // Get the subaccount's auth token - reuse the same logic as getSubaccountDirectClient
  const masterCreds = getMasterCreds();
  if (!masterCreds) throw new Error("Twilio master credentials not configured");
  
  const masterClient = twilio(masterCreds.accountSid, masterCreds.authToken);
  const subaccount = await masterClient.api.accounts(subaccountSid).fetch();
  if (!subaccount || !subaccount.authToken) {
    throw new Error(`Subaccount ${subaccountSid} auth token not available`);
  }
  
  const authToken = subaccount.authToken;
  const accountSid = subaccountSid;
  
  const baseUrl = "https://trunking.twilio.com/v1";
  const url = `${baseUrl}${path}`;
  
  const auth = Buffer.from(`${accountSid}:${authToken}`).toString("base64");
  const headers = {
    "Authorization": `Basic ${auth}`,
    "Content-Type": "application/x-www-form-urlencoded",
  };
  
  let body = null;
  if (data && (method === "POST" || method === "PUT")) {
    body = new URLSearchParams();
    for (const [key, value] of Object.entries(data)) {
      if (value !== undefined && value !== null) {
        body.append(key, String(value));
      }
    }
    body = body.toString();
  }
  
  const response = await fetch(url, {
    method,
    headers,
    body,
  });
  
  const responseText = await response.text();
  let responseData;
  try {
    responseData = JSON.parse(responseText);
  } catch {
    responseData = { message: responseText };
  }
  
  if (!response.ok) {
    const error = new Error(responseData.message || `HTTP ${response.status}`);
    error.status = response.status;
    error.code = responseData.code;
    throw error;
  }
  
  return responseData;
}

/**
 * Make a REST API request to Twilio SIP API (for IP ACL creation/management)
 * IP ACLs are created via SIP API, then associated with trunks via Trunking API
 */
async function twilioSipRequest({ subaccountSid, method, path, data }) {
  // Get the subaccount's auth token
  const masterCreds = getMasterCreds();
  if (!masterCreds) throw new Error("Twilio master credentials not configured");
  
  const masterClient = twilio(masterCreds.accountSid, masterCreds.authToken);
  const subaccount = await masterClient.api.accounts(subaccountSid).fetch();
  if (!subaccount || !subaccount.authToken) {
    throw new Error(`Subaccount ${subaccountSid} auth token not available`);
  }
  
  const authToken = subaccount.authToken;
  const accountSid = subaccountSid;
  
  const baseUrl = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}`;
  const url = `${baseUrl}${path}`;
  
  const auth = Buffer.from(`${accountSid}:${authToken}`).toString("base64");
  const headers = {
    "Authorization": `Basic ${auth}`,
    "Content-Type": "application/x-www-form-urlencoded",
  };
  
  let body = null;
  if (data && (method === "POST" || method === "PUT")) {
    body = new URLSearchParams();
    for (const [key, value] of Object.entries(data)) {
      if (value !== undefined && value !== null) {
        body.append(key, String(value));
      }
    }
    body = body.toString();
  }
  
  const response = await fetch(url, {
    method,
    headers,
    body,
  });
  
  const responseText = await response.text();
  let responseData;
  try {
    responseData = JSON.parse(responseText);
  } catch {
    responseData = { message: responseText };
  }
  
  if (!response.ok) {
    const error = new Error(responseData.message || `HTTP ${response.status}`);
    error.status = response.status;
    error.code = responseData.code;
    throw error;
  }
  
  return responseData;
}

async function ensureSipTrunkIpAcl({ subaccountSid, trunkSid, ipAddresses }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  if (!trunkSid) throw new Error("Trunk SID is required");
  if (!ipAddresses || !Array.isArray(ipAddresses) || ipAddresses.length === 0) {
    throw new Error("IP addresses array is required");
  }

  const client = await getSubaccountDirectClient(subaccountSid);
  
  console.log(`[ensureSipTrunkIpAcl] Using client for subaccount ${subaccountSid}, trunk ${trunkSid}`);
  
  // Verify trunk exists first
  try {
    const trunk = await client.trunking.v1.trunks(trunkSid).fetch();
    console.log(`[ensureSipTrunkIpAcl] ✓ Verified trunk ${trunkSid} exists on account ${trunk.accountSid}`);
  } catch (e) {
    const errorMsg = String(e?.message || e);
    const status = String(e?.status || "");
    console.error(`[ensureSipTrunkIpAcl] ✗ Failed to verify trunk: ${errorMsg} (status: ${status})`);
    if (errorMsg.includes("not found") || status === "404") {
      throw new Error(`Trunk ${trunkSid} does not exist. Please ensure the trunk is created first.`);
    }
    throw new Error(`Failed to verify trunk exists: ${errorMsg}`);
  }

  // Create or find an IP Access Control List for this trunk
  const aclFriendlyName = `RapidCall AI SIP ACL (${trunkSid.slice(-8)})`;
  
  // First, check if an ACL is already associated with this trunk using REST API
  let ipAclList = null;
  try {
    console.log(`[ensureSipTrunkIpAcl] Checking for existing ACLs on trunk ${trunkSid}`);
    const trunkAclsResponse = await twilioTrunkingRequest({
      subaccountSid,
      method: "GET",
      path: `/Trunks/${trunkSid}/IpAccessControlLists`,
    });
    
    if (trunkAclsResponse.ip_access_control_lists && trunkAclsResponse.ip_access_control_lists.length > 0) {
      // Use the first ACL already associated with the trunk
      ipAclList = trunkAclsResponse.ip_access_control_lists[0];
      console.log(`[ensureSipTrunkIpAcl] ✓ Found existing ACL ${ipAclList.sid} already associated with trunk`);
    } else {
      console.log(`[ensureSipTrunkIpAcl] No ACLs currently associated with trunk ${trunkSid}`);
    }
  } catch (e) {
    const errorMsg = String(e?.message || e);
    const status = String(e?.status || "");
    console.warn(`[ensureSipTrunkIpAcl] Could not list trunk ACLs: ${errorMsg} (status: ${status}) - will try to create new ACL`);
  }

  // If no ACL is associated, try to find or create one
  // NOTE: IP ACLs are created via SIP API, not Trunking API
  if (!ipAclList) {
    try {
      // Try to find an existing ACL by name on the account using SIP API
      console.log(`[ensureSipTrunkIpAcl] Listing all ACLs on account to find or create one`);
      const allAclsResponse = await twilioSipRequest({
        subaccountSid,
        method: "GET",
        path: "/SIP/IpAccessControlLists.json",
      });
      
      const allAcls = allAclsResponse.ip_access_control_lists || [];
      console.log(`[ensureSipTrunkIpAcl] Found ${allAcls.length} existing ACLs on account`);
      
      ipAclList = allAcls.find((acl) => acl.friendly_name === aclFriendlyName);
      
      if (!ipAclList) {
        // Create a new IP ACL resource on the account using SIP API
        console.log(`[ensureSipTrunkIpAcl] Creating new IP ACL with name: ${aclFriendlyName}`);
        const createResponse = await twilioSipRequest({
          subaccountSid,
          method: "POST",
          path: "/SIP/IpAccessControlLists.json",
          data: {
            FriendlyName: aclFriendlyName,
          },
        });
        ipAclList = createResponse;
        console.log(`[ensureSipTrunkIpAcl] ✓ Created new IP ACL ${ipAclList.sid}`);
      } else {
        console.log(`[ensureSipTrunkIpAcl] ✓ Found existing IP ACL ${ipAclList.sid} by name`);
      }
    } catch (e) {
      const errorMsg = String(e?.message || e);
      const status = String(e?.status || "");
      const code = String(e?.code || "");
      console.error(`[ensureSipTrunkIpAcl] ✗ Failed to create or find IP ACL: ${errorMsg} (status: ${status}, code: ${code})`);
      
      // Provide more specific error messages
      if (status === "401" || status === "403") {
        throw new Error(`Twilio API authorization failed for IP ACL operations. Check your subaccount credentials. Error: ${errorMsg}`);
      }
      if (status === "404") {
        throw new Error(`IP ACL API endpoint not found (404). Your Twilio account may not have SIP API access enabled. Please contact Twilio support. Error: ${errorMsg}`);
      }
      
      throw new Error(`Failed to create or find IP ACL: ${errorMsg} (status: ${status}, code: ${code})`);
    }

    // Associate the IP ACL with the trunk
    try {
      console.log(`[ensureSipTrunkIpAcl] Associating IP ACL ${ipAclList.sid} with trunk ${trunkSid}`);
      await twilioTrunkingRequest({
        subaccountSid,
        method: "POST",
        path: `/Trunks/${trunkSid}/IpAccessControlLists`,
        data: {
          IpAccessControlListSid: ipAclList.sid,
        },
      });
      console.log(`[ensureSipTrunkIpAcl] ✓ Associated IP ACL ${ipAclList.sid} with trunk ${trunkSid}`);
    } catch (e) {
      // May already be associated (race condition) - that's fine
      const errorMsg = String(e?.message || "");
      if (!errorMsg.includes("already associated") && !errorMsg.includes("already exists") && !errorMsg.includes("already in use")) {
        console.warn(`[ensureSipTrunkIpAcl] Could not associate ACL: ${e?.message || e}`);
        // Don't throw - we'll try to add IPs anyway
      } else {
        console.log(`[ensureSipTrunkIpAcl] ACL already associated (ok)`);
      }
    }
  }

  // Add IP addresses or CIDR ranges to the ACL
  // Fetch existing IPs to avoid duplicates (using SIP API)
  let existingIps = [];
  try {
    console.log(`[ensureSipTrunkIpAcl] Fetching existing IPs from ACL ${ipAclList.sid}`);
    const ipsResponse = await twilioSipRequest({
      subaccountSid,
      method: "GET",
      path: `/SIP/IpAccessControlLists/${ipAclList.sid}/IpAddresses.json`,
    });
    existingIps = ipsResponse.ip_addresses || [];
    console.log(`[ensureSipTrunkIpAcl] Found ${existingIps.length} existing IPs in ACL`);
  } catch (e) {
    console.warn(`[ensureSipTrunkIpAcl] Could not list existing IPs, will attempt to add all: ${e?.message || e}`);
  }
  
  const existingIpSet = new Set(existingIps.map((ip) => ip.ip_address || ip.ipAddress));
  const existingCidrSet = new Set(
    existingIps
      .map((ip) => {
        const ipAddr = ip.ip_address || ip.ipAddress;
        // Normalize: if no /, treat as /32
        return ipAddr && ipAddr.includes('/') ? ipAddr : ipAddr ? `${ipAddr}/32` : null;
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

    // Attempt to add the IP/CIDR using SIP API
    try {
      // Twilio SIP API accepts CIDR notation directly in IpAddress field
      // Format: "x.x.x.x/prefix" or "x.x.x.x" for single IP
      console.log(`[ensureSipTrunkIpAcl] Adding ${isCidr ? 'CIDR range' : 'IP'} ${trimmed} to ACL ${ipAclList.sid}`);
      await twilioSipRequest({
        subaccountSid,
        method: "POST",
        path: `/SIP/IpAccessControlLists/${ipAclList.sid}/IpAddresses.json`,
        data: {
          FriendlyName: `LiveKit SIP ${trimmed}`,
          IpAddress: trimmed, // Twilio accepts CIDR notation directly
        },
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
      if (errorMsg.includes("already exists") || errorMsg.includes("duplicate") || errorMsg.includes("already in use")) {
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

  // Fetch final count (using SIP API)
  let finalIps = [];
  try {
    const finalResponse = await twilioSipRequest({
      subaccountSid,
      method: "GET",
      path: `/SIP/IpAccessControlLists/${ipAclList.sid}/IpAddresses.json`,
    });
    finalIps = finalResponse.ip_addresses || [];
  } catch (e) {
    console.warn(`[ensureSipTrunkIpAcl] Could not fetch final IP count: ${e?.message || e}`);
  }

  return {
    aclSid: ipAclList.sid,
    aclFriendlyName: ipAclList.friendly_name || ipAclList.friendlyName,
    ipAddressesAdded: addedCount,
    ipAddressesSkipped: skippedCount,
    ipAddressesFailed: failedCount,
    failedIps: failedIps.length > 0 ? failedIps : undefined,
    totalIps: finalIps.length,
  };
}

/**
 * Remove all IP Access Control Lists associated with a Twilio SIP trunk.
 * This is used when IP ACL restrictions are no longer wanted (e.g., relying on credentials only).
 */
async function removeAllSipTrunkIpAcls({ subaccountSid, trunkSid }) {
  if (!subaccountSid) throw new Error("Workspace has no Twilio subaccount yet");
  if (!trunkSid) throw new Error("Trunk SID is required");

  let removedCount = 0;
  try {
    console.log(`[removeAllSipTrunkIpAcls] Listing ACLs on trunk ${trunkSid}`);
    const trunkAclsResponse = await twilioTrunkingRequest({
      subaccountSid,
      method: "GET",
      path: `/Trunks/${trunkSid}/IpAccessControlLists`,
    });

    const acls = trunkAclsResponse.ip_access_control_lists || [];
    console.log(`[removeAllSipTrunkIpAcls] Found ${acls.length} ACLs associated with trunk`);

    for (const acl of acls) {
      try {
        console.log(`[removeAllSipTrunkIpAcls] Disassociating ACL ${acl.sid} from trunk ${trunkSid}`);
        await twilioTrunkingRequest({
          subaccountSid,
          method: "DELETE",
          path: `/Trunks/${trunkSid}/IpAccessControlLists/${acl.sid}`,
        });
        removedCount++;
        console.log(`[removeAllSipTrunkIpAcls] ✓ Disassociated ACL ${acl.sid}`);
      } catch (e) {
        console.warn(`[removeAllSipTrunkIpAcls] Failed to disassociate ACL ${acl.sid}: ${e?.message || e}`);
      }
    }
  } catch (e) {
    console.warn(`[removeAllSipTrunkIpAcls] Could not list/remove ACLs: ${e?.message || e}`);
  }

  console.log(`[removeAllSipTrunkIpAcls] Done — removed ${removedCount} ACL associations`);
  return { removedCount };
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
  removeAllSipTrunkIpAcls,
  getCallIpAddresses,
  getIpAddressesFromRecentCalls,
};
