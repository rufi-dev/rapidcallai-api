const { twiml } = require("twilio");
const { getMasterClient, getSubaccountClient } = require("../twilio");

function requireTwilioCreds() {
  if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN) {
    throw new Error("Twilio is not configured (missing TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN)");
  }
}

function getTwilioClient(workspace) {
  requireTwilioCreds();
  const sid = workspace?.twilioSubaccountSid || workspace?.twilio_subaccount_sid || null;
  if (sid) {
    const c = getSubaccountClient(sid);
    if (!c) throw new Error("Twilio subaccount client not available");
    return c;
  }
  const c = getMasterClient();
  if (!c) throw new Error("Twilio master client not available");
  return c;
}

function buildSipTarget({ roomName, sipEndpoint }) {
  let dest = `${roomName}@${sipEndpoint}`;
  if (!dest.startsWith("sip:")) dest = `sip:${dest}`;
  return dest;
}

function buildTwiML({ roomName, sipEndpoint, sipUser, sipPass, twilioCallSid }) {
  const VoiceResponse = twiml.VoiceResponse;
  const vr = new VoiceResponse();
  const dial = vr.dial({ answerOnBridge: true });
  const dest = buildSipTarget({ roomName, sipEndpoint });
  const sipNode = sipUser && sipPass ? dial.sip({ username: sipUser, password: sipPass }, dest) : dial.sip(dest);
  if (sipNode && typeof sipNode.parameter === "function" && twilioCallSid) {
    try {
      sipNode.parameter({ name: "X-Twilio-CallSid", value: twilioCallSid });
    } catch {
      // ignore
    }
  }
  return vr.toString();
}

async function startOutboundCall({ job, workspace, fromNumber, sipEndpoint, sipUser, sipPass, statusCallbackUrl }) {
  const client = getTwilioClient(workspace);
  const roomName = job.roomName;
  if (!roomName) throw new Error("Missing roomName for outbound call");
  if (!sipEndpoint) throw new Error("LIVEKIT_SIP_ENDPOINT is not set");
  if (!fromNumber) throw new Error("Missing outbound from number");

  // Placeholder call to generate CallSid for TwiML param injection
  const call = await client.calls.create({
    to: job.phoneE164,
    from: fromNumber,
    twiml: buildTwiML({ roomName, sipEndpoint, sipUser, sipPass }),
    statusCallback: statusCallbackUrl || undefined,
    statusCallbackEvent: ["initiated", "ringing", "answered", "completed"],
    statusCallbackMethod: "POST",
  });

  return { providerCallId: call.sid, roomName };
}

async function hangupCall({ workspace, providerCallId }) {
  const client = getTwilioClient(workspace);
  await client.calls(providerCallId).update({ status: "completed" });
}

async function getCallStatus({ workspace, providerCallId }) {
  const client = getTwilioClient(workspace);
  const call = await client.calls(providerCallId).fetch();
  return call.status;
}

module.exports = {
  startOutboundCall,
  hangupCall,
  getCallStatus,
};
