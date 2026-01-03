const { AccessToken, RoomServiceClient } = require("livekit-server-sdk");

function getLiveKitConfig() {
  const url = process.env.LIVEKIT_URL;
  const apiKey = process.env.LIVEKIT_API_KEY;
  const apiSecret = process.env.LIVEKIT_API_SECRET;
  if (!url || !apiKey || !apiSecret) {
    throw new Error("Missing LIVEKIT_URL / LIVEKIT_API_KEY / LIVEKIT_API_SECRET in server environment");
  }
  return { url, apiKey, apiSecret };
}

function roomService() {
  const { url, apiKey, apiSecret } = getLiveKitConfig();
  return new RoomServiceClient(url, apiKey, apiSecret);
}

async function createParticipantToken({ roomName, identity, name, metadata }) {
  const { apiKey, apiSecret } = getLiveKitConfig();
  const at = new AccessToken(apiKey, apiSecret, { identity, name, metadata });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
  return await at.toJwt();
}

module.exports = { roomService, createParticipantToken };


