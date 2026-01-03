const { EgressClient } = require("livekit-server-sdk");
const { EncodedFileOutput, EncodedFileType, S3Upload } = require("@livekit/protocol");

function getS3Config() {
  const bucket = process.env.EGRESS_S3_BUCKET;
  const region = process.env.EGRESS_S3_REGION;
  const accessKey = process.env.EGRESS_S3_ACCESS_KEY;
  const secret = process.env.EGRESS_S3_SECRET;
  const endpoint = process.env.EGRESS_S3_ENDPOINT || "";
  const forcePathStyle = String(process.env.EGRESS_S3_FORCE_PATH_STYLE || "").toLowerCase() === "true";

  if (!bucket || !region || !accessKey || !secret) return null;
  return { bucket, region, accessKey, secret, endpoint, forcePathStyle };
}

function egressClient() {
  const host = process.env.LIVEKIT_URL;
  const apiKey = process.env.LIVEKIT_API_KEY;
  const secret = process.env.LIVEKIT_API_SECRET;
  if (!host || !apiKey || !secret) throw new Error("Missing LIVEKIT_URL / LIVEKIT_API_KEY / LIVEKIT_API_SECRET");
  return new EgressClient(host, apiKey, secret);
}

async function startCallEgress({ roomName, callId }) {
  const s3 = getS3Config();
  if (!s3) return { enabled: false };

  // Store as MP3 for best browser compatibility.
  const key = `calls/${callId}.mp3`;
  const output = new EncodedFileOutput({
    fileType: EncodedFileType.MP3,
    filepath: key,
    output: {
      case: "s3",
      value: new S3Upload({
        accessKey: s3.accessKey,
        secret: s3.secret,
        region: s3.region,
        bucket: s3.bucket,
        endpoint: s3.endpoint,
        forcePathStyle: s3.forcePathStyle,
      }),
    },
  });

  const ec = egressClient();
  const info = await ec.startRoomCompositeEgress(roomName, output, {
    audioOnly: true,
  });

  return {
    enabled: true,
    egressId: info.egressId,
    key,
    bucket: s3.bucket,
    status: info.status,
  };
}

async function stopEgress(egressId) {
  const ec = egressClient();
  return await ec.stopEgress(egressId);
}

async function getEgressInfo(egressId) {
  const ec = egressClient();
  const list = await ec.listEgress({ egressId });
  return list?.[0] ?? null;
}

module.exports = { getS3Config, startCallEgress, stopEgress, getEgressInfo };


