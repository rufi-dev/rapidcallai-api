const { S3Client, GetObjectCommand, HeadObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

async function withRetry(fn, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt += 1) {
    try {
      return await fn();
    } catch (e) {
      if (attempt >= maxRetries - 1) throw e;
      await new Promise((r) => setTimeout(r, 300 * (2 ** attempt)));
    }
  }
  throw new Error("S3 operation failed after retries");
}

function getS3Client() {
  const region = process.env.EGRESS_S3_REGION;
  const accessKeyId = process.env.EGRESS_S3_ACCESS_KEY;
  const secretAccessKey = process.env.EGRESS_S3_SECRET;
  const endpoint = process.env.EGRESS_S3_ENDPOINT || undefined;
  const forcePathStyle = String(process.env.EGRESS_S3_FORCE_PATH_STYLE || "").toLowerCase() === "true";

  if (!region || !accessKeyId || !secretAccessKey) return null;

  return new S3Client({
    region,
    endpoint,
    forcePathStyle,
    credentials: { accessKeyId, secretAccessKey },
  });
}

async function presignGetObject({ bucket, key, expiresInSeconds = 3600 }) {
  const client = getS3Client();
  if (!client) throw new Error("Missing S3 client config (EGRESS_S3_REGION/EGRESS_S3_ACCESS_KEY/EGRESS_S3_SECRET)");
  const cmd = new GetObjectCommand({ Bucket: bucket, Key: key });
  return await withRetry(() => getSignedUrl(client, cmd, { expiresIn: expiresInSeconds }));
}

async function getObject({ bucket, key, range }) {
  const client = getS3Client();
  if (!client) throw new Error("Missing S3 client config (EGRESS_S3_REGION/EGRESS_S3_ACCESS_KEY/EGRESS_S3_SECRET)");
  const cmd = new GetObjectCommand({
    Bucket: bucket,
    Key: key,
    ...(range ? { Range: range } : {}),
  });
  return await withRetry(() => client.send(cmd));
}

async function headObject({ bucket, key }) {
  const client = getS3Client();
  if (!client) throw new Error("Missing S3 client config (EGRESS_S3_REGION/EGRESS_S3_ACCESS_KEY/EGRESS_S3_SECRET)");
  const cmd = new HeadObjectCommand({ Bucket: bucket, Key: key });
  return await withRetry(() => client.send(cmd));
}

module.exports = { presignGetObject, getObject, headObject };


