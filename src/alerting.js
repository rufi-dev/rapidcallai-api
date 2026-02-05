const https = require("https");
const { URL } = require("url");

function sendAlert(type, payload) {
  const hook = String(process.env.ALERT_WEBHOOK_URL || "").trim();
  if (!hook) return;
  try {
    const u = new URL(hook);
    const body = JSON.stringify({
      type,
      ts: Date.now(),
      payload: payload || {},
    });

    const req = https.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === "https:" ? 443 : 80),
        path: `${u.pathname}${u.search}`,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
        timeout: 5000,
      },
      (res) => {
        res.resume();
      }
    );
    req.on("error", () => {});
    req.on("timeout", () => req.destroy());
    req.write(body);
    req.end();
  } catch {
    // ignore alert failures
  }
}

module.exports = { sendAlert };
