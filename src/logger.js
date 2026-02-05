let pino = null;
let pinoHttp = null;

try {
  // Optional dependency: pino
  // eslint-disable-next-line global-require
  pino = require("pino");
  // eslint-disable-next-line global-require
  pinoHttp = require("pino-http");
} catch {
  pino = null;
  pinoHttp = null;
}


const logger = pino
  ? pino({ level: process.env.LOG_LEVEL || "info" })
  : {
      info: console.log.bind(console),
      warn: console.warn.bind(console),
      error: console.error.bind(console),
    };

function requestLogger() {
  if (pinoHttp) {
    return pinoHttp({
      logger,
      customLogLevel: (_req, res, err) => (err || res.statusCode >= 500 ? "error" : "info"),
      serializers: {
        req(req) {
          return {
            id: req.requestId,
            method: req.method,
            url: req.url,
          };
        },
        res(res) {
          return {
            statusCode: res.statusCode,
          };
        },
      },
    });
  }

  return (req, res, next) => {
    const started = Date.now();
    res.on("finish", () => {
      logger.info({
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: Date.now() - started,
      });
    });
    next();
  };
}

module.exports = { logger, requestLogger };
