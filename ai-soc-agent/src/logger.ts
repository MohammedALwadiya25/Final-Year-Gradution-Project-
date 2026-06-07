import pino from "pino";
import { config } from "./config.js";

export const logger = pino({
  level: config.logLevel,
  base: {
    service: "ai-soc-agent",
  },
  redact: {
    paths: [
      "req.headers.authorization",
      "GEMINI_API_KEY",
      "*.WAZUH_PASSWORD",
      "*.apiKey",
      "*.password",
    ],
    remove: true,
  },
});
