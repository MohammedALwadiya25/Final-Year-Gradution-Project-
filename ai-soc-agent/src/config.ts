import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z.string().default("info"),
  AI_PROVIDER: z.enum(["gemini"]).default("gemini"),
  AI_MAX_TOKENS: z.coerce.number().int().positive().default(1600),
  GEMINI_API_KEY: z.string().optional(),
  GEMINI_MODEL: z.string().default("gemini-1.5-flash"),
  AGENT_MAX_TOOL_ROUNDS: z.coerce.number().int().min(1).max(20).default(5),
  MCP_READONLY: z
    .string()
    .default("true")
    .transform((value) => value.toLowerCase() !== "false"),
  ZEEK_MCP_COMMAND: z.string().default("node"),
  ZEEK_MCP_ARGS: z.string().default("../zeek-mcp/dist/index.js"),
  SURICATA_MCP_COMMAND: z.string().default("node"),
  SURICATA_MCP_ARGS: z.string().default("../suricata-mcp/dist/index.js"),
  MITRE_MCP_COMMAND: z.string().default("node"),
  MITRE_MCP_ARGS: z.string().default("../mitre-mcp/dist/index.js"),
  MITRE_MATRICES: z.string().default("enterprise"),
});

function splitArgs(args: string): string[] {
  return args
    .split(" ")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      if (part.startsWith("../") || part.startsWith("./")) {
        return path.resolve(projectRoot, part);
      }
      return part;
    });
}

const env = envSchema.parse(process.env);

export const config = {
  nodeEnv: env.NODE_ENV,
  port: env.PORT,
  logLevel: env.LOG_LEVEL,
  ai: {
    provider: env.AI_PROVIDER,
    maxTokens: env.AI_MAX_TOKENS,
  },
  gemini: {
    apiKey: env.GEMINI_API_KEY,
    model: env.GEMINI_MODEL,
    maxTokens: env.AI_MAX_TOKENS,
    maxToolRounds: env.AGENT_MAX_TOOL_ROUNDS,
  },
  mcp: {
    readonly: env.MCP_READONLY,
    servers: [
      {
        id: "zeek",
        displayName: "Zeek NSM",
        command: env.ZEEK_MCP_COMMAND,
        args: splitArgs(env.ZEEK_MCP_ARGS),
        env: {
          ZEEK_LOG_DIR: process.env.ZEEK_LOG_DIR ?? process.env.ZEEK_LOG_PATH,
          ZEEK_LOG_FORMAT: process.env.ZEEK_LOG_FORMAT,
        },
      },
      {
        id: "suricata",
        displayName: "Suricata IDS",
        command: env.SURICATA_MCP_COMMAND,
        args: splitArgs(env.SURICATA_MCP_ARGS),
        env: {
          SURICATA_EVE_LOG:
            process.env.SURICATA_EVE_LOG ??
            process.env.SURICATA_EVE_PATH ??
            process.env.EVE_JSON_PATH,
          ZEEK_LOGS_DIR: process.env.ZEEK_LOGS_DIR ?? process.env.ZEEK_LOG_DIR ?? process.env.ZEEK_LOG_PATH,
        },
      },
      // Wazuh removed — using direct sensor architecture (Suricata + Zeek)
      {
        id: "mitre",
        displayName: "MITRE ATT&CK",
        command: env.MITRE_MCP_COMMAND,
        args: splitArgs(env.MITRE_MCP_ARGS),
        env: {
          MITRE_MATRICES: env.MITRE_MATRICES,
          MITRE_DATA_DIR: process.env.MITRE_DATA_DIR,
        },
      },
    ],
  },
} as const;

export type AppConfig = typeof config;