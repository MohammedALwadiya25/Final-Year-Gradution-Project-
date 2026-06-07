import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { pinoHttp } from "pino-http";
import { z } from "zod";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { McpHub } from "./mcp/McpHub.js";
import { GeminiSocReasoner } from "./llm/GeminiSocReasoner.js";
import { InvestigationService } from "./services/InvestigationService.js";
import { investigationRequestSchema } from "./types.js";

const app = express();
const mcpHub = new McpHub();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: config.nodeEnv === "development" 
    ? "*" 
    : ["http://100.64.0.3:5678", "http://localhost:5678", "http://localhost:3000"],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
}));

// Rate limiting
const investigateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "rate_limited", message: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json({ limit: "1mb" }));
app.use(pinoHttp({ logger }));

// Request timeout middleware
const timeout = (ms: number) => (req: express.Request, res: express.Response, next: express.NextFunction) => {
  res.setTimeout(ms, () => {
    res.status(408).json({ error: "request_timeout", message: `Request timed out after ${ms}ms` });
  });
  next();
};

// Health check with MCP server verification
app.get("/health", async (_req, res) => {
  try {
    const tools = mcpHub.listTools();
    const failedServers = mcpHub.getFailedServers();
    const status = failedServers.length > 0 ? "degraded" : "ok";
    
    res.json({
      status,
      service: "ai-soc-agent",
      ai_provider: config.ai.provider,
      model: config.gemini.model,
      readonly_mcp: config.mcp.readonly,
      tools: tools.length,
      servers: Array.from(new Set(tools.map(t => t.serverId))),
      failed_servers: failedServers,
      degraded: failedServers.length > 0,
      gemini_configured: !!(config.gemini.apiKey && config.gemini.apiKey !== "YOUR_GEMINI_API_KEY_HERE"),
    });
  } catch (error) {
    logger.error({ error: error instanceof Error ? error.message : String(error) }, "Health check failed");
    res.status(503).json({
      status: "error",
      error: "health_check_failed",
      message: error instanceof Error ? error.message : String(error),
    });
  }
});

app.get("/tools", (_req, res) => {
  res.json({
    readonly_mcp: config.mcp.readonly,
    tools: mcpHub.listTools().map((tool) => ({
      name: tool.agentToolName,
      server: tool.serverId,
      original_name: tool.originalName,
      description: tool.description,
    })),
  });
});

// Simple API key auth middleware (optional, for production)
const apiKeyAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const apiKey = req.headers["x-api-key"];
  const expectedKey = process.env.AGENT_API_KEY;
  
  // Skip auth if no key configured (development mode)
  if (!expectedKey || expectedKey === "none") {
    return next();
  }
  
  if (apiKey !== expectedKey) {
    return res.status(401).json({ error: "unauthorized", message: "Invalid or missing API key" });
  }
  
  next();
};

app.post("/investigate", investigateLimiter, timeout(25000), apiKeyAuth, async (req, res, next) => {
  try {
    const parsed = investigationRequestSchema.parse(req.body);
    const service = req.app.locals.investigationService as InvestigationService;
    const result = await service.investigate(parsed);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

// Metrics endpoint for thesis data collection
app.get("/metrics", (_req, res) => {
  // This would connect to a metrics store in production
  res.json({
    status: "ok",
    note: "Connect to Prometheus or similar for production metrics",
    endpoints: {
      health: "/health",
      tools: "/tools",
      investigate: "POST /investigate",
      metrics: "/metrics",
    }
  });
});

// Error handler with Zod validation details
app.use(
  (
    error: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    if (error instanceof z.ZodError) {
      logger.warn({ issues: error.issues }, "Validation failed");
      return res.status(400).json({
        error: "validation_failed",
        message: "Request validation failed",
        issues: error.issues.map((issue) => ({
          path: issue.path,
          message: issue.message,
        })),
      });
    }

    const message = error instanceof Error ? error.message : String(error);
    logger.error({ error: message }, "Request failed");
    res.status(500).json({
      error: "investigation_failed",
      message,
    });
  },
);

async function main(): Promise<void> {
  await mcpHub.connect();

  const reasoner = new GeminiSocReasoner(mcpHub);
  app.locals.investigationService = new InvestigationService(reasoner);

  const server = app.listen(config.port, () => {
    logger.info(
      {
        port: config.port,
        provider: config.ai.provider,
        model: config.gemini.model,
        mcpTools: mcpHub.listTools().length,
        readonlyMcp: config.mcp.readonly,
        geminiConfigured: !!(config.gemini.apiKey && config.gemini.apiKey !== "YOUR_GEMINI_API_KEY_HERE"),
      },
      "AI SOC Agent started",
    );
  });

  const shutdown = async (signal: string) => {
    logger.info({ signal }, "Shutting down");
    server.close();
    await mcpHub.close();
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch(async (error) => {
  logger.error({ error: error instanceof Error ? error.message : String(error) }, "Fatal startup error");
  await mcpHub.close();
  process.exit(1);
});