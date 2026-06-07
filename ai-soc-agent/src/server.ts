import express from "express";
import helmet from "helmet";
import { pinoHttp } from "pino-http";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { McpHub } from "./mcp/McpHub.js";
import { GeminiSocReasoner } from "./llm/GeminiSocReasoner.js";
import { InvestigationService } from "./services/InvestigationService.js";
import { investigationRequestSchema } from "./types.js";

const app = express();
const mcpHub = new McpHub();

app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(
  pinoHttp({
    logger,
  }),
);

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "ai-soc-agent",
    ai_provider: config.ai.provider,
    model: config.gemini.model,
    readonly_mcp: config.mcp.readonly,
    tools: mcpHub.listTools().length,
  });
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

app.post("/investigate", async (req, res, next) => {
  try {
    const parsed = investigationRequestSchema.parse(req.body);
    const service = req.app.locals.investigationService as InvestigationService;
    const result = await service.investigate(parsed);
    res.json(result);
  } catch (error) {
    next(error);
  }
});

app.use(
  (
    error: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
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
