import "dotenv/config";
import { McpHub } from "../mcp/McpHub.js";
import { logger } from "../logger.js";

const hub = new McpHub();

try {
  await hub.connect();
  const tools = hub.listTools();
  logger.info(
    {
      toolCount: tools.length,
      sampleTools: tools.slice(0, 20).map((tool) => tool.agentToolName),
    },
    "Smoke test passed: MCP tools discovered",
  );
} finally {
  await hub.close();
}
