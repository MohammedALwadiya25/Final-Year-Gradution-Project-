import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig } from "./config.js";
import { QueryEngine } from "./query/engine.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerFlowTools } from "./tools/flows.js";
import { registerDnsTools } from "./tools/dns.js";
import { registerHttpTools } from "./tools/http.js";
import { registerTlsTools } from "./tools/tls.js";
import { registerSshTools } from "./tools/ssh.js";
import { registerAnomalyTools } from "./tools/anomalies.js";
import { registerInvestigationTools } from "./tools/investigation.js";
import { registerBeaconingTools } from "./analytics/beaconing.js";
import { registerDgaDetectionTools } from "./analytics/dns_entropy.js";
import { registerExfiltrationTools } from "./analytics/exfiltration.js";
import { registerLateralMovementTools } from "./analytics/lateral.js";
import { registerCorrelationTools } from "./tools/correlation.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

const server = new McpServer({
  name: "suricata-mcp",
  version: "2.0.0",
  description:
    "MCP server for read-only Suricata IDS log investigation and Zeek correlation",
});

const config = getConfig();
const engine = new QueryEngine(config);

// Alert analysis
registerAlertTools(server, engine);

// Flow analysis
registerFlowTools(server, engine);
registerBeaconingTools(server, engine);

// Protocol analysis
registerDnsTools(server, engine);
registerHttpTools(server, engine);
registerTlsTools(server, engine);
registerSshTools(server, engine);

// Anomaly analysis
registerAnomalyTools(server, engine);

// Cross-type investigation
registerInvestigationTools(server, engine);

// Advanced analytics
registerDgaDetectionTools(server, engine);
registerExfiltrationTools(server, engine);
registerLateralMovementTools(server, engine);

// Cross-correlation (Suricata + Zeek)
registerCorrelationTools(server, engine, config);

// Resources and prompts
registerResources(server, engine, config);
registerPrompts(server);

async function main() {
  const transport = new StdioServerTransport();
  // Strip draft `$schema` fields that some hosted LLM tool APIs reject.
  const __send = transport.send.bind(transport);
  (transport as any).send = (message: any) => {
    const tools = message?.result?.tools;
    if (Array.isArray(tools)) {
      for (const t of tools) {
        if (t?.inputSchema) delete t.inputSchema.$schema;
        if (t?.outputSchema) delete t.outputSchema.$schema;
      }
    }
    return __send(message);
  };
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
