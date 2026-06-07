import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig } from "./config.js";
import { registerConnectionTools } from "./tools/connections.js";
import { registerDnsTools } from "./tools/dns.js";
import { registerHttpTools } from "./tools/http.js";
import { registerSslTools } from "./tools/ssl.js";
import { registerFileTools } from "./tools/files.js";
import { registerNoticeTools } from "./tools/notices.js";
import { registerSshTools } from "./tools/ssh.js";
import { registerInvestigationTools } from "./tools/investigation.js";
import { registerBeaconingTools } from "./tools/beaconing.js";
import { registerAnomalyTools } from "./tools/anomaly.js";

import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

const server = new McpServer({
  name: "zeek-mcp",
  version: "3.0.0",
  description:
    "MCP server for read-only Zeek NIDS log investigation in the AI SOC Agent project",
});

const config = getConfig();

// Zeek log tools
registerConnectionTools(server, config);
registerDnsTools(server, config);
registerHttpTools(server, config);
registerSslTools(server, config);
registerFileTools(server, config);
registerNoticeTools(server, config);
registerSshTools(server, config);
registerInvestigationTools(server, config);

// Analytics tools
registerBeaconingTools(server, config);
registerAnomalyTools(server, config);

registerResources(server);
registerPrompts(server);

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
