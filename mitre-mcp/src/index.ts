import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { AttackDataStore } from "./data/index.js";
import { registerTechniqueTools } from "./tools/techniques.js";
import { registerTacticTools } from "./tools/tactics.js";
import { registerMitigationTools } from "./tools/mitigations.js";
import { registerDataSourceTools } from "./tools/datasources.js";
import { registerMappingTools } from "./tools/mapping.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

async function main(): Promise<void> {
  const config = loadConfig();

  const server = new McpServer({
    name: "mitre-mcp",
    version: "2.0.0",
    description:
      "MITRE ATT&CK MCP server for technique mapping and detection coverage in the AI SOC Agent project.",
  });

  const store = new AttackDataStore(config);

  // Initialize data store (downloads on first run, uses cache after)
  console.error("Loading ATT&CK data...");
  try {
    await store.initialize();
    const stats = store.getStats();
    console.error(
      `ATT&CK data loaded: ${stats.techniques} techniques, ${stats.groups} groups, ${stats.software} software, ${stats.mitigations} mitigations, ${stats.campaigns} campaigns`,
    );
  } catch (error) {
    console.error(
      `Warning: Failed to load ATT&CK data: ${error instanceof Error ? error.message : String(error)}`,
    );
    console.error("Some tools may not work until data is available.");
  }

  // Register core ATT&CK tools
  registerTechniqueTools(server, store);
  registerTacticTools(server, store);
  registerMitigationTools(server, store);
  registerDataSourceTools(server, store);
  registerMappingTools(server, store);

  // Register resources and prompts
  registerResources(server, store, config);
  registerPrompts(server);

  // Connect to transport
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

  console.error("MITRE ATT&CK MCP server v2.0.0 running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
