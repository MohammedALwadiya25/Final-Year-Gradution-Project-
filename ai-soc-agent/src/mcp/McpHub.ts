import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type {
  CallToolResult,
  ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import type { McpToolDefinition } from "../types.js";
import { isToolAllowed, toAgentToolName } from "../security/tools.js";

type ServerConfig = (typeof config.mcp.servers)[number];

type ConnectedServer = {
  id: string;
  displayName: string;
  client: Client;
  transport: StdioClientTransport;
};

export class McpHub {
  private readonly servers = new Map<string, ConnectedServer>();
  private readonly tools = new Map<string, McpToolDefinition>();
  private readonly failedServers: string[] = [];

  async connect(): Promise<void> {
    for (const serverConfig of config.mcp.servers) {
      try {
        await this.connectOne(serverConfig);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logger.warn(
          { server: serverConfig.id, error: message },
          "MCP server failed to connect, skipping"
        );
        this.failedServers.push(serverConfig.id);
      }
    }

    if (this.tools.size === 0) {
      throw new Error(
        "No MCP tools were discovered. Build the MCP repos and check .env paths.",
      );
    }

    if (this.failedServers.length > 0) {
      logger.warn(
        { failedServers: this.failedServers, availableServers: Array.from(this.servers.keys()) },
        "Some MCP servers failed to connect. Agent will operate with reduced capabilities."
      );
    }
  }

  listTools(): McpToolDefinition[] {
    return [...this.tools.values()];
  }

  getFailedServers(): string[] {
    return [...this.failedServers];
  }

  async callTool(
    agentToolName: string,
    input: unknown,
  ): Promise<CallToolResult> {
    const definition = this.tools.get(agentToolName);
    if (!definition) {
      throw new Error(`Unknown or blocked MCP tool: ${agentToolName}`);
    }

    const server = this.servers.get(definition.serverId);
    if (!server) {
      throw new Error(`MCP server is not connected: ${definition.serverId}`);
    }

    logger.info(
      {
        server: definition.serverId,
        tool: definition.originalName,
      },
      "Calling MCP tool",
    );

    return (await server.client.callTool({
      name: definition.originalName,
      arguments:
        input && typeof input === "object"
          ? (input as Record<string, unknown>)
          : {},
    })) as CallToolResult;
  }

  async close(): Promise<void> {
    await Promise.allSettled(
      [...this.servers.values()].map(async (server) => {
        await server.client.close();
        await server.transport.close();
      }),
    );
  }

  private async connectOne(serverConfig: ServerConfig): Promise<void> {
    const childEnv = {
      ...process.env,
      ...Object.fromEntries(
        Object.entries(serverConfig.env).filter(
          ([, value]) => value !== undefined,
        ),
      ),
    } as Record<string, string>;

    const transport = new StdioClientTransport({
      command: serverConfig.command,
      args: serverConfig.args,
      env: childEnv,
    });

    const client = new Client({
      name: "ai-soc-agent",
      version: "1.0.0",
    });

    await client.connect(transport);

    this.servers.set(serverConfig.id, {
      id: serverConfig.id,
      displayName: serverConfig.displayName,
      client,
      transport,
    });

    const listed = (await client.listTools()) as ListToolsResult;
    let allowedCount = 0;

    for (const tool of listed.tools ?? []) {
      const agentToolName = toAgentToolName(serverConfig.id, tool.name);
      if (!isToolAllowed(agentToolName, tool.name, config.mcp.readonly))
        continue;
      this.tools.set(agentToolName, {
        serverId: serverConfig.id,
        serverDisplayName: serverConfig.displayName,
        originalName: tool.name,
        agentToolName,
        description: `[${serverConfig.displayName}] ${tool.description ?? tool.name}`,
        inputSchema: sanitizeSchema(tool.inputSchema),
      });
      allowedCount += 1;
    }

    logger.info(
      {
        server: serverConfig.id,
        allowedTools: allowedCount,
        readonly: config.mcp.readonly,
      },
      "Connected MCP server",
    );
  }
}

function sanitizeSchema(schema: unknown): unknown {
  if (!schema || typeof schema !== "object") {
    return { type: "object", properties: {} };
  }
  const copy = JSON.parse(JSON.stringify(schema)) as Record<string, unknown>;
  delete copy.$schema;
  return stripUnsupported(copy);
}

/**
 * Gemini does not support JSON Schema keywords: `const`, `$defs`, `$ref`,
 * `if/then/else`, `not`, `unevaluatedProperties`.
 * Zod v4 emits `anyOf: [{const: X}, ...]` for enum members — convert those
 * to a flat `enum` array, and strip any remaining bare `const` nodes.
 */
function stripUnsupported(node: unknown): unknown {
  if (Array.isArray(node)) {
    return node.map(stripUnsupported);
  }
  if (!node || typeof node !== "object") {
    return node;
  }

  const obj = node as Record<string, unknown>;

  // Convert anyOf:[{const:X},{const:Y},...] → enum:[X,Y,...] for strings,
  // or → plain type for numbers (Gemini enum only works with type:string).
  if (Array.isArray(obj.anyOf)) {
    const constValues = (obj.anyOf as unknown[]).filter(
      (item): item is { const: unknown } =>
        typeof item === "object" && item !== null && "const" in item,
    );
    if (constValues.length === obj.anyOf.length && constValues.length > 0) {
      const values = constValues.map((i) => i.const);
      const allStrings = values.every((v) => typeof v === "string");
      const result: Record<string, unknown> = allStrings
        ? { type: "string", enum: values }
        : { type: "integer" };
      if (obj.description) result.description = obj.description;
      return result;
    }
  }

  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    if (
      key === "$schema" ||
      key === "$defs" ||
      key === "$ref" ||
      key === "not" ||
      key === "if" ||
      key === "then" ||
      key === "else" ||
      key === "unevaluatedProperties"
    ) {
      continue;
    }
    if (key === "const") {
      // bare const — turn into enum for strings, plain type for numbers
      if (typeof val === "string") {
        out.type = "string";
        out.enum = [val];
      } else {
        out.type = "integer";
      }
      continue;
    }
    out[key] = stripUnsupported(val);
  }
  return out;
}