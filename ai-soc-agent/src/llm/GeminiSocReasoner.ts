import https from "node:https";
import { config } from "../config.js";
import { logger } from "../logger.js";
import type { McpHub } from "../mcp/McpHub.js";
import { SYSTEM_PROMPT } from "../prompts/systemPrompt.js";
import type {
  InvestigationRequest,
  McpToolDefinition,
  SocDecision,
} from "../types.js";
import { socDecisionSchema } from "../types.js";
import { extractJsonObject, stringifyToolResult } from "../utils/json.js";

type GeminiPart =
  | { text: string }
  | { functionCall: { name: string; args?: Record<string, unknown> } }
  | { functionResponse: { name: string; response: Record<string, unknown> } };

type GeminiContent = {
  role: "user" | "model";
  parts: GeminiPart[];
};

type GeminiResponse = {
  candidates?: Array<{
    content?: {
      parts?: GeminiPart[];
    };
  }>;
  error?: {
    message?: string;
  };
};

export class GeminiSocReasoner {
  constructor(private readonly mcpHub: McpHub) {}

  async investigate(request: InvestigationRequest): Promise<SocDecision> {
    if (!config.gemini.apiKey) {
      throw new Error("GEMINI_API_KEY is required when AI_PROVIDER=gemini.");
    }

    const contents: GeminiContent[] = [
      {
        role: "user",
        parts: [{ text: this.buildUserPrompt(request) }],
      },
    ];

    for (let round = 0; round < config.gemini.maxToolRounds; round += 1) {
      const response = await this.generate(contents);
      const parts = response.candidates?.[0]?.content?.parts ?? [];

      if (parts.length === 0) {
        throw new Error(
          response.error?.message ?? "Gemini returned no content.",
        );
      }

      contents.push({ role: "model", parts });

      const functionCalls = parts.filter(
        (
          part,
        ): part is {
          functionCall: { name: string; args?: Record<string, unknown> };
        } => "functionCall" in part,
      );

      if (functionCalls.length === 0) {
        const text = parts
          .filter((part): part is { text: string } => "text" in part)
          .map((part) => part.text)
          .join("\n");

        const parsed = socDecisionSchema.parse(extractJsonObject(text));
        return this.enforcePolicy(parsed, request);
      }

      const toolResponses: GeminiPart[] = [];
      for (const call of functionCalls) {
        toolResponses.push(await this.executeFunctionCall(call.functionCall));
      }

      contents.push({
        role: "user",
        parts: toolResponses,
      });
    }

    throw new Error(
      `Gemini did not produce a final decision after ${config.gemini.maxToolRounds} tool rounds.`,
    );
  }

  private async generate(contents: GeminiContent[]): Promise<GeminiResponse> {
    const path = `/v1beta/models/${config.gemini.model}:generateContent?key=${encodeURIComponent(config.gemini.apiKey ?? "")}`;
    const body = JSON.stringify({
      systemInstruction: {
        parts: [{ text: SYSTEM_PROMPT }],
      },
      contents,
      tools: [
        {
          functionDeclarations: this.toGeminiTools(this.mcpHub.listTools()),
        },
      ],
      generationConfig: {
        temperature: 0.1,
        maxOutputTokens: config.gemini.maxTokens,
      },
    });

    const data = (await httpsPost(
      "generativelanguage.googleapis.com",
      path,
      body,
    )) as GeminiResponse;
    if (data.error?.message) {
      throw new Error(data.error.message);
    }
    return data;
  }

  private async executeFunctionCall(call: {
    name: string;
    args?: Record<string, unknown>;
  }): Promise<GeminiPart> {
    try {
      const result = await this.mcpHub.callTool(call.name, call.args ?? {});
      return {
        functionResponse: {
          name: call.name,
          response: {
            result: stringifyToolResult(result.content),
          },
        },
      };
    } catch (error) {
      logger.warn(
        {
          tool: call.name,
          error: error instanceof Error ? error.message : String(error),
        },
        "MCP tool failed",
      );

      return {
        functionResponse: {
          name: call.name,
          response: {
            error: error instanceof Error ? error.message : String(error),
          },
        },
      };
    }
  }

  private toGeminiTools(tools: McpToolDefinition[]) {
    return tools.map((tool) => ({
      name: tool.agentToolName,
      description: tool.description,
      parameters: ensureGeminiSchema(tool.inputSchema),
    }));
  }

  private buildUserPrompt(request: InvestigationRequest): string {
    return JSON.stringify(
      {
        task: "Investigate this security alert and return the final SOC decision JSON.",
        alert: request,
        required_src_ip: request.src_ip,
      },
      null,
      2,
    );
  }

  private enforcePolicy(
    decision: SocDecision,
    request: InvestigationRequest,
  ): SocDecision {
    const corrected: SocDecision = {
      ...decision,
      src_ip: request.src_ip,
    };

    if (corrected.confidence >= 80) {
      corrected.action = "auto-block";
      if (corrected.recommended_block_duration === "none") {
        corrected.recommended_block_duration = "1h";
      }
    } else if (corrected.confidence >= 50) {
      corrected.action = "analyst-review";
      if (corrected.recommended_block_duration === "permanent") {
        corrected.recommended_block_duration = "24h";
      }
    } else {
      corrected.action = "monitor";
      corrected.threat_confirmed = false;
      corrected.recommended_block_duration = "none";
    }

    return socDecisionSchema.parse(corrected);
  }
}

function ensureGeminiSchema(schema: unknown): Record<string, unknown> {
  if (!schema || typeof schema !== "object") {
    return { type: "object", properties: {} };
  }

  const copy = stripGeminiUnsupported(
    JSON.parse(JSON.stringify(schema)),
  ) as Record<string, unknown>;

  if (copy.type !== "object") {
    copy.type = "object";
  }
  if (!copy.properties || typeof copy.properties !== "object") {
    copy.properties = {};
  }
  return copy;
}

/** Mirror of McpHub.stripUnsupported — keeps GeminiSocReasoner self-contained. */
function stripGeminiUnsupported(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(stripGeminiUnsupported);
  if (!node || typeof node !== "object") return node;
  const obj = node as Record<string, unknown>;

  if (Array.isArray(obj.anyOf)) {
    const constVals = (obj.anyOf as unknown[]).filter(
      (i): i is { const: unknown } =>
        typeof i === "object" && i !== null && "const" in i,
    );
    if (constVals.length === obj.anyOf.length && constVals.length > 0) {
      const values = constVals.map((i) => i.const);
      const allStrings = values.every((v) => typeof v === "string");
      const result: Record<string, unknown> = allStrings
        ? { type: "string", enum: values }
        : { type: "integer" };
      if (obj.description) result.description = obj.description;
      return result;
    }
  }

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (
      [
        "$schema",
        "$defs",
        "$ref",
        "not",
        "if",
        "then",
        "else",
        "unevaluatedProperties",
      ].includes(k)
    )
      continue;
    if (k === "const") {
      if (typeof v === "string") {
        out.type = "string";
        out.enum = [v];
      } else {
        out.type = "integer";
      }
      continue;
    }
    out[k] = stripGeminiUnsupported(v);
  }
  return out;
}

function httpsPost(
  hostname: string,
  path: string,
  body: string,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname,
        path,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let raw = "";
        res.on("data", (chunk: Buffer) => {
          raw += chunk.toString();
        });
        res.on("end", () => {
          try {
            resolve(JSON.parse(raw) as Record<string, unknown>);
          } catch {
            reject(
              new Error(
                `Gemini API returned non-JSON (HTTP ${res.statusCode}): ${raw.slice(0, 200)}`,
              ),
            );
          }
        });
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}
