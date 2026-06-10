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

// Simple in-memory cache for investigation results
const investigationCache = new Map<string, { decision: SocDecision; timestamp: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function getCacheKey(request: InvestigationRequest): string {
  return `${request.alert_type}:${request.src_ip}:${request.severity}`;
}

function sanitizeForPrompt(value: string): string {
  return value
    .replace(/[`{}]/g, "")
    .replace(/\b(ignore|disregard|override|bypass)\b/gi, "[REDACTED]")
    .slice(0, 500);
}

export class GeminiSocReasoner {
  constructor(private readonly mcpHub: McpHub) {}

  async investigate(request: InvestigationRequest): Promise<SocDecision> {
    const MAX_INVESTIGATION_MS = 15000;
    const startTime = Date.now();
    const toolResults: string[] = [];

    // Check cache first
    const cacheKey = getCacheKey(request);
    const cached = investigationCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
      logger.info({ cacheKey, ageMs: Date.now() - cached.timestamp }, "Returning cached decision");
      return cached.decision;
    }

    logger.info({ alertId: request.alert_id, alertType: request.alert_type }, "Starting investigation");

    const hasValidKey = config.gemini.apiKey && 
                       config.gemini.apiKey !== "YOUR_GEMINI_API_KEY_HERE" &&
                       config.gemini.apiKey.length > 10;

    if (!hasValidKey) {
      logger.warn("No valid GEMINI_API_KEY configured, using rule-based fallback");
      const decision = this.fallbackDecision(request, toolResults);
      investigationCache.set(cacheKey, { decision, timestamp: Date.now() });
      return decision;
    }

    try {
      const contents: GeminiContent[] = [
        {
          role: "user",
          parts: [{ text: this.buildUserPrompt(request) }],
        },
      ];

      for (let round = 0; round < config.gemini.maxToolRounds; round += 1) {
        const elapsed = Date.now() - startTime;
        if (elapsed > MAX_INVESTIGATION_MS) {
          logger.warn({ elapsedMs: elapsed, maxMs: MAX_INVESTIGATION_MS }, "Investigation timeout reached, using fallback");
          const decision = this.fallbackDecision(request, toolResults);
          investigationCache.set(cacheKey, { decision, timestamp: Date.now() });
          return decision;
        }

        logger.info({ round, elapsedMs: elapsed }, "Calling Gemini API...");
        const response = await this.generateWithRetry(contents);
        logger.info({ round }, "Gemini API call successful");

        const parts = response.candidates?.[0]?.content?.parts ?? [];

        if (parts.length === 0) {
          logger.warn("Gemini returned no content, using fallback");
          throw new Error(response.error?.message ?? "Gemini returned no content.");
        }

        contents.push({ role: "model", parts });

        const functionCalls = parts.filter(
          (part): part is { functionCall: { name: string; args?: Record<string, unknown> } } => 
            "functionCall" in part,
        );

        logger.info({ round, textParts: parts.length - functionCalls.length, functionCalls: functionCalls.length }, "Received response from Gemini");

        if (functionCalls.length === 0) {
          // Final decision received
          const text = parts
            .filter((part): part is { text: string } => "text" in part)
            .map((part) => part.text)
            .join("\n");

          logger.info({ textLength: text.length }, "Parsing final decision from Gemini");
          
          try {
            const parsed = socDecisionSchema.parse(extractJsonObject(text));
            logger.info({ 
              confidence: parsed.confidence, 
              action: parsed.action,
              threatType: parsed.threat_type,
              evidenceCount: parsed.evidence?.length ?? 0
            }, "Decision parsed successfully");
            const decision = this.enforcePolicy(parsed, request);
            investigationCache.set(cacheKey, { decision, timestamp: Date.now() });
            return decision;
          } catch (parseError) {
            logger.error({ error: parseError instanceof Error ? parseError.message : String(parseError) }, "Failed to parse Gemini decision");
            throw parseError;
          }
        }

        // Execute tool calls and capture results
        const toolResponses: GeminiPart[] = [];
        for (const call of functionCalls) {
          logger.info({ tool: call.functionCall.name, round }, "Executing tool call");
          const result = await this.executeFunctionCallWithResult(call.functionCall);
          toolResults.push(`Tool ${call.functionCall.name}: ${result.summary}`);
          toolResponses.push(result.part);
        }

        contents.push({ role: "user", parts: toolResponses });
      }

      throw new Error(`Gemini did not produce a final decision after ${config.gemini.maxToolRounds} tool rounds.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error({ error: message }, "Gemini investigation failed, using fallback");
      const decision = this.fallbackDecision(request, toolResults);
      investigationCache.set(cacheKey, { decision, timestamp: Date.now() });
      return decision;
    }
  }

  private async generateWithRetry(contents: GeminiContent[]): Promise<GeminiResponse> {
    const maxRetries = 2;
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await this.generate(contents);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        const isRateLimit = lastError.message.includes("high demand") || 
                           lastError.message.includes("rate limit") ||
                           lastError.message.includes("429") ||
                           lastError.message.includes("quota") ||
                           lastError.message.includes("temporarily unavailable") ||
                           lastError.message.includes("Resource exhausted") ||
                           lastError.message.includes("exceeded your current quota");
        
        logger.warn({ attempt, error: lastError.message, isRateLimit }, "Gemini API attempt failed");
        
        if (attempt < maxRetries) {
          const delay = isRateLimit ? 5000 : 1000;
          logger.info({ delayMs: delay }, "Retrying Gemini API call");
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }

    throw lastError ?? new Error("Gemini API failed after all retries");
  }

  private async generate(contents: GeminiContent[]): Promise<GeminiResponse> {
    const path = `/v1beta/models/${config.gemini.model}:generateContent?key=${encodeURIComponent(config.gemini.apiKey ?? "")}`;
    const body = JSON.stringify({
      systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
      contents,
      tools: [{ functionDeclarations: this.toGeminiTools(this.mcpHub.listTools()) }],
      generationConfig: { temperature: 0.1, maxOutputTokens: config.gemini.maxTokens },
    });

    const data = await httpsPost("generativelanguage.googleapis.com", path, body, 8000) as GeminiResponse;
    if (data.error?.message) {
      throw new Error(data.error.message);
    }
    return data;
  }

  private async executeFunctionCallWithResult(call: { name: string; args?: Record<string, unknown> }): Promise<{ part: GeminiPart; summary: string }> {
    try {
      const result = await this.mcpHub.callTool(call.name, call.args ?? {});
      const resultStr = stringifyToolResult(result.content);
      return {
        part: {
          functionResponse: {
            name: call.name,
            response: { result: resultStr },
          },
        },
        summary: resultStr.length > 100 ? `${resultStr.slice(0, 100)}...` : resultStr,
      };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      logger.warn({ tool: call.name, error: errMsg }, "MCP tool failed");
      return {
        part: {
          functionResponse: {
            name: call.name,
            response: { error: errMsg },
          },
        },
        summary: `Error: ${errMsg}`,
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
    const sanitized = {
      alert_id: sanitizeForPrompt(request.alert_id),
      src_ip: request.src_ip,
      alert_type: sanitizeForPrompt(request.alert_type),
      rule_id: request.rule_id ? sanitizeForPrompt(request.rule_id) : undefined,
      severity: request.severity,
      timestamp: request.timestamp,
    };

    return JSON.stringify({
      task: "Investigate this security alert and return the final SOC decision JSON.",
      alert: sanitized,
      required_src_ip: request.src_ip,
    }, null, 2);
  }

  private enforcePolicy(decision: SocDecision, request: InvestigationRequest): SocDecision {
    const corrected: SocDecision = { ...decision, src_ip: request.src_ip };

    if (corrected.confidence >= 80) {
      corrected.action = "auto-block";
      if (corrected.recommended_block_duration === "none") {
        corrected.recommended_block_duration = "1h";
      }
    } else if (corrected.confidence >= 40) {
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

  private fallbackDecision(request: InvestigationRequest, toolResults: string[] = []): SocDecision {
    logger.warn({ alertId: request.alert_id, severity: request.severity, toolResultsCount: toolResults.length }, "Using rule-based fallback decision");

    const severity = request.severity ?? 0;
    const alertType = request.alert_type.toLowerCase().trim();

    const mitreTechnique = this.mapAlertToMitre(alertType);
    const mitreTactic = this.mapAlertToTactic(alertType);
    const threatType = this.mapAlertToThreatType(alertType);

    // Build evidence from tool results + fallback message
    const evidence: string[] = [];
    
    if (toolResults.length > 0) {
      evidence.push(...toolResults.slice(0, 6));
    }
    
    evidence.push(`Rule-based fallback applied. Severity: ${severity}, Alert type: ${alertType}.`);
    
    if (severity >= 10) {
      return socDecisionSchema.parse({
        threat_confirmed: true,
        confidence: 85,
        action: "auto-block",
        mitre_technique: mitreTechnique,
        mitre_tactic: mitreTactic,
        src_ip: request.src_ip,
        threat_type: threatType,
        evidence,
        incident_report: `Critical severity ${alertType} alert from ${request.src_ip}. ${toolResults.length > 0 ? 'Some tool results were collected before Gemini API failure.' : 'No tool results available.'} Rule-based analysis with severity ${severity} triggers automatic blocking. MITRE: ${mitreTechnique} (${mitreTactic}).`,
        recommended_block_duration: "24h",
      });
    }
    
    if (severity >= 8) {
      return socDecisionSchema.parse({
        threat_confirmed: true,
        confidence: 75,
        action: "analyst-review",
        mitre_technique: mitreTechnique,
        mitre_tactic: mitreTactic,
        src_ip: request.src_ip,
        threat_type: threatType,
        evidence,
        incident_report: `High severity ${alertType} alert from ${request.src_ip}. ${toolResults.length > 0 ? 'Some tool results were collected before Gemini API failure.' : 'No tool results available.'} Rule-based analysis with severity ${severity} requires analyst review. MITRE: ${mitreTechnique} (${mitreTactic}).`,
        recommended_block_duration: "1h",
      });
    }

    if (severity >= 5) {
      return socDecisionSchema.parse({
        threat_confirmed: true,
        confidence: 60,
        action: "analyst-review",
        mitre_technique: mitreTechnique,
        mitre_tactic: mitreTactic,
        src_ip: request.src_ip,
        threat_type: threatType,
        evidence,
        incident_report: `Medium severity ${alertType} alert from ${request.src_ip}. ${toolResults.length > 0 ? 'Some tool results were collected before Gemini API failure.' : 'No tool results available.'} Rule-based analysis indicates potential threat. MITRE: ${mitreTechnique} (${mitreTactic}).`,
        recommended_block_duration: "none",
      });
    }

    return socDecisionSchema.parse({
      threat_confirmed: false,
      confidence: 30,
      action: "monitor",
      mitre_technique: mitreTechnique,
      mitre_tactic: mitreTactic,
      src_ip: request.src_ip,
      threat_type: threatType,
      evidence,
      incident_report: `Low severity ${alertType} alert from ${request.src_ip}. ${toolResults.length > 0 ? 'Some tool results were collected before Gemini API failure.' : 'No tool results available.'} Rule-based analysis suggests monitoring. MITRE: ${mitreTechnique} (${mitreTactic}).`,
      recommended_block_duration: "none",
    });
  }

  private mapAlertToMitre(alertType: string): string {
    const mapping: Record<string, string> = {
      "ssh-bruteforce": "T1110.001",
      "sql-injection": "T1190",
      "sqli": "T1190",
      "ddos": "T1498",
      "syn-flood": "T1498",
      "c2": "T1071.004",
      "beaconing": "T1071.004",
      "lateral-movement": "T1046",
      "port-scan": "T1046",
      "web-scan": "T1190",
      "xss": "T1189",
      "malware": "T1204.002",
      "suspicious-outbound": "T1041",
      "data-exfiltration": "T1041",
      "dns-tunneling": "T1071.004",
    };
    return mapping[alertType] ?? "T1190";
  }

  private mapAlertToTactic(alertType: string): string {
    const mapping: Record<string, string> = {
      "ssh-bruteforce": "Credential Access",
      "sql-injection": "Initial Access",
      "sqli": "Initial Access",
      "ddos": "Impact",
      "syn-flood": "Impact",
      "c2": "Command and Control",
      "beaconing": "Command and Control",
      "lateral-movement": "Discovery",
      "port-scan": "Discovery",
      "web-scan": "Initial Access",
      "xss": "Initial Access",
      "malware": "Execution",
      "suspicious-outbound": "Exfiltration",
      "data-exfiltration": "Exfiltration",
      "dns-tunneling": "Command and Control",
    };
    return mapping[alertType] ?? "Initial Access";
  }

  private mapAlertToThreatType(alertType: string): string {
    const mapping: Record<string, string> = {
      "ssh-bruteforce": "brute-force",
      "sql-injection": "web-attack",
      "sqli": "web-attack",
      "ddos": "ddos",
      "syn-flood": "ddos",
      "c2": "c2",
      "beaconing": "c2",
      "lateral-movement": "lateral-movement",
      "port-scan": "lateral-movement",
      "web-scan": "web-attack",
      "xss": "web-attack",
      "malware": "c2",
      "suspicious-outbound": "c2",
      "data-exfiltration": "c2",
      "dns-tunneling": "c2",
    };
    return mapping[alertType] ?? "unknown";
  }
}

function ensureGeminiSchema(schema: unknown): Record<string, unknown> {
  if (!schema || typeof schema !== "object") {
    return { type: "object", properties: {} };
  }

  const copy = stripGeminiUnsupported(JSON.parse(JSON.stringify(schema))) as Record<string, unknown>;

  if (copy.type !== "object") {
    copy.type = "object";
  }
  if (!copy.properties || typeof copy.properties !== "object") {
    copy.properties = {};
  }
  return copy;
}

function stripGeminiUnsupported(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(stripGeminiUnsupported);
  if (!node || typeof node !== "object") return node;
  const obj = node as Record<string, unknown>;

  if (Array.isArray(obj.anyOf)) {
    const constVals = (obj.anyOf as unknown[]).filter(
      (i): i is { const: unknown } => typeof i === "object" && i !== null && "const" in i,
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
    if (["$schema", "$defs", "$ref", "not", "if", "then", "else", "unevaluatedProperties"].includes(k))
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
  timeoutMs: number = 8000,
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
        timeout: timeoutMs,
      },
      (res) => {
        let raw = "";
        res.on("data", (chunk: Buffer) => { raw += chunk.toString(); });
        res.on("end", () => {
          try {
            resolve(JSON.parse(raw) as Record<string, unknown>);
          } catch {
            reject(new Error(`Gemini API returned non-JSON (HTTP ${res.statusCode}): ${raw.slice(0, 200)}`));
          }
        });
      },
    );
    
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Gemini API request timed out after ${timeoutMs}ms`));
    });
    
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}
