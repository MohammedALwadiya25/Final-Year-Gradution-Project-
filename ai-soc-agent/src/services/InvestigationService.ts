import { randomUUID } from "node:crypto";
import type { GeminiSocReasoner } from "../llm/GeminiSocReasoner.js";
import type { InvestigationRequest, SocDecision } from "../types.js";
import { logger } from "../logger.js";

export type InvestigationResponse = {
  investigation_id: string;
  received_at: string;
  completed_at: string;
  duration_ms: number;
  investigation_path: "fast" | "deep" | "fallback";
  deep_investigation_used: boolean;
  gemini_available: boolean;
  decision: SocDecision;
};

export class InvestigationService {
  constructor(private readonly reasoner: GeminiSocReasoner) {}

  async investigate(request: InvestigationRequest): Promise<InvestigationResponse> {
    const startedAt = Date.now();
    const investigationId = randomUUID();

    logger.info(
      {
        investigationId,
        alertId: request.alert_id,
        srcIp: request.src_ip,
        alertType: request.alert_type,
        severity: request.severity,
      },
      "Investigation started",
    );

    let decision: SocDecision;
    let investigationPath: "fast" | "deep" | "fallback" = "fast";
    let deepInvestigationUsed = false;
    let geminiAvailable = true;

    try {
      decision = await this.reasoner.investigate(request);
      
      // Determine path based on duration and tool usage
      const duration = Date.now() - startedAt;
      if (duration > 8000) {
        investigationPath = "deep";
        deepInvestigationUsed = true;
      } else if (duration < 2000) {
        investigationPath = "fallback";
        geminiAvailable = false;
      }
    } catch (error) {
      // This shouldn't happen with fallback mode, but just in case
      logger.error({ error: error instanceof Error ? error.message : String(error) }, "Investigation failed unexpectedly");
      throw error;
    }

    const completedAt = Date.now();

    logger.info(
      {
        investigationId,
        action: decision.action,
        confidence: decision.confidence,
        threatType: decision.threat_type,
        durationMs: completedAt - startedAt,
        path: investigationPath,
        geminiAvailable,
      },
      "Investigation completed",
    );

    return {
      investigation_id: investigationId,
      received_at: new Date(startedAt).toISOString(),
      completed_at: new Date(completedAt).toISOString(),
      duration_ms: completedAt - startedAt,
      investigation_path: investigationPath,
      deep_investigation_used: deepInvestigationUsed,
      gemini_available: geminiAvailable,
      decision,
    };
  }
}