import { randomUUID } from "node:crypto";
import type { GeminiSocReasoner } from "../llm/GeminiSocReasoner.js";
import type { InvestigationRequest, SocDecision } from "../types.js";
import { logger } from "../logger.js";

export type InvestigationResponse = {
  investigation_id: string;
  received_at: string;
  completed_at: string;
  duration_ms: number;
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
      },
      "Investigation started",
    );

    const decision = await this.reasoner.investigate(request);
    const completedAt = Date.now();

    logger.info(
      {
        investigationId,
        action: decision.action,
        confidence: decision.confidence,
        threatType: decision.threat_type,
        durationMs: completedAt - startedAt,
      },
      "Investigation completed",
    );

    return {
      investigation_id: investigationId,
      received_at: new Date(startedAt).toISOString(),
      completed_at: new Date(completedAt).toISOString(),
      duration_ms: completedAt - startedAt,
      decision,
    };
  }
}
