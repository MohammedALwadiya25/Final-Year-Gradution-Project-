import { z } from "zod";

export const investigationRequestSchema = z.object({
  alert_id: z.string().min(1),
  src_ip: z.union([z.ipv4(), z.ipv6()]),
  alert_type: z.string().min(1),
  rule_id: z.string().optional(),
  severity: z.number().int().min(0).max(15).optional(),
  timestamp: z.string().optional(),
  raw_alert: z.unknown().optional(),
});

export type InvestigationRequest = z.infer<typeof investigationRequestSchema>;

export const socDecisionSchema = z.object({
  threat_confirmed: z.boolean(),
  confidence: z.number().int().min(0).max(100),
  action: z.enum(["auto-block", "analyst-review", "monitor"]),
  mitre_technique: z.string().regex(/^T\d{4}(?:\.\d{3})?$|^unknown$/),
  mitre_tactic: z.string().min(1),
  src_ip: z.union([z.ipv4(), z.ipv6()]),
  threat_type: z.enum(["brute-force", "c2", "lateral-movement", "web-attack", "ddos", "unknown"]),
  evidence: z.array(z.string().min(1)).min(1).max(8),
  incident_report: z.string().min(20).max(1600),
  recommended_block_duration: z.enum(["none", "1h", "24h", "7d", "permanent"]),
});

export type SocDecision = z.infer<typeof socDecisionSchema>;

export type McpToolDefinition = {
  serverId: string;
  serverDisplayName: string;
  originalName: string;
  agentToolName: string;
  description: string;
  inputSchema: unknown;
};

export type AgentToolResult = {
  tool: string;
  result: unknown;
};
