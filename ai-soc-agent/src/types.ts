import { z } from "zod";

// Custom IP validation for Zod v3 (z.string().ip() is Zod v4 only)
const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;

const ipSchema = z.string().refine(
  (val) => ipv4Regex.test(val) || ipv6Regex.test(val),
  { message: "Invalid IP address format" }
);

export const investigationRequestSchema = z.object({
  alert_id: z.string().min(1),
  src_ip: ipSchema,
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
  mitre_technique: z.string().min(1),
  mitre_tactic: z.string().min(1),
  src_ip: ipSchema,
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