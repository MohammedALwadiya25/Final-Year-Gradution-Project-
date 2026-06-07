const blockedWriteWords = [
  "add",
  "apply",
  "block",
  "create",
  "delete",
  "disable",
  "enable",
  "reload",
  "remove",
  "restart",
  "toggle",
  "update",
  "write",
];

const blockedIntegrations = ["thehive", "misp", "cortex"];

const thesisToolAllowlist = new Set([
  "zeek__zeek_query_connections",
  "zeek__zeek_connection_summary",
  "zeek__zeek_long_connections",
  "zeek__zeek_query_dns",
  "zeek__zeek_dns_summary",
  "zeek__zeek_dns_tunneling_check",
  "zeek__zeek_query_http",
  "zeek__zeek_suspicious_http",
  "zeek__zeek_query_ssl",
  "zeek__zeek_query_files",
  "zeek__zeek_query_notices",
  "zeek__zeek_query_ssh",
  "zeek__zeek_ssh_bruteforce",
  "zeek__zeek_investigate_host",
  "zeek__zeek_detect_beaconing",
  "zeek__zeek_detect_anomalies",
  "suricata__suricata_query_alerts",
  "suricata__suricata_alert_summary",
  "suricata__suricata_top_alerts",
  "suricata__suricata_alert_timeline",
  "suricata__suricata_query_flows",
  "suricata__suricata_flow_summary",
  "suricata__suricata_query_dns",
  "suricata__suricata_query_http",
  "suricata__suricata_query_tls",
  "suricata__suricata_query_ssh",
  "suricata__suricata_query_anomalies",
  "suricata__suricata_investigate_host",
  "suricata__suricata_investigate_alert",
  "suricata__suricata_beaconing_detection",
  "suricata__suricata_dga_detection",
  "suricata__suricata_lateral_movement_detection",
  "suricata__suricata_exfiltration_detection",
  "suricata__correlate_alert_with_zeek",
  "wazuh__get_alerts",
  "wazuh__get_alert",
  "wazuh__search_alerts",
  "wazuh__list_agents",
  "wazuh__get_agent",
  "wazuh__get_fim_files",
  "wazuh__list_rules",
  "wazuh__get_rule",
  "wazuh__search_rules",
  "wazuh__diagnose_wazuh_connection",
  "wazuh__get_wazuh_version",
  "mitre__mitre_get_technique",
  "mitre__mitre_search_techniques",
  "mitre__mitre_list_tactics",
  "mitre__mitre_get_tactic",
  "mitre__mitre_map_alert_to_technique",
  "mitre__mitre_technique_overlap",
  "mitre__mitre_attack_path",
  "mitre__mitre_mitigations_for_technique",
  "mitre__mitre_detection_coverage",
]);

export function isToolAllowed(agentToolName: string, originalToolName: string, readonly: boolean): boolean {
  if (!thesisToolAllowlist.has(agentToolName)) return false;
  if (!readonly) return true;

  const normalized = originalToolName.toLowerCase();
  return ![...blockedWriteWords, ...blockedIntegrations].some((word) =>
    normalized.includes(word),
  );
}

export function toAgentToolName(serverId: string, toolName: string): string {
  return `${serverId}__${toolName}`.replace(/[^a-zA-Z0-9_-]/g, "_");
}
