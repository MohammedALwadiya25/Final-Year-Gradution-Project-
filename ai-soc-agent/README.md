# AI SOC Agent - Thesis Component

**Architectural Role**: Intelligence layer (Layer 5 of 5-layer pipeline)

The AI SOC Agent is the reasoning engine that orchestrates detection, aggregation, and intelligence systems. It receives alerts from n8n, queries threat context across four MCP servers, applies AI reasoning to evidence, and returns validated decisions for policy enforcement.

## Architectural Design

### 5-Layer Detection Pipeline

1. **Capture** → pfSense SPAN mirrors traffic
2. **Detection** → Zeek behavioral + Suricata signatures  
3. **Aggregation** → Wazuh SIEM correlates alerts
4. **Intelligence** → **This Agent** reasons through evidence
5. **Response** → n8n orchestrates pfSense firewall actions

### Agent Architecture

```
HTTP Alert (n8n) 
    ↓
InvestigationService (timing, logging, orchestration)
    ↓
MCP Hub (stdio connections to 4 servers)
    ├→ zeek-mcp (25 tools: network behavior, beaconing, anomaly detection)
    ├→ suricata-mcp (36 tools: signature alerts, flow analysis, DGA detection)
    ├→ wazuh-mcp (28 tools: SIEM alerts, agent inventory, compliance mapping)
    └→ mitre-mcp (39 tools: threat framework, technique mapping, SOC integration)
    ↓
GeminiSocReasoner (Google Gemini Flash)
    ├→ Tool calling (agent queries MCP servers)
    ├→ Evidence synthesis (correlates findings)
    └→ Decision validation (JSON schema enforcement)
    ↓
Validated SocDecision (monitor | analyst-review | auto-block)
    ↓
Response to n8n (for policy enforcement)
```

## Key Design Decisions

### Why MCP (Model Context Protocol)?
- **Abstraction layer** between investigation logic and data sources
- **Tool-agnostic** - can swap Zeek for Suricata, Wazuh for Splunk
- **Stdio-based** - secure isolation, no network exposure
- **Standard interface** - tools/resources/prompts are formal contracts

### Why Read-Only Mode (`MCP_READONLY=true`)?
- **Thesis/demo default** - AI agent cannot modify network configs
- **Security principle** - LLM generates recommendations only
- **Policy enforcement separation** - n8n controls actual firewall changes
- **Audit trail** - all agent decisions logged before execution

### Why Gemini API?
- **Tool use capability** - native support for MCP tool calling
- **Evidence reasoning** - LLM excels at correlating security signals
- **JSON validation** - Zod schema enforces decision structure
- **Free-tier friendly** - Google AI Studio/Gemini is suitable for thesis demos
- **Scalability** - external API removes compute load from edge

## Setup for Evaluation

```bash
cd ai-soc-agent
copy .env.example .env
npm install
npm run build
```

Configure environment:

```bash
# MCP servers must be built first
cd ../zeek-mcp && npm install && npm run build
cd ../suricata-mcp && npm install && npm run build
cd ../wazuh-mcp && npm install && npm run build
cd ../mitre-mcp && npm install && npm run build
cd ../ai-soc-agent

# Configure AI provider (use free Gemini for thesis)
AI_PROVIDER=gemini
GEMINI_API_KEY=<from google ai studio>
GEMINI_MODEL=gemini-2.5-flash

# Run in read-only thesis mode (default)
MCP_READONLY=true
npm run dev
```

## Investigation Request Example

```bash
curl -X POST http://localhost:3000/investigate -H "Content-Type: application/json" \
  -d '{
    "alert_id": "demo-001",
    "src_ip": "192.168.80.99",
    "alert_type": "ssh-bruteforce",
    "rule_id": "100001",
    "severity": 10
  }'
```

Agent will:
1. Query zeek-mcp for connection patterns (beaconing analysis)
2. Query suricata-mcp for alert context and rule details
3. Query wazuh-mcp for alert history and threat correlation
4. Query mitre-mcp for ATT&CK technique mapping
5. Synthesize evidence via Gemini
6. Return decision: `{status, decision, technique, confidence, recommendation}`

## Response Schema

The `/investigate` endpoint returns metadata plus a validated SOC decision:

```json
{
  "investigation_id": "uuid",
  "received_at": "2026-06-07T10:00:00.000Z",
  "completed_at": "2026-06-07T10:00:01.250Z",
  "duration_ms": 1250,
  "decision": {
    "threat_confirmed": true,
    "confidence": 92,
    "action": "auto-block",
    "mitre_technique": "T1110.001",
    "mitre_tactic": "Credential Access",
    "src_ip": "203.0.113.55",
    "threat_type": "brute-force",
    "evidence": [
      "25 failed SSH attempts in 2 minutes",
      "Wazuh rule severity 10 matched SSH brute-force behavior"
    ],
    "incident_report": "Repeated SSH authentication failures indicate a likely brute-force attempt.",
    "recommended_block_duration": "1h"
  }
}
```
