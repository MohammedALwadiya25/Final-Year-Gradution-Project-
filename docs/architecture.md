# Architecture — AI-Powered SOC Agent NIDS

## Contents

1. [System Overview](#1-system-overview)
2. [Network Topology](#2-network-topology)
3. [5-Layer Pipeline Design](#3-5-layer-pipeline-design)
4. [AI Agent Design](#4-ai-agent-design)
5. [MCP Server Architecture](#5-mcp-server-architecture)
6. [SOAR Integration](#6-soar-integration)
7. [Key Design Decisions](#7-key-design-decisions)
8. [Data Flow — Alert Lifecycle](#8-data-flow--alert-lifecycle)
9. [Academic Contributions](#9-academic-contributions)

---

## 1. System Overview

The project implements a **Wazuh-Primary Hybrid AI Agent** — a two-phase investigation model where Wazuh (the SIEM) is always queried first because it already aggregates and correlates data from both Zeek and Suricata. The agent only queries Zeek and Suricata directly when confidence is ambiguous (40–79%).

This architecture minimises API calls (fast path: 2 MCP servers, ~3 s), reduces false positives (cross-sensor validation), and maintains a human-in-the-loop for uncertain cases (analyst-review action).

**Stack:** pfSense · Zeek · Suricata · Wazuh · n8n · Google Gemini · MCP Servers  
**Network:** VMware Workstation (local) + Azure (cloud) + Tailscale (WireGuard mesh)  
**Languages:** TypeScript (all components), Node.js 20

---

## 2. Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│  LAPTOP (VMware Workstation — Subnet Router via Tailscale)      │
│                                                                 │
│  192.168.80.10  pfSense 2.7 (Firewall / VLAN / SPAN)           │
│  192.168.80.11  Ubuntu 22.04 (Zeek + Suricata)                  │
│  192.168.80.12  Ubuntu 22.04 (All 4 MCP Servers)                │
│  192.168.80.13  Ubuntu 22.04 (DVWA — Attack Target, DMZ)        │
│  192.168.80.14  Windows 10  (Insider Threat Sim)                │
│                                                                 │
│  pfSense VLANs:                                                 │
│    VLAN10 DMZ  → 192.168.80.13                                  │
│    VLAN20 LAN  → 192.168.80.14                                  │
│    VLAN30 MGMT → 192.168.80.11, .12                             │
└─────────────────────────────┬───────────────────────────────────┘
                              │  Tailscale WireGuard
                              │  (laptop advertises 192.168.80.0/24)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  AZURE CLOUD (Tailscale 100.64.0.0/10)                         │
│                                                                 │
│  100.64.0.2  Ubuntu 22.04 (Wazuh SIEM — 4 CPU / 8 GB)          │
│  100.64.0.3  Ubuntu 22.04 (n8n SOAR + AI Agent)                 │
│  100.64.0.4  Kali Linux   (Attacker)                            │
└─────────────────────────────────────────────────────────────────┘
```

**Why Tailscale?**  
Azure VMs must communicate with local VMware VMs. Tailscale provides zero-config WireGuard meshing; the laptop advertises `192.168.80.0/24` as a subnet router so Azure VMs reach all local VMs directly. This eliminates the need for a VPN gateway.

---

## 3. 5-Layer Pipeline Design

### Layer 1 — Capture
pfSense SPAN-mirrors all VLAN traffic to a dedicated interface on the detection VM (`192.168.80.11`). Both Zeek and Suricata share this SPAN interface.

### Layer 2 — Detection (Dual Sensor)

**Zeek (Behavioral):**
- Produces structured logs: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `ssh.log`, `files.log`, etc.
- Excels at *what happened* — connection metadata, protocol parsing, behavioral baselines
- Detects: C2 beaconing, DNS tunneling, data exfiltration, anomalous port usage

**Suricata (Signature):**
- Produces `eve.json` alerts matching loaded rule sets (Emerging Threats + custom rules)
- Excels at *known threats* — malware C2 domains, exploit signatures, known attack patterns
- 5 custom rules cover: SSH brute-force, SQLi, DDoS SYN flood, DNS beaconing, lateral movement

**Design rationale:** Zeek and Suricata are *complementary*, not redundant. Zeek catches unknown behavioral anomalies; Suricata catches known signatures. Cross-sensor validation is a core confidence-building mechanism.

### Layer 3 — Aggregation (Wazuh SIEM)
Wazuh agents on `192.168.80.11` ship both Suricata `eve.json` and Zeek logs to the Wazuh server (`100.64.0.2`). Wazuh applies correlation rules that:
- Combine multi-source signals into single high-confidence alerts
- Map alerts to MITRE ATT&CK via rule tags
- Trigger a webhook to n8n when severity ≥ 12

### Layer 4 — Intelligence (AI Agent + MCP Servers)
The AI agent is a Node.js Express server. It receives the alert from n8n, runs a two-phase investigation, and returns a validated JSON decision.

See [AI Agent Design](#4-ai-agent-design) for detail.

### Layer 5 — Response (n8n SOAR)
n8n receives the agent decision and executes:
- `auto-block` → calls pfSense API to add `src_ip` to the `ai_soc_blocklist` alias
- `analyst-review` → sends Telegram alert; waits for `/approve` or `/deny`
- `monitor` → logs to Wazuh only

---

## 4. AI Agent Design

### Two-Phase Investigation

```
Alert arrives at /investigate
          │
          ▼
    Phase 1 — FAST PATH (always)
    ├── wazuh-mcp: get_alerts(src_ip, 10m)
    ├── wazuh-mcp: search_alerts(src_ip)
    └── mitre-mcp: map_technique(alert_type)
          │
          ▼
    Calculate preliminary confidence
          │
    ┌─────┴──────────────────────┐
    │ confidence 40–79%?         │
    │ YES → Phase 2 — DEEP PATH  │
    │       zeek-mcp tools       │
    │       suricata-mcp tools   │
    │       Recalculate confidence│
    │ NO  → Skip deep path       │
    └─────────────────────────────┘
          │
          ▼
    Final Decision (validated JSON)
    action: auto-block | analyst-review | monitor
```

### Confidence Calculation

Wazuh data factors (Phase 1):
- Multiple rules firing for same `src_ip` → +20
- Alert count > 10 in 10 min → +15
- Multiple destination hosts → +20
- Wazuh severity 10–13 → +25
- Known malicious pattern in rule description → +15
- Only 1 rule, low severity → -20
- Alert count < 3 → -15
- Internal RFC1918 source → -10

Deep-dive adjustment (Phase 2):
- Tools confirm Wazuh data → +15 to +25
- Tools show nothing → -20

### Decision Schema (Zod-validated)

```typescript
{
  threat_confirmed: boolean,
  confidence: number,          // 0–100
  action: "auto-block" | "analyst-review" | "monitor",
  deep_investigation_used: boolean,
  investigation_path: "fast-path" | "deep-path",
  mitre_technique: string,     // e.g. "T1110.001"
  mitre_tactic: string,
  threat_type: "brute-force" | "c2-beacon" | "web-attack" | "lateral-movement" | "ddos" | "unknown",
  src_ip: string,
  affected_hosts: string[],
  alert_count: number,
  wazuh_severity: number,
  evidence: string[],
  recommended_block_duration: "1h" | "24h" | "7d" | "permanent",
  incident_report: string,
  processing_ms: number
}
```

### Why Gemini (not Claude)?
- Native function/tool calling with multi-turn support
- Google AI Studio free tier is suitable for thesis demos
- Removes API cost concern during evaluation
- Architecture is provider-agnostic; swap `GeminiSocReasoner` to use any LLM

### Why Read-Only Mode (`MCP_READONLY=true`)?
- **Safety:** LLMs should recommend, not execute. n8n translates recommendations into real firewall changes
- **Audit trail:** Every agent decision is logged before any enforcement action
- **Thesis principle:** Demonstrates supervised autonomy — a key academic argument

---

## 5. MCP Server Architecture

All four servers follow the same pattern:
- **Transport:** stdio (spawned as child processes by McpHub)
- **Interface:** MCP SDK tools/resources/prompts
- **Validation:** Zod schemas on all tool inputs
- **Format:** TypeScript, compiled to `dist/`

### Tool Counts

| Server | Tools | Design Focus |
|---|---|---|
| zeek-mcp | 25 | Behavioral analysis, streaming TSV/JSON parsers |
| suricata-mcp | 36 | Signature alerts, analytics (DGA, beaconing, exfiltration) |
| wazuh-mcp | 28 | Dual API (REST + OpenSearch), privacy-first output |
| mitre-mcp | 39 | Offline STIX cache, SOC integrations, Navigator export |

### Stdio vs HTTP
MCP servers use stdio transport: the AI agent spawns them as child processes and communicates over stdin/stdout. This provides:
- **Security isolation** — no network port exposure for MCP servers
- **Process lifecycle management** — McpHub handles restart on crash
- **Simplicity** — no authentication layer needed for inter-process communication

---

## 6. SOAR Integration

### n8n Workflow (11 nodes)

```
Webhook (Wazuh alert)
  → Extract Fields
  → Call AI Agent POST /investigate
  → Parse Decision
  → Confidence Switch (≥80 / 40–79 / <40)
  → AbuseIPDB Enrichment (parallel)
  → VirusTotal Enrichment (parallel)
  → Merge Enrichment
  → pfSense Block (auto-block only)  ← calls pfSense REST API
  → Telegram Alert (all paths)
  → Log to Wazuh (all paths)
```

### pfSense Integration
The `ai_soc_blocklist` firewall alias is managed via the pfSense REST API. n8n adds the `src_ip` to the alias and immediately applies the rules. The block is applied within 2–5 seconds of the agent decision.

### Telegram Analyst Approval
For `analyst-review` decisions, the Telegram bot sends an alert with the investigation report and waits for `/approve` or `/deny`. A timeout fallback auto-escalates high-confidence (70–79%) alerts after 5 minutes.

---

## 7. Key Design Decisions

### Why Wazuh-Primary?
Wazuh already aggregates data from both Zeek and Suricata. Querying Wazuh first gives the agent a correlated picture in one call. Querying Zeek and Suricata directly is only needed when that correlated picture is inconclusive. This reduces API calls on the fast path from 4 → 2 and cuts average latency from 8 s to 3 s for clear-cut cases.

### Why Two Phases?
A single-phase approach forces the agent to always call all 4 MCP servers, even for trivial cases (password spray with 200 failures → obvious auto-block). The two-phase design allocates deep investigation only where it matters: ambiguous 40–79% cases. This is analogous to a human analyst first checking the SIEM before digging into raw sensor logs.

### Why Not a Static ML Model?
Traditional NIDS ML models require:
1. Labelled training data for each environment
2. Retraining when traffic patterns change
3. Separate deployment pipeline

The LLM-based agent requires none of these. It reasons from natural language rule descriptions and numerical signal values, making it deployable in any environment without training. This is the core academic novelty of the project.

### Why MITRE ATT&CK?
Every decision is tagged with a MITRE technique. This:
- Provides a standard vocabulary for incident reports
- Enables detection gap analysis (which techniques are not covered?)
- Supports compliance mapping (PCI-DSS, NIST)
- Makes thesis results comparable to published NIDS research

---

## 8. Data Flow — Alert Lifecycle

```
t=0s    Kali Linux launches SSH brute-force against 192.168.80.13

t=2s    Suricata fires SID 9000001 → writes to eve.json

t=3s    Wazuh agent ships eve.json event to Wazuh server (100.64.0.2)

t=5s    Wazuh rule 100001 matches (5 failures in 60s from same IP)
        Wazuh fires webhook → POST http://100.64.0.3:5678/webhook/wazuh-alert

t=5s    n8n receives webhook, calls AI agent:
        POST http://localhost:3000/investigate
        {src_ip: "203.0.113.55", alert_type: "SSH Brute Force", ...}

t=5s    AI Agent Phase 1:
        ├── wazuh-mcp.get_alerts(src_ip)     → 25 alerts, severity 10
        └── mitre-mcp.map_technique(...)     → T1110.001

t=6s    Confidence calculated: 90% → auto-block, fast-path

t=6s    Agent returns:
        {action: "auto-block", confidence: 90, mitre: "T1110.001", ...}

t=7s    n8n:
        ├── AbuseIPDB: 85% abuse score
        ├── VirusTotal: 12/90 engines flagged
        ├── pfSense API: adds 203.0.113.55 to ai_soc_blocklist
        └── Telegram: "🚨 SSH BRUTE FORCE — auto-blocked"

t=8s    pfSense applies block rule → traffic from 203.0.113.55 dropped

MTTR: 8 seconds (vs ~30 minutes human analyst)
```

---

## 9. Academic Contributions

| Contribution | Novelty |
|---|---|
| MCP as SOC intelligence layer | First undergraduate thesis using MCP servers as the reasoning backbone of a NIDS |
| Wazuh-Primary Hybrid model | Architecturally justified two-phase design — Wazuh first, raw sources only when ambiguous |
| LLM replaces static ML | No training data, no retraining cycles — immediately deployable in any environment |
| Cross-sensor validation | Requires Zeek + Suricata + Wazuh agreement — formally reduces FPR vs single-sensor |
| Supervised autonomy | Confidence-threshold human-in-loop design — academically defensible safety argument |
| Tailscale zero trust | WireGuard mesh architecture contribution beyond NIDS |
| Quantitative comparison | AI Agent vs Suricata-only baseline — measurable, defensible, publishable results |
| Open-source-only stack | Zero licensing cost — real-world applicability for SME e-commerce businesses |
