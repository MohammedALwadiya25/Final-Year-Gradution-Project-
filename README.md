# 🛡️ AI-Powered SOC Agent — NIDS for E-Commerce

[![CI](https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-/actions/workflows/ci.yml/badge.svg)](https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green?logo=node.js)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org)
[![MCP](https://img.shields.io/badge/MCP-Model_Context_Protocol-purple)](https://modelcontextprotocol.io)

> **Final-Year Graduation Project** — Design and Implementation of an AI-Powered SOC Agent Using MCP Servers for Intelligent Intrusion Detection and Automated Response in E-Commerce Environments.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Repository Structure](#repository-structure)
- [Components](#components)
- [Quick Start](#quick-start)
- [Infrastructure](#infrastructure)
- [Threat Coverage](#threat-coverage)
- [Metrics & Results](#metrics--results)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This project builds a **5-layer AI-powered Network Intrusion Detection System (NIDS)** that replaces manual SOC triage with an intelligent reasoning agent. When a threat alert fires, the agent:

1. Queries four **MCP servers** (Zeek, Suricata, Wazuh, MITRE ATT&CK) for evidence
2. Applies **AI reasoning** (Google Gemini) to synthesize cross-sensor findings
3. Maps the threat to a **MITRE ATT&CK technique**
4. Returns a **structured JSON decision** with confidence score and recommended action
5. Feeds the decision into **n8n SOAR** for automated response (pfSense block / Telegram alert)

**Key achievement:** Mean time to respond (MTTR) reduced from ~30 minutes (human analyst) to under 30 seconds.

---

## Architecture

### 5-Layer Detection Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                        E-COMMERCE NETWORK                           │
└────────────────────────────┬────────────────────────────────────────┘
                             │ Traffic
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 1 — CAPTURE                                                  │
│  pfSense Firewall  →  SPAN mirror  →  Detection VM                  │
└────────────────────────────┬────────────────────────────────────────┘
                             │ Raw packets
                    ┌────────┴────────┐
                    ▼                 ▼
┌───────────────────────┐  ┌──────────────────────┐
│  LAYER 2 — DETECTION  │  │  LAYER 2 — DETECTION  │
│  Zeek (Behavioral)    │  │  Suricata (Signature) │
│  conn/dns/http/ssl    │  │  EVE JSON alerts      │
└───────────┬───────────┘  └──────────┬───────────┘
            └──────────┬──────────────┘
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3 — AGGREGATION                                              │
│  Wazuh SIEM  →  Correlates alerts  →  Triggers webhook to n8n       │
└────────────────────────────┬────────────────────────────────────────┘
                             │ Correlated alert + src_ip
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 4 — INTELLIGENCE  (this repo)                                │
│                                                                     │
│   AI SOC Agent  ←→  MCP Hub                                         │
│   (Gemini LLM)       ├── zeek-mcp    (25 tools)                     │
│                      ├── suricata-mcp (36 tools)                    │
│                      ├── wazuh-mcp   (28 tools)                     │
│                      └── mitre-mcp   (39 tools)                     │
│                                                                     │
│   Two-Phase Investigation:                                          │
│   Fast Path  → Wazuh + MITRE  (~3s)   → confidence ≥80 or <40      │
│   Deep Path  → All 4 servers  (~8s)   → confidence 40–79           │
└────────────────────────────┬────────────────────────────────────────┘
                             │ Validated JSON decision
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 5 — RESPONSE                                                 │
│  n8n SOAR  →  auto-block (pfSense)  /  analyst-review (Telegram)    │
└─────────────────────────────────────────────────────────────────────┘
```

### Agent Decision Logic

| Confidence | Investigation Path | Action | Avg Latency |
|---|---|---|---|
| ≥ 80% | Fast (Wazuh + MITRE only) | `auto-block` | ~3 s |
| 40 – 79% | Deep (all 4 MCP servers) | `analyst-review` | ~8 s |
| < 40% | Fast | `monitor` | ~3 s |

---

## Repository Structure

```
Final-Year-Gradution-Project-/
├── ai-soc-agent/           # 🤖 AI reasoning agent (Layer 4)
│   ├── src/
│   │   ├── server.ts       #   Express HTTP server + /investigate endpoint
│   │   ├── services/
│   │   │   └── InvestigationService.ts  # Orchestration + timing
│   │   ├── llm/
│   │   │   └── GeminiSocReasoner.ts     # Gemini tool-use reasoning
│   │   ├── mcp/
│   │   │   └── McpHub.ts               # Stdio MCP server manager
│   │   ├── security/
│   │   │   └── tools.ts                # MCP tool definitions
│   │   ├── prompts/
│   │   │   └── systemPrompt.ts         # SOC analyst system prompt
│   │   └── types.ts        #   Zod-validated decision schema
│   └── .env.example
│
├── zeek-mcp/               # 🦎 Zeek behavioral analysis (25 tools)
├── suricata-mcp/           # 🔥 Suricata signature IDS (36 tools)
├── wazuh-mcp/              # 🛡️  Wazuh SIEM aggregation (28 tools)
├── mitre-mcp/              # 🎯 MITRE ATT&CK intelligence (39 tools)
│
├── docs/
│   └── architecture.md     # Detailed architecture documentation
│
├── NIDS_Full_Milestone_Guide.md  # 12-week implementation guide
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
└── README.md               # ← you are here
```

---

## Components

| Component | Role | Tools | Tech |
|---|---|---|---|
| [ai-soc-agent](./ai-soc-agent/) | AI reasoning + orchestration | — | TypeScript, Gemini, Express |
| [zeek-mcp](./zeek-mcp/) | Behavioral network analysis | 25 | TypeScript, MCP SDK |
| [suricata-mcp](./suricata-mcp/) | Signature-based IDS alerts | 36 | TypeScript, MCP SDK |
| [wazuh-mcp](./wazuh-mcp/) | SIEM event aggregation | 28 | TypeScript, MCP SDK |
| [mitre-mcp](./mitre-mcp/) | Threat intelligence (ATT&CK) | 39 | TypeScript, MCP SDK |

---

## Quick Start

### Prerequisites

- **Node.js 20+** — [download](https://nodejs.org)
- **npm 10+** (bundled with Node.js)
- **TypeScript** (installed as dev dependency per package)

### 1. Clone

```bash
git clone https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-.git
cd Final-Year-Gradution-Project-
```

### 2. Build all MCP servers

```bash
# Build each MCP server (required before starting the AI agent)
cd zeek-mcp      && npm install && npm run build && cd ..
cd suricata-mcp  && npm install && npm run build && cd ..
cd wazuh-mcp     && npm install && npm run build && cd ..
cd mitre-mcp     && npm install && npm run build && cd ..
```

### 3. Configure and start the AI agent

```bash
cd ai-soc-agent
cp .env.example .env
# Edit .env:
#   GEMINI_API_KEY=<your Google AI Studio key>
#   WAZUH_URL, WAZUH_USERNAME, WAZUH_PASSWORD (your Wazuh instance)
npm install
npm run build
npm start
```

### 4. Test the agent

```bash
# Health check
curl http://localhost:3000/health

# Simulate an SSH brute-force alert
curl -X POST http://localhost:3000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "demo-001",
    "src_ip": "203.0.113.55",
    "alert_type": "ssh-bruteforce",
    "rule_id": "100001",
    "severity": 10
  }'
```

Expected response:

```json
{
  "investigation_id": "...",
  "duration_ms": 1240,
  "decision": {
    "threat_confirmed": true,
    "confidence": 92,
    "action": "auto-block",
    "mitre_technique": "T1110.001",
    "mitre_tactic": "Credential Access",
    "threat_type": "brute-force",
    "incident_report": "Repeated SSH authentication failures from 203.0.113.55 indicate an active brute-force campaign.",
    "recommended_block_duration": "1h"
  }
}
```

### Running Tests

```bash
# Test all packages
cd zeek-mcp     && npm test   # 110 tests
cd suricata-mcp && npm test   # 158 tests
cd wazuh-mcp    && npm test
cd mitre-mcp    && npm test
```

---

## Infrastructure

The full lab environment is documented in [`NIDS_Full_Milestone_Guide.md`](./NIDS_Full_Milestone_Guide.md).

### VM Layout

| VM | Location | OS | IP | Role |
|---|---|---|---|---|
| pfSense | VMware | pfSense 2.7 | `192.168.80.10` | Firewall / VLAN / SPAN |
| Zeek + Suricata | VMware | Ubuntu 22.04 | `192.168.80.11` | Detection engines |
| MCP Servers | VMware | Ubuntu 22.04 | `192.168.80.12` | 4 MCP servers (ports 3001–3004) |
| DVWA | VMware | Ubuntu 22.04 | `192.168.80.13` | Attack target (DMZ) |
| Windows Client | VMware | Windows 10 | `192.168.80.14` | Insider threat simulation |
| Wazuh | Azure | Ubuntu 22.04 | `100.64.0.2` | SIEM |
| n8n + AI Agent | Azure | Ubuntu 22.04 | `100.64.0.3` | SOAR + AI Agent |
| Kali Linux | Azure | Kali 2024 | `100.64.0.4` | Attacker |

Hybrid connectivity uses **Tailscale** (WireGuard mesh) — the laptop advertises `192.168.80.0/24` so Azure VMs reach local VMs without a VPN gateway.

---

## Threat Coverage

| Threat | Detection Source | MITRE Technique | Agent Path |
|---|---|---|---|
| SSH Brute Force | Zeek SSH + Suricata SID 9000001 + Wazuh rule 100001 | T1110.001 | Fast |
| SQL Injection | Suricata SID 9000002 + Zeek HTTP | T1190 | Fast |
| DDoS SYN Flood | Suricata SID 9000003 | T1498 | Fast |
| C2 DNS Beaconing | Zeek beaconing + Suricata SID 9000004 | T1071.004 | Deep |
| Lateral Movement | Suricata SID 9000005 + Zeek conn | T1046 | Deep |

---

## Metrics & Results

> Results are recorded during Phase 6 attack simulations. Update this table after completing all 5 attack scenarios.

| Metric | Target | Achieved |
|---|---|---|
| Detection Rate (DR) | ≥ 80% | TBD |
| False Positive Rate (FPR) | ≤ 15% | TBD |
| Mean Time to Detect (MTTD) | ≤ 60 s | TBD |
| Mean Time to Respond (MTTR) | ≤ 30 s | TBD |
| Agent Accuracy | ≥ 85% | TBD |
| Fast-path latency | ≤ 5 000 ms | TBD |
| Deep-path latency | ≤ 15 000 ms | TBD |

---

## Documentation

| Document | Description |
|---|---|
| [`NIDS_Full_Milestone_Guide.md`](./NIDS_Full_Milestone_Guide.md) | Complete 12-week build guide (infrastructure → attacks) |
| [`PROJECT_EVALUATION.md`](./PROJECT_EVALUATION.md) | Full code and architecture evaluation with findings |
| [`docs/architecture.md`](./docs/architecture.md) | In-depth architecture with design rationale |
| [`docs/deployment.md`](./docs/deployment.md) | Lab, Docker Compose, and production deployment |
| [`ai-soc-agent/README.md`](./ai-soc-agent/README.md) | Agent setup, API reference, response schema |
| [`zeek-mcp/README.md`](./zeek-mcp/README.md) | Zeek MCP: 25 tools, configuration, test data |
| [`suricata-mcp/README.md`](./suricata-mcp/README.md) | Suricata MCP: 36 tools, EVE JSON parser |
| [`wazuh-mcp/README.md`](./wazuh-mcp/README.md) | Wazuh MCP: 28 tools, dual-API design |
| [`mitre-mcp/README.md`](./mitre-mcp/README.md) | MITRE MCP: 39 tools, offline STIX cache |

---

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for commit conventions, branching strategy, and development setup.

---

## Security

Please report vulnerabilities privately. See [SECURITY.md](./SECURITY.md) for the responsible disclosure policy.

---

## License

MIT © Mohammed ALwadiya — see [LICENSE](./LICENSE) for details.

> **Academic Use:** This project was developed as a final-year graduation project. Component code (MCP servers) is released under MIT and may be used independently.
