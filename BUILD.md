# Build from Scratch — AI SOC Agent NIDS

Complete guide to clone, configure, build, and run the project on a fresh machine.

---

## Prerequisites

| Tool | Required Version | Check |
|------|-----------------|-------|
| Node.js | ≥ 20.0.0 | `node --version` |
| npm | ≥ 10.0.0 | `npm --version` |
| Git | any | `git --version` |

> **Wazuh lab** (for full functionality): a running Wazuh 4.x manager + Wazuh Indexer (OpenSearch).  
> **Gemini API key** (free): get one at [aistudio.google.com](https://aistudio.google.com).

---

## Repository Structure

```
Final-Year-Gradution-Project-/
├── zeek-mcp/          # Zeek NSM log analysis MCP server (Layer 1 — behavioral)
├── suricata-mcp/      # Suricata IDS log analysis MCP server (Layer 2 — signature)
├── wazuh-mcp/         # Wazuh SIEM MCP server (Layer 3 — aggregation)
├── mitre-mcp/         # MITRE ATT&CK MCP server (Layer 4 — threat intel)
├── ai-soc-agent/      # AI SOC Agent — orchestrates all 4 MCP servers via Gemini
├── scripts/
│   └── setup.sh       # One-shot build script
└── package.json       # Workspace root
```

---

## Step 1 — Clone the Repo

```bash
git clone https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-.git
cd Final-Year-Gradution-Project-
```

---

## Step 2 — Build Everything (One Command)

The setup script installs dependencies and builds all 5 packages in order:

```bash
bash scripts/setup.sh
```

This does:
1. Checks Node.js ≥ 20
2. Runs `npm install && npm run build` in each of: `zeek-mcp`, `suricata-mcp`, `wazuh-mcp`, `mitre-mcp`, `ai-soc-agent`
3. Creates `ai-soc-agent/.env` from `.env.example` if it doesn't exist

> **Or build manually** (one package at a time):
> ```bash
> for pkg in zeek-mcp suricata-mcp wazuh-mcp mitre-mcp ai-soc-agent; do
>   cd $pkg && npm install && npm run build && cd ..
> done
> ```

After the build, each MCP package will have a `dist/index.js` file:
```
zeek-mcp/dist/index.js
suricata-mcp/dist/index.js
wazuh-mcp/dist/index.js
mitre-mcp/dist/index.js
ai-soc-agent/dist/server.js
```

---

## Step 3 — Configure the Agent

Edit `ai-soc-agent/.env` (created automatically by setup.sh):

```bash
nano ai-soc-agent/.env
```

### Required settings

```env
# ── Gemini AI (required) ─────────────────────────────────────────
GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE
GEMINI_MODEL=gemini-2.5-flash
AI_MAX_TOKENS=1600
AGENT_MAX_TOOL_ROUNDS=8

# ── Wazuh SIEM (required for alert tools) ────────────────────────
WAZUH_URL=https://<your-wazuh-ip>:55000
WAZUH_USERNAME=wazuh-admin
WAZUH_PASSWORD=YOUR_WAZUH_PASSWORD
WAZUH_VERIFY_SSL=false

# ── Wazuh Indexer / OpenSearch (required for alert queries) ──────
WAZUH_INDEXER_URL=https://<your-wazuh-ip>:9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=YOUR_INDEXER_PASSWORD
WAZUH_INDEXER_VERIFY_SSL=false

# ── Sensor log paths ─────────────────────────────────────────────
ZEEK_LOG_DIR=/opt/zeek/logs/current
ZEEK_LOG_FORMAT=tsv
SURICATA_EVE_LOG=/var/log/suricata/eve.json
```

### Optional / defaults you can leave as-is

```env
NODE_ENV=development
PORT=3000
LOG_LEVEL=info
MCP_READONLY=true          # agent can investigate but not write/block
MITRE_MATRICES=enterprise  # ATT&CK matrix to load

# MCP server paths — no change needed unless you moved dist/ files
ZEEK_MCP_COMMAND=node
ZEEK_MCP_ARGS=../zeek-mcp/dist/index.js
SURICATA_MCP_COMMAND=node
SURICATA_MCP_ARGS=../suricata-mcp/dist/index.js
WAZUH_MCP_COMMAND=node
WAZUH_MCP_ARGS=../wazuh-mcp/dist/index.js
MITRE_MCP_COMMAND=node
MITRE_MCP_ARGS=../mitre-mcp/dist/index.js
```

> **Important:** Never commit `ai-soc-agent/.env` — it's in `.gitignore`.

---

## Step 4 — Start the Agent

```bash
cd ai-soc-agent
npm start
```

Expected startup output:
```
{"level":"info","service":"ai-soc-agent","msg":"Connected MCP server","server":"zeek","allowedTools":16}
{"level":"info","service":"ai-soc-agent","msg":"Connected MCP server","server":"suricata","allowedTools":13}
{"level":"info","service":"ai-soc-agent","msg":"Connected MCP server","server":"wazuh","allowedTools":11}
{"level":"info","service":"ai-soc-agent","msg":"Connected MCP server","server":"mitre","allowedTools":9}
{"level":"info","service":"ai-soc-agent","msg":"AI SOC Agent started","port":3000}
```

---

## Step 5 — Verify

### Health check
```bash
curl http://localhost:3000/health
```
Expected:
```json
{
  "status": "ok",
  "service": "ai-soc-agent",
  "ai_provider": "gemini",
  "model": "gemini-2.5-flash",
  "readonly_mcp": true,
  "tools": 49
}
```

### List available tools
```bash
curl http://localhost:3000/tools | python3 -m json.tool | head -40
```

### Smoke test (MCP connectivity only, no Gemini call)
```bash
cd ai-soc-agent
npm run smoke
```

---

## Step 6 — Send an Investigation Request

```bash
curl -s -X POST http://localhost:3000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "1234",
    "src_ip": "192.168.1.105",
    "alert_type": "SSH brute force attempt",
    "rule_id": "5710",
    "severity": 10
  }' | python3 -m json.tool
```

The agent will:
1. Query Wazuh for matching alerts
2. Map to MITRE ATT&CK technique
3. Cross-reference with Zeek/Suricata if confidence is inconclusive
4. Return a structured decision

Example response:
```json
{
  "investigation_id": "a1b2c3d4-...",
  "received_at": "2026-06-07T10:00:00.000Z",
  "completed_at": "2026-06-07T10:00:08.421Z",
  "duration_ms": 8421,
  "decision": {
    "threat_confirmed": true,
    "confidence": 85,
    "action": "auto-block",
    "mitre_technique": "T1110.001",
    "mitre_tactic": "credential-access",
    "src_ip": "192.168.1.105",
    "threat_type": "brute-force",
    "evidence": ["22 failed SSH attempts in 60s", "Wazuh rule 5710 triggered", "Zeek ssh_bruteforce: 22 failures from 192.168.1.105"],
    "incident_report": "Host 192.168.1.105 performed an SSH brute force attack...",
    "recommended_block_duration": "24h"
  }
}
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Server status, model, tool count |
| `/tools` | GET | Full list of allowed MCP tools |
| `/investigate` | POST | Submit an alert for AI investigation |

### `/investigate` request schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alert_id` | string | ✅ | Unique alert identifier |
| `src_ip` | string | ✅ | Source IPv4 or IPv6 address |
| `alert_type` | string | ✅ | Human-readable alert description |
| `rule_id` | string | ❌ | Wazuh rule ID (e.g. `"5710"`) |
| `severity` | number 0–15 | ❌ | Wazuh alert level |
| `timestamp` | ISO string | ❌ | Alert timestamp |
| `raw_alert` | any | ❌ | Full raw alert payload |

---

## MCP Servers Overview

Each MCP server runs as a **stdio child process** — the agent spawns them on startup. You never run them directly.

| Server | Tools | Data Source | Key Capabilities |
|--------|-------|-------------|-----------------|
| `zeek-mcp` | 16 | Zeek logs (TSV/JSON) | Connections, DNS, HTTP, SSL, SSH, beaconing, anomaly detection |
| `suricata-mcp` | 13 | `eve.json` | Alerts, flows, DNS, HTTP, TLS, SSH, DGA detection, C2 beaconing, lateral movement |
| `wazuh-mcp` | 11 | Wazuh REST API + OpenSearch | Agents, alerts, FIM, rules, MITRE mapping, compliance |
| `mitre-mcp` | 9 | STIX 2.1 bundle (cached) | Technique lookup, tactic mapping, alert-to-technique, mitigations |

### MITRE ATT&CK data download

On first run, `mitre-mcp` downloads the STIX 2.1 bundle from MITRE (~15 MB) and caches it at `~/.mitre-mcp/data`. Subsequent starts use the cache. Set `MITRE_UPDATE_INTERVAL=86400` to auto-refresh every 24 h.

---

## Environment Variables — Full Reference

### `ai-soc-agent/.env`

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | — | **Required.** Get free at aistudio.google.com |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Model to use |
| `AI_MAX_TOKENS` | `1600` | Max tokens per response |
| `AGENT_MAX_TOOL_ROUNDS` | `8` | Max tool calls per investigation |
| `MCP_READONLY` | `true` | Block write/action tools |
| `PORT` | `3000` | HTTP server port |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `WAZUH_URL` | — | Wazuh manager API URL |
| `WAZUH_USERNAME` | — | Wazuh API username |
| `WAZUH_PASSWORD` | — | Wazuh API password |
| `WAZUH_VERIFY_SSL` | `false` | Set `true` in production |
| `WAZUH_INDEXER_URL` | — | OpenSearch URL |
| `WAZUH_INDEXER_USERNAME` | `admin` | Indexer username |
| `WAZUH_INDEXER_PASSWORD` | — | Indexer password |
| `ZEEK_LOG_DIR` | `/opt/zeek/logs/current` | Live Zeek logs directory |
| `ZEEK_LOG_FORMAT` | `json` | `tsv` (native Zeek) or `json` |
| `SURICATA_EVE_LOG` | `/var/log/suricata/eve.json` | Suricata EVE JSON log path |
| `MITRE_MATRICES` | `enterprise` | `enterprise`, `mobile`, or `ics` |
| `MITRE_DATA_DIR` | `~/.mitre-mcp/data` | STIX bundle cache directory |

---

## Troubleshooting

### Agent fails to start: `No MCP tools were discovered`
All 4 MCP servers failed to connect. Check that you built each package first:
```bash
ls zeek-mcp/dist/index.js suricata-mcp/dist/index.js wazuh-mcp/dist/index.js mitre-mcp/dist/index.js
```
If any are missing, re-run `bash scripts/setup.sh`.

### `GEMINI_API_KEY is required`
You haven't set the key in `ai-soc-agent/.env`. Get a free key at [aistudio.google.com](https://aistudio.google.com).

### Wazuh alerts return empty
The alert tools (`get_alerts`, `search_alerts`) need `WAZUH_INDEXER_URL`. Without it the agent still works but skips alert queries:
```
error: "Alerts require WAZUH_INDEXER_URL configuration."
```

### `npm ci` fails with `missing package-lock.json`
This is a known issue with npm workspaces — use `npm install` instead:
```bash
cd <package> && npm install && npm run build
```

### TypeScript errors during build
Make sure Node.js is ≥ 20. The project uses `"ignoreDeprecations": "6.0"` in `tsconfig.json` for TypeScript 6 compatibility.

### MITRE data not loading
First-run download requires internet access. The cache lives at `~/.mitre-mcp/data`. To force a re-download, delete the cache:
```bash
rm -rf ~/.mitre-mcp/data
```

---

## Run Tests

```bash
# mitre-mcp — 70 tests, all passing
cd mitre-mcp && npm test

# suricata-mcp — core analytics tests pass; some tool stubs pending
cd suricata-mcp && npm test

# wazuh-mcp — most tests pass; decoders/SCA stubs pending
cd wazuh-mcp && npm test

# zeek-mcp — core parser/query/analytics tests pass; some stubs pending
cd zeek-mcp && npm test
```

---

## Development Mode

Run any MCP server in watch mode (auto-recompile on save):
```bash
cd zeek-mcp && npm run dev
cd suricata-mcp && npm run dev
cd wazuh-mcp && npm run dev
cd mitre-mcp && npm run dev
```

Run the agent in watch mode:
```bash
cd ai-soc-agent && npm run dev
```

---

## Project Architecture

```
Alert (from Wazuh / n8n)
        │
        ▼
  POST /investigate
        │
        ▼
  InvestigationService
        │
        ▼
  GeminiSocReasoner  ◄──── Gemini 2.5 Flash
        │                       │
        │    ┌──────────────────┤
        │    │  tool calls      │
        ▼    ▼                  │
      McpHub (stdio)            │
   ┌──┬──┬──┬──┐               │
   │  │  │  │  │               │
  zeek sur waz mit             │
  mcp  mcp mcp mcp             │
        │                      │
        └──── results ─────────┘
        │
        ▼
  SocDecision (JSON)
  {threat_confirmed, confidence, action, mitre_technique, ...}
```

**Investigation flow:**
1. Wazuh context first → MITRE ATT&CK mapping
2. If confidence 40–79 → drill into Zeek / Suricata
3. confidence ≥ 80 → `auto-block` | 40–79 → `analyst-review` | < 40 → `monitor`
4. n8n (external) reads the decision and performs the actual block action
