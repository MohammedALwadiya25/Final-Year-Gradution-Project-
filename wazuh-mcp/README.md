# wazuh-mcp - Thesis Component

**Architectural Role**: SIEM Aggregation Layer (Layer 3 of 5-layer pipeline)

Wazuh MCP is a Model Context Protocol server exposing SIEM/XDR functionality across 28 tools. It enables AI-powered investigation of aggregated security events, agent inventory, detection rules, compliance mappings, and threat correlations—providing LLM reasoning with centralized security events from Wazuh manager and OpenSearch indexer.

## Architectural Design

### Aggregation Role in Pipeline

- **Input**: Alerts from Zeek + Suricata + system logs (forwarded by Wazuh agents)
- **Correlation**: Rules aggregate multi-source events into higher-confidence alerts
- **Output**: Indexed alerts + rule metadata exposed as MCP tools for AI agent
- **Integration**: Provides centralized event store for investigation and reporting
- **Compliance**: Maps alerts to compliance frameworks (PCI-DSS, GDPR, HIPAA, NIST, MITRE ATT&CK)

### Why Wazuh?

- **Centralized alert aggregation** - collects from agents, Zeek, Suricata, syslog
- **Rule-based correlation** - combines signals into meaningful security events
- **Agent inventory** - OS, packages, processes, ports, open files (FIM)
- **Full-text indexing** - via OpenSearch for fast historical alert queries
- **Compliance mapping** - built-in PCI-DSS, GDPR, HIPAA, NIST associations
- **SCA policies** - security configuration assessment (CIS benchmarks)

## Key Design Decisions

### Dual API Access
- **Wazuh REST API** (port 55000): Manager configuration, rules, decoders, agents
- **OpenSearch Indexer** (port 9200): Alert queries, vulnerabilities, historical data
- **Design**: Separation of control plane (API) and data plane (indexer)
- **JWT auth**: Automatic token refresh on expiry

### Sensitive Output By Default
- **Privacy-first**: Hide IP addresses, command lines, hashes, raw logs by default
- **Explicit opt-in**: Use `include_ip`, `include_full_log`, `include_hashes` to expose
- **Thesis rationale**: Avoid exposing sensitive data in agent output

### Input Validation
- **Pagination bounds**: Enforce limits to prevent resource exhaustion
- **Sort field enumeration**: Only allow fields that exist in each tool
- **ID validation**: Reject unsupported characters in agent IDs, group names
- **Type safety**: Zod schema validation on all tool inputs

## Setup for Evaluation

```bash
cd wazuh-mcp
npm install
npm run build
```

## Configuration

For thesis evaluation, configure Wazuh API and indexer access:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WAZUH_URL` | Yes | - | Wazuh API URL (e.g., `https://10.0.0.2:55000`) |
| `WAZUH_USERNAME` | Yes | - | API username |
| `WAZUH_PASSWORD` | Yes | - | API password |
| `WAZUH_VERIFY_SSL` | No | `false` | Verify SSL (false for self-signed lab) |
| `WAZUH_INDEXER_URL` | No | - | OpenSearch indexer URL (e.g., `https://10.0.0.2:9200`) |
| `WAZUH_INDEXER_USERNAME` | No | `admin` | Indexer username |
| `WAZUH_INDEXER_PASSWORD` | No | - | Indexer password |

## Running the MCP Server

Wazuh MCP runs as a stdio-based server, typically started by the AI SOC Agent via McpHub:

```bash
# For production (started by ai-soc-agent McpHub)
export WAZUH_URL=https://wazuh-manager:55000
export WAZUH_USERNAME=wazuh-wui
export WAZUH_PASSWORD=<your-password>
export WAZUH_INDEXER_URL=https://wazuh-indexer:9200
export WAZUH_INDEXER_USERNAME=admin
export WAZUH_INDEXER_PASSWORD=<indexer-password>

npm run build && node dist/index.js
```

The ai-soc-agent manages stdio connections to all MCP servers automatically.

## Tools Overview

**28 tools** across agent management, alert queries, vulnerability assessment, rules, compliance, and diagnostics:

- **Agents** (3): List agents, get details, check stats
- **Alerts** (3): Get recent, search full-text, get single alert
- **Vulnerabilities** (2): List inventory, search by CVE/package
- **Rules** (3): List, get details, search by description
- **SCA Policies** (2): List policies for agent, get check results
- **System Inventory** (6): OS info, packages, processes, ports, network, hotfixes
- **FIM & Rootcheck** (2): File integrity monitoring, rootkit detection
- **Manager** (2): Manager logs, configuration
- **Groups** (2): List groups, get group members
- **Other** (2): List decoders, get version, diagnose connection

## Testing

```bash
npm test          # Run all tests
npm run test:watch # Watch mode
npm run typecheck  # Type-check TypeScript
```

**Test coverage**:
- Wazuh API client (JWT auth, token refresh)
- OpenSearch indexer client
- Paginated tool responses
- Input validation and error handling

## Configuration

Set the following environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
<!-- content-guard: allow private-ipv4 -->
| `WAZUH_URL` | Yes | - | Wazuh API URL (e.g., `https://10.0.0.2:55000`) |
| `WAZUH_USERNAME` | Yes | - | API username |
| `WAZUH_PASSWORD` | Yes | - | API password |
| `WAZUH_VERIFY_SSL` | No | `false` | Set to `true` to verify SSL certificates. The default is intended for trusted self-signed lab environments only. |
| `WAZUH_TIMEOUT` | No | `30` | Request timeout in seconds. Must be a positive integer. |
| `WAZUH_MCP_MAX_RESPONSE_BYTES` | No | `250000` | Maximum MCP tool response size before returning a truncated preview with metadata. |

Alternative variable names `WAZUH_BASE_URL` and `WAZUH_USER` are also supported.

### Wazuh Indexer (OpenSearch) - Required for Alerts and Vulnerabilities

Wazuh 4.x stores alerts and vulnerability inventory in the Wazuh Indexer (OpenSearch), not the REST API. To enable alert tools (`get_alerts`, `get_alert`, `search_alerts`), vulnerability tools (`list_vulnerabilities`, `search_vulnerabilities`), and the `wazuh://alerts/recent` resource, configure the indexer connection:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
<!-- content-guard: allow private-ipv4 -->
| `WAZUH_INDEXER_URL` | No | - | Wazuh Indexer URL (e.g., `https://10.0.0.2:9200`) |
| `WAZUH_INDEXER_USERNAME` | No | `admin` | Indexer username |
| `WAZUH_INDEXER_PASSWORD` | No | - | Indexer password |
| `WAZUH_INDEXER_VERIFY_SSL` | No | `false` | Set to `true` to verify SSL certificates. The default is intended for trusted self-signed lab environments only. |
| `WAZUH_INDEXER_TIMEOUT` | No | `30` | Indexer request timeout in seconds. Must be a positive integer. |

If `WAZUH_INDEXER_URL` is not set, alert and vulnerability tools will return a helpful configuration message. All other tools (agents, rules, decoders, version) work without the indexer.

When either SSL verification setting is `false`, the server prints a startup warning to stderr. TLS verification is disabled only for that configured Wazuh client.

### Sensitive Output Defaults

Several tools return minimized output by default to avoid exposing raw logs, IPs, command lines, hashes, or raw event payloads unless requested:

| Tool | Hidden by default | Opt-in field |
|------|-------------------|--------------|
| `list_agents`, `get_agent`, `get_group_agents` | Agent IP details | `include_ip: true` |
| `get_alerts`, `search_alerts` | `full_log` | `include_full_log: true` |
| `get_alert` | `full_log`, raw `data` | `include_full_log: true`, `include_raw_data: true` |
| `list_vulnerabilities`, `search_vulnerabilities` | Vulnerability descriptions | `include_description: true` |
| `get_agent_processes` | Process command lines and arguments | `include_command: true` |
| `get_fim_files` | MD5 and SHA-256 hashes | `include_hashes: true` |
| `get_manager_logs` | Full log descriptions | `include_description: true` |
| `get_manager_config` | Secret-like config values | `include_sensitive_config: true` |

### Input Validation

Tool inputs are validated before requests are sent to Wazuh. Pagination is bounded, search text is length-limited, sort fields are enumerated per tool, and path-oriented identifiers such as agent IDs, alert IDs, group IDs, and SCA policy IDs reject unsupported characters.

Paginated tool responses include a `pagination` object with `total`, `limit`, `offset`, and `has_more` fields while preserving the existing top-level `total`, `limit`, and `offset` fields.

Tool responses are capped by `WAZUH_MCP_MAX_RESPONSE_BYTES`. Oversized responses return valid JSON with `output.response_truncated`, byte counts, and a preview instead of flooding the MCP client.

Transient manager `GET` requests and indexer search/readiness requests retry briefly on `429`, `502`, `503`, `504`, and common transient network reset or timeout errors.

## Usage

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "wazuh-mcp",
      "env": {
        "WAZUH_URL": "https://your-wazuh-manager:55000",
        "WAZUH_USERNAME": "wazuh-wui",
        "WAZUH_PASSWORD": "your-password",
        "WAZUH_INDEXER_URL": "https://your-wazuh-indexer:9200",
        "WAZUH_INDEXER_USERNAME": "admin",
        "WAZUH_INDEXER_PASSWORD": "your-indexer-password"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add wazuh \
  --env WAZUH_URL=https://your-wazuh-manager:55000 \
  --env WAZUH_USERNAME=wazuh-wui \
  --env WAZUH_PASSWORD=your-password \
  --env WAZUH_INDEXER_URL=https://your-wazuh-indexer:9200 \
  --env WAZUH_INDEXER_USERNAME=admin \
  --env WAZUH_INDEXER_PASSWORD=your-indexer-password \
  -- wazuh-mcp
```

Add `--scope user` to make it available from any directory instead of only the current project.

### Standalone

```bash
export WAZUH_URL=https://your-wazuh-manager:55000
export WAZUH_USERNAME=wazuh-wui
export WAZUH_PASSWORD=your-password
npm start
```

### Development

```bash
npm run dev    # Watch mode with tsx
npm run lint   # Type checking
npm test       # Run tests
```

## MCP Tools

### Agent Tools

| Tool | Description |
|------|-------------|
| `list_agents` | List all agents with optional status filtering (active, disconnected, never_connected, pending) |
| `get_agent` | Get detailed info for a specific agent by ID |
| `get_agent_stats` | Get CPU, memory, and disk statistics for an agent |

### Alert Tools

| Tool | Description |
|------|-------------|
| `get_alerts` | Retrieve recent alerts with filtering by time range, level, agent, rule, and text search |
| `get_alert` | Retrieve a single alert by ID |
| `search_alerts` | Full-text search across alerts with optional time range filtering |

### Vulnerability Tools

| Tool | Description |
|------|-------------|
| `list_vulnerabilities` | List vulnerability inventory with optional CVE, agent, severity, and package filters |
| `search_vulnerabilities` | Search vulnerability inventory by CVE, package, agent, or description |

### Rule Tools

| Tool | Description |
|------|-------------|
| `list_rules` | List detection rules with level and group filtering |
| `get_rule` | Get full rule details including compliance mappings |
| `search_rules` | Search rules by description text |

### SCA Tools (Security Configuration Assessment)

| Tool | Description |
|------|-------------|
| `get_sca_policies` | List SCA policies and scores for an agent (CIS benchmarks, etc.) |
| `get_sca_checks` | Get individual check results with remediation steps and compliance mappings |

### Syscollector Tools (System Inventory)

| Tool | Description |
|------|-------------|
| `get_agent_os` | Get OS information (name, version, architecture, hostname) |
| `get_agent_packages` | List installed software packages with versions |
| `get_agent_processes` | List running processes with PIDs and command lines |
| `get_agent_ports` | List open network ports with associated processes |
| `get_agent_network` | List network interfaces and IP addresses |
| `get_agent_hotfixes` | List installed Windows hotfixes/patches |

### FIM & Rootcheck Tools

| Tool | Description |
|------|-------------|
| `get_fim_files` | Get File Integrity Monitoring results (files, registry keys, hashes) |
| `get_rootcheck` | Get rootkit detection scan findings |

### Manager Tools

| Tool | Description |
|------|-------------|
| `get_manager_logs` | Get Wazuh manager logs filtered by level and module |
| `get_manager_config` | Get active manager configuration by section with secret-like values redacted by default |

### Group Tools

| Tool | Description |
|------|-------------|
| `list_groups` | List all agent groups |
| `get_group_agents` | List agents in a specific group |

### Other Tools

| Tool | Description |
|------|-------------|
| `list_decoders` | List log decoders with optional name filtering |
| `get_wazuh_version` | Get Wazuh manager version and API info |
| `diagnose_wazuh_connection` | Check sanitized configuration, URL/TLS settings, manager auth/version, and indexer readiness |

## MCP Resources

| Resource URI | Description |
|-------------|-------------|
| `wazuh://agents` | All registered agents and their status |
| `wazuh://alerts/recent` | 25 most recent security alerts |
| `wazuh://rules/summary` | Detection rules sorted by severity |

## MCP Prompts

| Prompt | Description |
|--------|-------------|
| `investigate-alert` | Step-by-step alert investigation with MITRE mapping and remediation |
| `agent-health-check` | Comprehensive agent health assessment (status, resources, alerts) |
| `security-overview` | Full environment security summary with compliance coverage |

## Examples

### List active agents

```
Use list_agents with status "active" to see all connected agents.
```

### Investigate a brute force attempt

```
Search alerts for "brute force" and investigate the top result,
including the MITRE ATT&CK technique and remediation steps.
```

### Check agent health

```
Run an agent health check on agent 001 - check its connection status,
resource usage, and any recent critical alerts.
```

### Find high-severity rules

```
List all rules with level 12 or higher to see critical detection rules
and their compliance framework mappings.
```

## Testing

```bash
npm test               # Run all tests
npm run typecheck      # Type-check TypeScript
npm audit --omit=dev   # Audit production dependencies
npm run pack:check     # Verify package contents
npm run test:watch     # Watch mode
```

Tests use mocked Wazuh API responses - no live Wazuh instance needed.

## Project Structure

```
wazuh-mcp/
├── src/
│   ├── index.ts           # MCP server entry point
│   ├── config.ts          # Environment configuration
│   ├── client.ts          # Wazuh REST API client (JWT auth)
│   ├── indexer-client.ts  # Wazuh Indexer (OpenSearch) client
│   ├── types.ts           # TypeScript type definitions
│   ├── resources.ts       # MCP resource handlers
│   ├── prompts.ts         # MCP prompt templates
│   └── tools/
│       ├── agents.ts      # Agent management tools
│       ├── alerts.ts      # Alert query tools
│       ├── rules.ts       # Rule query tools
│       ├── decoders.ts    # Decoder listing tool
│       ├── version.ts     # Version info tool
│       ├── sca.ts         # Security Configuration Assessment
│       ├── syscollector.ts # System inventory (OS, packages, ports, etc.)
│       ├── syscheck.ts    # File Integrity Monitoring
│       ├── rootcheck.ts   # Rootkit detection
│       ├── manager.ts     # Manager logs and configuration
│       └── groups.ts      # Agent group management
├── tests/
│   ├── client.test.ts     # API client unit tests
│   └── tools.test.ts      # Tool handler unit tests
├── package.json
├── tsconfig.json
├── tsup.config.ts
└── vitest.config.ts
```

## License

MIT
