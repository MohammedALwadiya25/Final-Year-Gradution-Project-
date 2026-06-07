# suricata-mcp - Thesis Component

**Architectural Role**: Signature-Based Detection Layer (Layer 2 of 5-layer pipeline)

Suricata MCP is a Model Context Protocol server exposing IDS/IPS detection analysis across 36 tools. It enables AI-powered investigation of signature-based alerts, protocol anomalies, threat intelligence correlation, and advanced analytics—providing LLM reasoning with IDS evidence from Suricata EVE JSON logs.

## Architectural Design

### Detection Role in Pipeline

- **Input**: Suricata EVE JSON alerts from live inspection or PCAP replay
- **Detection logic**: Signature matching (rules) + protocol inspection + IDS analytics
- **Output**: Query results + analytics exposed as MCP tools for AI agent
- **Integration**: Cross-correlates with Zeek NSM for behavioral context
- **Threat intel**: Integrates with MISP (IOC lookup) + TheHive (case creation)

### Why Suricata?

- **High-performance IDS/IPS** - processes 1M+ packets per second
- **EVE JSON output** - standardized, queryable alert format
- **Protocol analysis** - deep inspection of DNS, HTTP, TLS, SSH, FILES
- **Rule management** - dynamic rule enable/disable without restart
- **Live commands** - Unix socket for real-time stats and config
- **PCAP replay** - can re-analyze captured traffic through rules

## Key Design Decisions

### Signature vs Behavioral
- **Signature layer**: Known attack patterns (malware, exploits, C2 domains)
- **Behavioral layer**: Zeek handles anomalies (beaconing, exfiltration)
- **Complementary**: Suricata catches known threats; Zeek catches unknown
- **Thesis evaluation**: Both layers active for defense-in-depth detection

### Streaming Parser for EVE JSON
- **Large file handling**: EVE logs can grow to GB per hour
- **Memory efficiency**: Line-by-line streaming without full load
- **Zod validation**: Each JSON object validated against schema
- **Gzip support**: Handles compressed archived logs automatically

### Advanced Analytics
- **DGA detection**: Shannon entropy on DNS queries
- **C2 beaconing**: Connection interval regularity + jitter scoring
- **Lateral movement**: Detects internal-to-internal scanning
- **Data exfiltration**: Hosts with abnormal outbound data transfer

## Setup for Evaluation

```bash
cd suricata-mcp
npm install
npm run build
```

## Configuration

For thesis evaluation, configure Suricata log locations:

| Variable | Default | Description |
|----------|---------|-------------|
| `SURICATA_EVE_LOG` | `/var/log/suricata/eve.json` | Path to primary EVE JSON log |
| `SURICATA_RULES_DIR` | _(none)_ | Suricata rules directory (optional) |
| `ZEEK_LOGS_DIR` | _(none)_ | Zeek log directory for cross-correlation |
| `SURICATA_MAX_RESULTS` | `1000` | Maximum results per query |

## Running the MCP Server

Suricata MCP runs as a stdio-based server, typically started by the AI SOC Agent via McpHub:

```bash
# For development/testing
SURICATA_EVE_LOG=./test-data/eve.json npm run dev

# For production (started by ai-soc-agent McpHub)
SURICATA_EVE_LOG=/var/log/suricata/eve.json npm run build && node dist/index.js
```

The ai-soc-agent manages stdio connections to all MCP servers automatically.

## Tools Overview

**36 tools** across alert analysis, flow analysis, protocol analysis, rule management, advanced analytics, and Zeek integration:

- **Alert Analysis** (4): Query/summarize alerts, timeline generation
- **Flow Analysis** (2): Search flows, bandwidth statistics
- **Protocol Analysis** (6): DNS, HTTP, TLS/JA3, SSH, file extraction, anomalies
- **Rule Management** (5): Search, stats, create custom rules, toggle, reload
- **Advanced Analytics** (4): Beaconing detection, DGA detection, exfiltration, lateral movement
- **Zeek Integration** (8): Cross-reference with NSM logs
- **Cross-Correlation** (1): Suricata-Zeek correlation
- **Threat Intel** (3): MISP lookup, TheHive case creation
- **PCAP Tools** (3): List, replay, analysis

## Testing

```bash
npm test          # Run all 158 tests
npm run test:watch # Watch mode
```

**Test coverage** (158 tests):
- EVE JSON parser validation and streaming
- Query filters and aggregation
- Advanced analytics (beaconing, DGA, exfiltration, lateral movement)
- Zeek integration and cross-correlation
- PCAP replay orchestration

## Tools

### Suricata Alert Analysis (4 tools)

| Tool | Description |
|------|-------------|
| `suricata_query_alerts` | Search alerts by SID, signature, category, severity, IP, port, protocol, action, time range |
| `suricata_alert_summary` | Aggregated alert statistics grouped by signature, category, severity, source, or destination |
| `suricata_top_alerts` | Top alerts by frequency and severity with unique source/destination counts |
| `suricata_alert_timeline` | Time-bucketed alert counts with severity breakdown |

### Suricata Flow Analysis (2 tools)

| Tool | Description |
|------|-------------|
| `suricata_query_flows` | Search flows by IP, port, protocol, app protocol, bytes, duration, state |
| `suricata_flow_summary` | Top talkers, protocol distribution, bandwidth stats |

### Suricata Protocol Analysis (6 tools)

| Tool | Description |
|------|-------------|
| `suricata_query_dns` | Search DNS queries by name, source IP, record type, response code |
| `suricata_query_http` | Search HTTP transactions by hostname, URL, method, status, user-agent |
| `suricata_query_tls` | Search TLS connections by SNI, JA3/JA4, certificate subject/issuer |
| `suricata_query_ssh` | Search SSH connections by client/server software version |
| `suricata_query_fileinfo` | Search extracted files by name, magic type, hash, size |
| `suricata_query_anomalies` | Search protocol anomalies by type, source/destination IP |

### Suricata Rule Management (5 tools)

| Tool | Description |
|------|-------------|
| `suricata_search_rules` | Search rule files by SID, message, classtype, reference, content |
| `suricata_rule_stats` | Rule set statistics: total, enabled/disabled, by action, by classtype |
| `suricata_create_rule` | Write a custom rule to local.rules |
| `suricata_toggle_rule` | Enable or disable a rule by SID |
| `suricata_reload_rules_docker` | Reload rules via Docker (suricata-update + SIGUSR2) |

### Suricata Engine & Live Commands (3 tools)

| Tool | Description |
|------|-------------|
| `suricata_engine_stats` | Capture, decoder, detect, and flow statistics |
| `suricata_reload_rules` | Live rule reload via Unix socket |
| `suricata_iface_stat` | Interface capture statistics via Unix socket |

### Suricata Investigation (2 tools)

| Tool | Description |
|------|-------------|
| `suricata_investigate_host` | Full host investigation across all event types |
| `suricata_investigate_alert` | Deep alert investigation with correlated flow and protocol data |

### Advanced Analytics (4 tools)

| Tool | Description |
|------|-------------|
| `suricata_beaconing_detection` | Detect C2 beaconing via connection interval analysis with jitter and confidence scoring |
| `suricata_dga_detection` | Detect DGA domains using Shannon entropy analysis on DNS queries |
| `suricata_exfiltration_detection` | Detect hosts with abnormally high outbound data transfer |
| `suricata_lateral_movement_detection` | Detect internal-to-internal scanning on unusual ports |

### Zeek NSM Analysis (8 tools)

| Tool | Description |
|------|-------------|
| `zeek_query_connections` | Search conn.log by IP, port, protocol, service, duration, bytes, state |
| `zeek_query_dns` | Search dns.log by query name, type, rcode |
| `zeek_query_http` | Search http.log by host, URI, method, status, user-agent |
| `zeek_query_ssl` | Search ssl.log by server name, TLS version |
| `zeek_query_files` | Search files.log by filename, MIME type, hash |
| `zeek_query_ssh` | Search ssh.log by client, server, auth success |
| `zeek_query_weird` | Search weird.log for protocol anomalies |
| `zeek_connection_summary` | Top talkers, protocol and service distribution, bandwidth stats |

### Cross-Correlation (1 tool)

| Tool | Description |
|------|-------------|
| `correlate_alert_with_zeek` | Cross-correlate Suricata alerts with Zeek conn/dns/http/ssl logs by IP pair and time window |

### PCAP Management (3 tools)

| Tool | Description |
|------|-------------|
| `pcap_list` | List available PCAP files |
| `pcap_replay_suricata` | Replay a PCAP through Suricata |
| `pcap_replay_zeek` | Replay a PCAP through Zeek |

### Threat Intelligence (3 tools)

| Tool | Description |
|------|-------------|
| `misp_search_ioc` | Search MISP for IOCs (IP, domain, hash) |
| `thehive_create_case` | Create a TheHive case from investigation findings |
| `thehive_create_alert` | Push a Suricata alert to TheHive for triage |

## Resources

| URI | Description |
|-----|-------------|
| `suricata://event-types` | All EVE event types with field descriptions |
| `suricata://stats/current` | Latest engine performance statistics |
| `suricata://rules/summary` | Rule set summary |
| `suricata://config` | Current server configuration (sanitized) |
| `zeek://log-types` | Available Zeek log types with field descriptions |

## Prompts

| Prompt | Description |
|--------|-------------|
| `investigate-alert` | Guided alert investigation workflow |
| `hunt-for-threats` | Proactive threat hunting methodology |
| `incident-response` | Full IR workflow with Suricata + Zeek + TheHive |
| `network-baseline` | Network baseline report generation |
| `daily-alert-report` | Daily alert summary report template |

## Architecture

```
suricata-mcp/
  src/
    index.ts              # MCP server entry, tool registration
    config.ts             # Environment config (Suricata, Zeek, PCAP, MISP, TheHive)
    types.ts              # EVE JSON type definitions
    parser/
      eve.ts              # Streaming EVE JSON parser (supports .gz)
      rules.ts            # Suricata rule file parser
      zeek.ts             # Zeek TSV log parser with header handling
    query/
      engine.ts           # Query engine for EVE files
      filters.ts          # CIDR, wildcard, time range, IP matching
      aggregation.ts      # Statistical aggregation, top-N, numeric stats
      timeline.ts         # Time-bucketed event aggregation
    tools/
      alerts.ts           # Suricata alert analysis
      flows.ts            # Suricata flow analysis
      dns.ts              # Suricata DNS tools
      http.ts             # Suricata HTTP tools
      tls.ts              # Suricata TLS/JA3/JA4 tools
      files.ts            # Suricata file extraction tools
      ssh.ts              # Suricata SSH tools
      anomalies.ts        # Suricata anomaly tools
      rules.ts            # Rule management (search, stats, create, toggle, reload)
      stats.ts            # Engine stats tools
      investigation.ts    # Cross-type investigation
      zeek.ts             # Zeek log query tools (conn, dns, http, ssl, files, ssh, weird)
      pcap.ts             # PCAP list and replay tools
      threatintel.ts      # MISP search + TheHive case/alert creation
      correlation.ts      # Suricata-Zeek cross-correlation
    analytics/
      beaconing.ts        # C2 beacon detection
      dns_entropy.ts      # DGA detection via Shannon entropy
      exfiltration.ts     # Data exfiltration detection
      lateral.ts          # Lateral movement detection + RFC1918 helpers
      ja3.ts              # Known JA3 fingerprint database
    socket/
      client.ts           # Unix socket for live Suricata commands
    resources.ts          # MCP resources
    prompts.ts            # MCP prompts
  tests/
    parser.test.ts        # Parser unit tests
    query.test.ts         # Filter and aggregation tests
    tools.test.ts         # Tool handler integration tests
    zeek.test.ts          # Zeek parser and tool tests
    analytics.test.ts     # Advanced analytics tests
    correlation.test.ts   # Cross-correlation tests
  test-data/
    eve.json              # Sample Suricata EVE JSON data
    sample.rules          # Sample Suricata rules
    conn.log              # Sample Zeek conn.log
    dns.log               # Sample Zeek dns.log
    http.log              # Sample Zeek http.log
    ssl.log               # Sample Zeek ssl.log
    files.log             # Sample Zeek files.log
    ssh.log               # Sample Zeek ssh.log
    weird.log             # Sample Zeek weird.log
  scripts/
    generate-eve.ts       # Mock EVE data generator
```

## Testing

```bash
npm test             # Run all 158 tests
npm run test:watch   # Watch mode
```

## License

MIT
