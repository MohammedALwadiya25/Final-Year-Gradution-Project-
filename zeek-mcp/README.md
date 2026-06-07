# zeek-mcp - Thesis Component

**Architectural Role**: Network Behavior Detection Layer (Layer 2 of 5-layer pipeline)

Zeek MCP is a Model Context Protocol server exposing behavioral network analysis across 25 tools. It enables AI-powered investigation of connection flows, DNS patterns, encrypted protocols, and anomalies—providing LLM reasoning with rich metadata from Zeek Network Security Monitoring logs.

## Architectural Design

### Detection Role in Pipeline

- **Input**: Zeek logs (live or archived) from network tap/SPAN mirror
- **Detection logic**: Statistical + behavioral (connection patterns, DNS entropy, beaconing)
- **Output**: Query results + analytics exposed as MCP tools for AI agent
- **Integration**: Feeds AI SOC Agent with behavioral context for evidence synthesis

### Why Zeek?

- **Full application awareness** - parses 16 log types (DNS, HTTP, SSL/TLS, SSH, DHCP, etc.)
- **Protocol-level intelligence** - extracts URIs, certificate chains, hostnames, IPs
- **Behavioral baselines** - detects beaconing, anomalies, port scans, data exfiltration
- **Cross-reference capability** - follows a connection UID across all logs
- **Scalable** - processes 10,000+ pps on commodity hardware

## Features

- **25 tools** for querying and analyzing Zeek + Suricata logs
- **2 resources** for log type metadata and sensor stats
- **4 prompts** for guided investigation workflows
- **Dual format support** - JSON and TSV (Zeek's native tab-separated format)
- **Suricata integration** - Query eve.json alerts, cross-correlate with Zeek, engine stats
<!-- content-guard: allow private-ipv4 -->
- **CIDR matching** - Filter by IP ranges (10.0.0.0/8, 192.168.1.0/24)
- **IPv6 support** - Full IPv6 CIDR matching
- **Wildcard matching** - Search domains and URIs with patterns (*.evil.com)
- **Beaconing detection** - Statistical C2 beacon analysis with jitter scoring
- **Anomaly detection** - Port scan, data exfiltration, and unusual port detection
- **DNS tunneling detection** - Shannon entropy analysis with encoding detection
- **DHCP asset mapping** - MAC-to-IP/hostname device inventory
- **Compressed log support** - Reads .gz archived logs
- **Date-based rotation** - Navigates Zeek's archived log directories by date

## Key Design Decisions

### Dual Format Support (JSON + TSV)
- **Zeek native format**: TSV (tab-separated) is Zeek's default—requires custom header parsing
- **Modern format**: JSON is more accessible but TSV is native output
- **Format abstraction**: `src/parser/` provides unified interface regardless of format
- **Thesis choice**: Use TSV from live Zeek for evaluation (native format, minimal overhead)

### Parser Architecture
- **Streaming parsers**: Process large log files without loading entire file into memory
- **Format-agnostic query engine**: Filtering logic identical for both JSON and TSV
- **CIDR/wildcard matching**: Encapsulated in `src/query/filters.ts` for reuse

### Analytics Design
- **Beaconing detection**: Interval regularity + jitter analysis (identifies C2 communication)
- **Entropy analysis**: Shannon entropy on DNS queries (detects tunneling/DGA)
- **Anomaly detection**: Statistical detection of port scans, exfiltration, unusual ports
- **DHCP asset mapping**: Correlates MAC → IP → hostname for inventory

## Setup for Evaluation

```bash
cd zeek-mcp
npm install
npm run build
```

## Configuration

For thesis evaluation, configure Zeek log locations:

| Variable | Default | Description |
|----------|---------|-------------||
| `ZEEK_LOG_DIR` | `/opt/zeek/logs/current` | Path to current Zeek logs |
| `ZEEK_LOG_ARCHIVE` | `/opt/zeek/logs` | Path to archived/rotated logs |
| `ZEEK_LOG_FORMAT` | `json` | Log format: `json` or `tsv` (use `tsv` for thesis) |
| `ZEEK_MAX_RESULTS` | `1000` | Maximum results per query |

## Running the MCP Server

Zeek MCP runs as a stdio-based server, typically started by the AI SOC Agent via McpHub:

```bash
# For development/testing
ZEEK_LOG_DIR=./test-data npm run dev

# For production (started by ai-soc-agent McpHub)
ZEEK_LOG_DIR=/var/log/zeek ZEEK_LOG_FORMAT=tsv npm run build && node dist/index.js
```

The ai-soc-agent manages stdio connections to all MCP servers (zeek, suricata, wazuh, mitre) automatically.

## Tools

### Connection Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_connections` | Search connection logs with flexible filters (CIDR, protocol, duration, bytes) |
| `zeek_connection_summary` | Statistical summary: top talkers, services, bytes, connection counts |
| `zeek_long_connections` | Find long-lived connections (potential C2 beacons, tunnels) |

### DNS Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_dns` | Search DNS queries with domain wildcards and response code filtering |
| `zeek_dns_summary` | Top domains, NXDOMAIN counts (DGA detection), query type distribution |
| `zeek_dns_tunneling_check` | Detect DNS tunneling via entropy analysis and encoding detection |

### HTTP Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_http` | Search HTTP requests by host, URI, method, user agent, status code |
| `zeek_suspicious_http` | Find suspicious HTTP: POSTs to IPs, unusual agents, large bodies, base64 in URLs |

### SSL/TLS Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_ssl` | Search SSL/TLS by SNI, version, validation status, certificate fields |
| `zeek_expired_certs` | Find expired, self-signed, or invalid certificates |

### File Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_files` | Search file extractions by MIME type, hash, filename, size |
| `zeek_executable_downloads` | Find executable transfers (PE, ELF, scripts) on the wire |

### Security Notices

| Tool | Description |
|------|-------------|
| `zeek_query_notices` | Search Zeek security notices (port scans, invalid certs, custom alerts) |

### SSH Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_ssh` | Search SSH connections by auth status, direction, client/server |
| `zeek_ssh_bruteforce` | Detect SSH brute force attempts exceeding a failure threshold |

### DHCP & Asset Discovery

| Tool | Description |
|------|-------------|
| `zeek_query_dhcp` | Search DHCP logs for lease assignments and device discovery |
| `zeek_dhcp_asset_map` | Build MAC-to-IP/hostname asset map for network inventory |

### Cross-Log Investigation

| Tool | Description |
|------|-------------|
| `zeek_investigate_host` | Full host investigation across all log types |
| `zeek_investigate_uid` | Follow a connection UID across all log types |

### Software Discovery

| Tool | Description |
|------|-------------|
| `zeek_software_inventory` | List detected software and versions on the network |

### Analytics

| Tool | Description |
|------|-------------|
| `zeek_detect_beaconing` | Detect C2 beaconing by analyzing connection interval regularity and jitter |
| `zeek_detect_anomalies` | Statistical anomaly detection: port scans, data exfiltration, unusual ports |

### Suricata IDS

| Tool | Description |
|------|-------------|
| `suricata_query_alerts` | Search Suricata alerts by signature, severity, IP, protocol, time |
| `suricata_alert_summary` | High-level alert summary: top signatures, categories, IPs, severity distribution |
| `suricata_correlate_zeek` | Cross-reference Suricata alerts with Zeek logs for full context |
| `suricata_eve_stats` | Suricata engine statistics: packets, flows, detection performance |

### Sensor Management

| Tool | Description |
|------|-------------|
| `nids_sensor_status` | Live sensor status: log inventory, sizes, freshness, health checks |

## Resources

| Resource | URI | Description |
|----------|-----|-------------|
| Log Types | `zeek://log-types` | All Zeek log types with field descriptions |
| Stats | `zeek://stats` | Sensor statistics and available log types |

## Prompts

| Prompt | Description |
|--------|-------------|
| `triage-alert` | Triage a Suricata alert by cross-referencing with Zeek logs |
| `investigate-host` | Guided host investigation workflow across all logs |
| `hunt-for-c2` | Threat hunting for C2 communication patterns |
| `network-baseline` | Generate a network activity baseline |

## Supported Log Types

conn, dns, http, ssl, files, notice, weird, x509, smtp, ssh, dpd, software, dhcp, ntp, ocsp, websocket

## Testing

```bash
npm test          # Run all 110 tests
npm run test:watch # Watch mode
```

**Test coverage** (110 tests):
- Parsers: JSON + TSV log parsing, header detection
- Query engine: Filtering, sorting, pagination  
- Analytics: Entropy analysis, beaconing detection, anomaly detection
- Filters: CIDR matching (IPv4+IPv6), wildcard matching, date ranges
- Integration: Full tool handler tests with sample data

### Generate Test Data

```bash
npm run generate-logs
npx tsx scripts/generate-zeek-logs.ts --output=/tmp/zeek-logs --format=json
```

## Project Structure

```
zeek-mcp/
  src/
    index.ts                 # MCP server entry point
    config.ts                # Environment config + validation
    types.ts                 # Zeek log type definitions (16 log types)
    resources.ts             # MCP resources
    prompts.ts               # MCP prompts (4 workflows)
    parser/
      index.ts               # Format-agnostic parser + log resolution
      json.ts                # JSON log parser
      tsv.ts                 # TSV log parser with header detection
    query/
      engine.ts              # Query engine with filtering/sorting
      filters.ts             # CIDR match (v4+v6), wildcard, range operators
      aggregation.ts         # Statistical aggregation functions
    tools/
      connections.ts         # Connection analysis tools
      dns.ts                 # DNS analysis tools
      http.ts                # HTTP analysis tools
      ssl.ts                 # SSL/TLS analysis tools
      files.ts               # File analysis tools
      notices.ts             # Security notice tools
      ssh.ts                 # SSH analysis tools
      investigation.ts       # Cross-log investigation tools
      software.ts            # Software/asset discovery
      dhcp.ts                # DHCP log tools + asset mapping
      beaconing.ts           # Beaconing detection tool
      anomaly.ts             # Anomaly detection tool
      suricata.ts            # Suricata eve.json tools
      sensor.ts              # Sensor status + health checks
    analytics/
      entropy.ts             # Shannon entropy calculation
      beaconing.ts           # Beacon detection algorithms
      anomaly.ts             # Statistical anomaly detection
  tests/
    parser.test.ts           # Parser unit tests (JSON + TSV)
    query.test.ts            # Query engine + filter tests
    analytics.test.ts        # Entropy, beaconing, anomaly tests
    tools.test.ts            # Integration tests with sample data
    suricata.test.ts         # Suricata eve.json parsing tests
    dhcp.test.ts             # DHCP log parsing + asset map tests
    beaconing-tools.test.ts  # Beaconing + anomaly detection tests
    sensor.test.ts           # Sensor status tests
  test-data/                 # Sample Zeek + Suricata logs
  scripts/
    generate-zeek-logs.ts    # Mock data generator
```

## License

MIT
