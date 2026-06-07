# mitre-mcp - Thesis Component

**Architectural Role**: Threat Intelligence & Framework Layer (Layer 4 of 5-layer pipeline)

MITRE ATT&CK MCP is a Model Context Protocol server providing comprehensive access to the MITRE ATT&CK knowledge base across 39 tools. It enables AI-powered investigation of threat techniques, tactic navigation, threat actor profiling, detection coverage analysis, and SOC stack integration—providing LLM reasoning with threat framework context.

## Architectural Design

### Intelligence Role in Pipeline

- **Input**: Alerts + observables from Zeek, Suricata, Wazuh
- **Mapping**: Map alerts to ATT&CK techniques + tactics
- **Enrichment**: Profile threat actors, techniques, software
- **Output**: MITRE ATT&CK insights exposed as MCP tools for AI agent
- **SOC Integration**: Enrich Wazuh alerts, TheHive cases, MISP events
- **Navigator**: Generate attack heatmaps and coverage maps

### Why MITRE ATT&CK?

- **Standard framework** - industry-standard threat taxonomy (250+ techniques)
- **Coverage analysis** - assess detection capability across known techniques
- **Attribution** - threat actor profiling and technique overlap analysis
- **Kill chain** - organize techniques from initial access through impact
- **Compliance mapping** - correlate detection rules to frameworks (PCI, NIST)
- **Offline capable** - STIX bundle cached locally after first download

## Key Design Decisions

### Offline-First Architecture
- **STIX 2.1 bundles**: Download once, cache locally (`~/.mitre-mcp/data`)
- **Auto-update**: Configurable refresh interval (default 24h)
- **No API rate limits**: All queries use cached data after first sync
- **Thesis benefit**: Evaluation lab may lack internet; cache ensures availability

### STIX Bundle Parsing
- **Enterprise, Mobile, ICS**: Support three MITRE matrices
- **Campaign objects**: Parse STIX campaigns for threat actor analysis
- **Relationship navigation**: Map techniques ↔ tactics ↔ groups ↔ software
- **Indexing**: Build queryable index for 100+ attributes per technique

### SOC Stack Integration
- **Wazuh rules**: Map Wazuh detection rules to techniques
- **TheHive cases**: Enrich cases with mitigations and investigation tasks
- **Cortex analyzers**: Map analyzers to data sources for coverage
- **MISP events**: Extract techniques from galaxies and attributes

## Setup for Evaluation

```bash
cd mitre-mcp
npm install
npm run build
```

## Configuration

For thesis evaluation, core MITRE configuration only:

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_DATA_DIR` | `~/.mitre-mcp/data` | Local cache directory for STIX bundles |
| `MITRE_MATRICES` | `enterprise` | Matrices: `enterprise`, `mobile`, `ics` |
| `MITRE_UPDATE_INTERVAL` | `86400` | Auto-update check (seconds, default 24h) |

Optional SOC integrations (for advanced features):
- `WAZUH_URL`, `WAZUH_USERNAME`, `WAZUH_PASSWORD` - for Wazuh rule mapping
- `THEHIVE_URL`, `THEHIVE_API_KEY` - for case enrichment
- `CORTEX_URL`, `CORTEX_API_KEY` - for analyzer coverage
- `MISP_URL`, `MISP_API_KEY` - for event correlation

## Running the MCP Server

MITRE MCP runs as a stdio-based server, typically started by the AI SOC Agent via McpHub:

```bash
# For production (started by ai-soc-agent McpHub)
MITRE_MATRICES=enterprise npm run build && node dist/index.js
```

The ai-soc-agent manages stdio connections to all MCP servers automatically.

## Tools Overview

**39 tools** across technique lookup, tactic navigation, threat actor profiling, campaign analysis, and SOC integration:

- **Techniques** (2): Get technique details, search by keyword/tactic/platform
- **Tactics** (2): List all tactics, get tactic with techniques
- **Threat Groups** (3): Get group details, search, list all
- **Software** (2): Get software details, search by name/type
- **Mitigations** (3): Get mitigation, find for technique, search
- **Data Sources** (2): Get data source, analyze detection coverage
- **Mapping** (3): Map alert to technique, find technique overlap, attack paths
- **Data Management** (2): Force update, get version info
- **Campaigns** (4): Build campaign profile, get campaign, list, search
- **Navigator Export** (1): Generate ATT&CK Navigator layers
- **Wazuh Integration** (4): Manager status, map alert, rule coverage, get alerts
- **TheHive Integration** (3): Enrich case, create case, list cases
- **Cortex Integration** (2): Analyzer coverage, run analyzers
- **MISP Integration** (4): Map event, search indicators, create event, list events
- **Cross-Stack** (2): SOC status, cross-correlate across platforms

## Testing

```bash
npm test          # Run all tests
npm run test:watch # Watch mode
npm run lint       # Type-check
```

**Test coverage**:
- STIX bundle parsing and indexing
- Technique/tactic/group queries
- Mapping and correlation logic
- Campaign profile generation
- Navigator layer export

## Configuration

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_DATA_DIR` | `~/.mitre-mcp/data` | Local cache directory for STIX bundles |
| `MITRE_MATRICES` | `enterprise` | Comma-separated matrices: `enterprise`, `mobile`, `ics` |
| `MITRE_UPDATE_INTERVAL` | `86400` | Auto-update check interval in seconds (default 24h) |

### SOC Integration (all optional)

| Variable | Description |
|----------|-------------|
| `WAZUH_URL` | Wazuh API URL (e.g., `https://wazuh.example.internal:55000`) |
| `WAZUH_USERNAME` | Wazuh API username (default: `wazuh-wui`) |
| `WAZUH_PASSWORD` | Wazuh API password |
| `WAZUH_VERIFY_SSL` | Verify SSL certs (default: `true`, set `false` for self-signed) |
| `THEHIVE_URL` | TheHive URL (e.g., `http://thehive.example.internal:9000`) |
| `THEHIVE_API_KEY` | TheHive API key |
| `CORTEX_URL` | Cortex URL (e.g., `http://cortex.example.internal:9001`) |
| `CORTEX_API_KEY` | Cortex API key |
| `MISP_URL` | MISP URL (e.g., `https://misp.example.internal`) |
| `MISP_API_KEY` | MISP API key (authkey) |
| `MISP_VERIFY_SSL` | Verify SSL certs (default: `true`, set `false` for self-signed) |

## Usage

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "mitre-attack": {
      "command": "mitre-mcp",
      "env": {
        "MITRE_MATRICES": "enterprise",
        "WAZUH_URL": "https://wazuh.example.internal:55000",
        "WAZUH_USERNAME": "wazuh-wui",
        "WAZUH_PASSWORD": "your-password",
        "WAZUH_VERIFY_SSL": "false",
        "THEHIVE_URL": "http://thehive.example.internal:9000",
        "THEHIVE_API_KEY": "your-api-key",
        "CORTEX_URL": "http://cortex.example.internal:9001",
        "CORTEX_API_KEY": "your-api-key",
        "MISP_URL": "https://misp.example.internal",
        "MISP_API_KEY": "your-api-key",
        "MISP_VERIFY_SSL": "false"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add mitre-attack \
  --env MITRE_MATRICES=enterprise \
  -- mitre-mcp
```

Add `--scope user` to make it available from any directory instead of only the current project. Add `--env` flags for any SOC integrations (Wazuh, TheHive, Cortex, MISP) you want to enable.

### Standalone

```bash
npm run start
```

### Development

```bash
npm run dev
```

## Tool Reference

### Core ATT&CK Tools (19)

#### Technique Lookup

| Tool | Description |
|------|-------------|
| `mitre_get_technique` | Get full details of a technique by ID (T1059, T1059.001) |
| `mitre_search_techniques` | Search techniques by keyword, tactic, platform, data source |

#### Tactic Navigation

| Tool | Description |
|------|-------------|
| `mitre_list_tactics` | List all tactics in kill-chain order |
| `mitre_get_tactic` | Get tactic details with all associated techniques |

#### Threat Group Intelligence

| Tool | Description |
|------|-------------|
| `mitre_get_group` | Get group details including techniques and software used |
| `mitre_search_groups` | Search groups by keyword or technique usage |
| `mitre_list_groups` | List all known threat groups |

#### Software & Malware

| Tool | Description |
|------|-------------|
| `mitre_get_software` | Get software details with techniques and associated groups |
| `mitre_search_software` | Search software by name, technique, or type (malware/tool) |

#### Mitigation Mapping

| Tool | Description |
|------|-------------|
| `mitre_get_mitigation` | Get mitigation details with addressed techniques |
| `mitre_mitigations_for_technique` | Get all mitigations for a specific technique |
| `mitre_search_mitigations` | Search mitigations by keyword |

#### Detection & Data Sources

| Tool | Description |
|------|-------------|
| `mitre_get_datasource` | Get data source details with detectable techniques |
| `mitre_detection_coverage` | Analyze detection coverage based on available data sources |

#### Mapping & Correlation

| Tool | Description |
|------|-------------|
| `mitre_map_alert_to_technique` | Map security alerts to likely ATT&CK techniques |
| `mitre_technique_overlap` | Find technique overlap between groups for attribution |
| `mitre_attack_path` | Generate possible attack paths through the kill chain |

#### Data Management

| Tool | Description |
|------|-------------|
| `mitre_update_data` | Force update of the local ATT&CK data cache |
| `mitre_data_version` | Get current data version and object counts |

### Campaign Tools (4)

| Tool | Description |
|------|-------------|
| `mitre_campaign_profile` | Build a technique profile with group/software/campaign matching |
| `mitre_get_campaign` | Get campaign details with techniques, software, and groups |
| `mitre_list_campaigns` | List all known ATT&CK campaigns |
| `mitre_search_campaigns` | Search campaigns by keyword or technique |

### Navigator Layer Export (1)

| Tool | Description |
|------|-------------|
| `mitre_navigator_layer` | Generate ATT&CK Navigator JSON layers (coverage, group, campaign, diff) |

### Wazuh Integration (4)

| Tool | Description |
|------|-------------|
| `mitre_wazuh_status` | Wazuh manager status, agents, and rule stats |
| `mitre_map_wazuh_alert` | Map Wazuh alerts to ATT&CK techniques by rule ID/description/groups |
| `mitre_wazuh_rule_coverage` | Analyze Wazuh rules mapped to ATT&CK techniques |
| `mitre_wazuh_alerts` | Fetch recent alerts enriched with ATT&CK context |

### TheHive Integration (3)

| Tool | Description |
|------|-------------|
| `mitre_thehive_enrich` | Enrich a TheHive case with ATT&CK techniques and mitigations |
| `mitre_thehive_create_case` | Create a case pre-populated with ATT&CK context |
| `mitre_thehive_list_cases` | List cases with ATT&CK technique filtering |

### Cortex Integration (2)

| Tool | Description |
|------|-------------|
| `mitre_cortex_analyzer_coverage` | Map Cortex analyzers to ATT&CK data sources |
| `mitre_cortex_run_analyzers` | Run analyzers on observables with ATT&CK context |

### MISP Integration (4)

| Tool | Description |
|------|-------------|
| `mitre_misp_event_to_attack` | Map MISP event attributes/galaxies to ATT&CK |
| `mitre_misp_search_indicators` | Search MISP IOCs by technique or group |
| `mitre_misp_create_event` | Create events pre-tagged with ATT&CK techniques |
| `mitre_misp_list_events` | List events with ATT&CK enrichment |

### Cross-Stack Correlation (2)

| Tool | Description |
|------|-------------|
| `mitre_soc_status` | Connection status for all SOC integrations |
| `mitre_cross_correlate` | Search for techniques across Wazuh, TheHive, and MISP simultaneously |

## Resource Reference

| URI | Description |
|-----|-------------|
| `mitre://matrix/enterprise` | Full Enterprise ATT&CK matrix (tactics x techniques) |
| `mitre://version` | Current data version and statistics |
| `mitre://tactics` | All tactics in kill-chain order |

## Prompt Reference

| Prompt | Description |
|--------|-------------|
| `map-incident-to-attack` | Map incident observables to ATT&CK techniques |
| `threat-hunt-plan` | Generate a threat hunting plan |
| `gap-analysis` | Perform detection gap analysis |
| `attribution-analysis` | Assist with threat attribution |

## Examples

### Check SOC integration status

```
Use mitre_soc_status to check which SOC platforms are connected.
```

### Map a Wazuh alert to ATT&CK

```
Use mitre_map_wazuh_alert with ruleId 5710 and ruleGroups ["sshd", "authentication_failed"]
to find matching ATT&CK techniques.
```

### Create an ATT&CK-enriched TheHive case

```
Use mitre_thehive_create_case with title "Suspected APT28 Activity",
techniques ["T1059.001", "T1566.001", "T1078"] and severity 3
to create a case with ATT&CK context, mitigations, and investigation tasks.
```

### Generate a Navigator coverage layer

```
Use mitre_navigator_layer with mode "coverage" and
dataSources ["Process", "Network Traffic", "File"]
to generate a heatmap of detection coverage.
```

### Cross-correlate across the SOC stack

```
Use mitre_cross_correlate with techniques ["T1059.001", "T1566.001"]
to search for related alerts in Wazuh, cases in TheHive, and events in MISP.
```

### Map a MISP event to ATT&CK

```
Use mitre_misp_event_to_attack with eventId "1"
to extract ATT&CK techniques from MISP galaxies and attributes.
```

### Compare two threat groups

```
Use mitre_navigator_layer with mode "diff" and
compareGroupIds ["G0007", "G0016"]
to generate a visual comparison of APT28 vs APT29 techniques.
```

## Testing

```bash
npm test            # Run all tests
npm run test:watch  # Watch mode
npm run lint        # Type check
```

## Project Structure

```
mitre-mcp/
  src/
    index.ts              # MCP server entry point
    config.ts             # Environment config (core + SOC)
    types.ts              # STIX/ATT&CK type definitions
    resources.ts          # MCP resources
    prompts.ts            # MCP prompts
    data/
      loader.ts           # STIX bundle downloader and cache manager
      parser.ts           # STIX 2.1 JSON parser (incl. campaigns)
      index.ts            # Indexed, queryable ATT&CK data store
    tools/
      techniques.ts       # Technique lookup and search
      tactics.ts          # Tactic navigation
      groups.ts           # Threat group intelligence
      software.ts         # Software/malware lookup
      mitigations.ts      # Mitigation mapping
      datasources.ts      # Data source and detection coverage
      mapping.ts          # Alert-to-technique mapping and correlation
      campaigns.ts        # Campaign analysis and attribution
      navigator.ts        # ATT&CK Navigator layer generation
      management.ts       # Data update management
    soc/
      client.ts           # HTTP clients for Wazuh, TheHive, Cortex, MISP
      wazuh.ts            # Wazuh alert mapping and rule coverage
      thehive.ts          # TheHive case enrichment and creation
      cortex.ts           # Cortex analyzer coverage mapping
      misp.ts             # MISP event/IOC management
      correlation.ts      # Cross-stack ATT&CK correlation
      index.ts            # SOC module barrel export
  tests/
    parser.test.ts        # STIX parser tests
    tools.test.ts         # Data store query tests
    mapping.test.ts       # Mapping and correlation tests
  package.json
  tsconfig.json
  tsup.config.ts
  vitest.config.ts
  README.md
```

## Data Sources

ATT&CK data is sourced from the official MITRE STIX 2.1 bundles:

- **Enterprise ATT&CK**: Windows, Linux, macOS, Cloud, Network, Containers
- **Mobile ATT&CK**: Android and iOS
- **ICS ATT&CK**: Industrial control systems

Data is downloaded on first run and cached locally. Set `MITRE_UPDATE_INTERVAL` to control how often the server checks for updates.

## License

MIT
