# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Planned
- Phase 6: Attack simulation results and metrics
- Comparison table: AI Agent vs Suricata-only baseline
- Demo video walkthrough

---

## [1.0.0] — 2026-06-07

### Added

#### Project Foundation
- Repository structure: `ai-soc-agent`, `zeek-mcp`, `suricata-mcp`, `wazuh-mcp`, `mitre-mcp`
- Root `README.md` with full architecture diagram, quick start, and component table
- `CONTRIBUTING.md` with commit conventions, branching strategy, and PR checklist
- `SECURITY.md` with responsible disclosure policy and known lab limitations
- `CHANGELOG.md` (this file)
- `docs/architecture.md` with detailed design rationale
- GitHub Actions CI workflow (build + test all 5 packages)
- GitHub issue templates (bug report, feature request)
- GitHub pull request template

#### ai-soc-agent
- Express HTTP server with `/investigate` and `/health` endpoints
- `InvestigationService` — two-phase investigation orchestration with timing
- `GeminiSocReasoner` — Google Gemini Flash tool-use reasoning
- `McpHub` — stdio MCP server manager for all 4 MCP servers
- `SocDecision` Zod schema — validated structured decision output
- SOC analyst system prompt with Wazuh-primary hybrid logic
- `MCP_READONLY=true` default — agent recommends, n8n enforces
- `.env.example` covering all environment variables

#### zeek-mcp
- 25 tools: connection analysis, DNS, HTTP, SSL/TLS, files, SSH, DHCP, beaconing, anomalies
- Dual format support: JSON and TSV (Zeek native)
- Streaming parser for large log files
- Shannon entropy DNS tunneling detection
- C2 beaconing detection (interval regularity + jitter scoring)
- Statistical anomaly detection (port scans, exfiltration, unusual ports)
- Suricata EVE JSON cross-correlation tools
- 110 tests

#### suricata-mcp
- 36 tools: alert analysis, flow analysis, protocol analysis, rule management, advanced analytics
- Streaming EVE JSON parser with Gzip support and Zod validation
- DGA detection via Shannon entropy on DNS queries
- C2 beaconing detection with confidence scoring
- Lateral movement detection (internal-to-internal scanning)
- Data exfiltration detection
- Zeek NSM cross-correlation (8 tools)
- PCAP replay orchestration
- 158 tests

#### wazuh-mcp
- 28 tools: agents, alerts, vulnerabilities, rules, SCA, system inventory, FIM, manager, groups
- Dual API: Wazuh REST (port 55000) + OpenSearch indexer (port 9200)
- JWT authentication with automatic token refresh
- Privacy-first output: IPs, hashes, command lines hidden by default
- Zod input validation with pagination bounds
- Retry logic for transient errors (429, 502, 503, 504)
- Response size cap with truncated preview for oversized results

#### mitre-mcp
- 39 tools: techniques, tactics, groups, software, mitigations, data sources, mapping, campaigns, navigator
- Offline-first: STIX 2.1 bundle cached locally after first download
- STIX 2.1 parser: Enterprise, Mobile, ICS matrices
- SOC integrations: Wazuh, TheHive, Cortex, MISP
- ATT&CK Navigator layer generation (coverage, group, campaign, diff modes)
- Cross-stack correlation across Wazuh + TheHive + MISP

#### Infrastructure (NIDS_Full_Milestone_Guide.md)
- Phase 1: pfSense VLAN design, Zeek/Suricata deployment, Tailscale mesh, Wazuh setup
- Phase 2: 5 custom Suricata rules + 5 custom Wazuh correlation rules with MITRE ATT&CK mapping
- Phase 3: MCP server installation order, PM2 production configuration, integration test script
- Phase 4: AI agent Node.js code, system prompt, 3-scenario test suite
- Phase 5: n8n SOAR workflow (11 nodes), pfSense auto-block, Telegram analyst approval
- Phase 6: 5 attack scenarios, metrics collection template, thesis chapter outline

---

[Unreleased]: https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-/releases/tag/v1.0.0
