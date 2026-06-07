# Project Evaluation — AI-Powered SOC Agent NIDS

**Evaluated by:** Code and architecture review  
**Date:** June 2026  
**Scope:** Full repository — all 5 packages, infrastructure design, code quality, security, and academic merit

---

## Executive Summary

This is a **well-conceived and substantially implemented** final-year graduation project. The architectural choices are sound, the code quality is above average for an undergraduate project, and the use of Model Context Protocol (MCP) as a reasoning backbone for a NIDS is genuinely novel. Several issues exist that should be addressed before thesis defence, but none are fundamental blockers.

**Overall Grade: A− (88/100)**

---

## 1. Architecture Assessment

### 1.1 Wazuh-Primary Hybrid Model ✅ Strong

The two-phase investigation design is the most important architectural decision in the project, and it is well-justified:

- **Fast path** (Wazuh + MITRE only) handles ≥80% and <40% confidence cases in ~3 s
- **Deep path** (all 4 MCP servers) is reserved for the 40–79% ambiguous band
- This is analogous to real-world analyst workflows: check the SIEM aggregation first, then dig into raw sensors only if the picture is unclear

**Strength:** The two-phase design is a publishable academic contribution. No prior work on AI-driven NIDS uses MCP as the intelligence layer with this kind of conditional escalation logic.

**Weakness:** The confidence thresholds (80/40) are hardcoded constants. In production, these should be calibrated per environment. The thesis should acknowledge this limitation.

### 1.2 MCP as Intelligence Layer ✅ Novel

Using MCP servers as the abstraction layer between the AI reasoning engine and the security data sources is architecturally elegant:

- The AI agent is completely decoupled from the data sources
- Swapping Zeek for Arkime, or Wazuh for Splunk, only requires a new MCP server — no agent code changes
- The tool-calling model (128 total tools across 4 servers) gives the LLM precise, typed access to each data source

**Strength:** This is genuine architectural novelty. The `McpHub` class and the `isToolAllowed` read-only enforcement are well-designed.

**Improvement:** The `GeminiSocReasoner` has a mirror copy of `stripGeminiUnsupported` that already exists in `McpHub`. This shared logic should be extracted to a shared utility.

### 1.3 Network Topology ✅ Appropriate

The VMware-local + Azure + Tailscale hybrid is a pragmatic solution to the "need cloud SIEM but low budget" constraint:

- Tailscale subnet routing is correctly used (laptop advertises `192.168.80.0/24`)
- pfSense VLAN segmentation (DMZ/LAN/MGMT) reflects real-world network design
- The architecture acknowledges the "lab constraint" of requiring the laptop to be powered on

**Risk:** This architecture cannot be used as-is in production. The thesis should explicitly state this and describe a production alternative (dedicated ESXi host advertises subnet; Tailscale is replaced by site-to-site VPN or SD-WAN).

---

## 2. Code Quality

### 2.1 `ai-soc-agent` ✅ Good

| Aspect | Assessment |
|---|---|
| TypeScript strictness | ✅ Strict mode, `noEmit` typecheck, no `any` in core paths |
| Input validation | ✅ Zod schemas on all HTTP inputs (`investigationRequestSchema`) |
| Error handling | ✅ Graceful shutdown (SIGINT/SIGTERM), fallback on agent error |
| Logging | ✅ `pino` structured JSON logging with `pino-http` for request tracing |
| Security headers | ✅ `helmet` middleware applied |
| Policy enforcement | ✅ `enforcePolicy()` post-validates Gemini output — LLM cannot bypass thresholds |
| Separation of concerns | ✅ Clean split: `server.ts` → `InvestigationService` → `GeminiSocReasoner` → `McpHub` |

**Issue:** `GeminiSocReasoner.generate()` uses a raw `https.request()` implementation instead of a proper HTTP client. This works but is harder to test and doesn't support retries. Should be replaced with `node-fetch` or `undici` with retry logic.

**Issue:** No rate limiting on `/investigate`. A single malformed webhook loop from n8n could exhaust Gemini API quota. Add `express-rate-limit`.

### 2.2 `zeek-mcp` ✅ Good (110 tests)

The streaming parsers for both JSON and TSV formats are a highlight — they handle large log files without loading the entire file into memory. The dual-format abstraction in `src/parser/` is well-designed.

**Issue:** CIDR matching uses a custom implementation. `ip-cidr` or `ipaddr.js` would be more reliable and cover edge cases (IPv4-mapped IPv6, etc.).

**Issue:** The beaconing detection algorithm calculates interval regularity but does not weight by connection count. A connection that fires 4 times is treated the same as one that fires 400 times.

### 2.3 `suricata-mcp` ✅ Strong (158 tests)

The most test-covered component. The advanced analytics (DGA via Shannon entropy, beaconing with jitter scoring, lateral movement via RFC1918 detection) demonstrate good security domain knowledge.

**Strength:** 158 tests is excellent for an undergraduate project. The EVE JSON streaming parser with Gzip support is production-grade.

**Issue:** `suricata_reload_rules_docker` assumes a Docker deployment. The thesis lab uses bare-metal Suricata. The tool should fail gracefully with a helpful message when Docker is not available.

### 2.4 `wazuh-mcp` ✅ Strong

The dual API design (Wazuh REST + OpenSearch indexer) correctly models how Wazuh 4.x actually works. The privacy-first output defaults (IPs/hashes hidden, opt-in exposure) is a thoughtful security-by-design choice.

**Strength:** Automatic JWT token refresh, retry logic on transient errors, and response size caps are production-grade features uncommon in thesis code.

**Issue:** `WAZUH_VERIFY_SSL=false` defaults are correct for the lab but will produce startup warnings. The README correctly documents this as lab-only. The CI should set `WAZUH_VERIFY_SSL=true` (with mocked certs) to ensure the warning path is tested.

### 2.5 `mitre-mcp` ✅ Good (39 tools)

The offline-first STIX bundle caching is the right design for a lab environment that may lack internet access during demos. The Navigator layer export is a genuinely useful feature.

**Issue:** The SOC integrations (TheHive, Cortex, MISP) are defined but are optional and may not be reachable in the lab. The MCP server should start successfully and return helpful "not configured" messages when these are absent, rather than failing silently. Verify this behavior.

**Fixed:** The OpenClaw, Hermes Agent, and Codex CLI sections have been removed from `mitre-mcp/README.md` and `wazuh-mcp/README.md`. These were upstream boilerplate sections irrelevant to this project.

---

## 3. Security Analysis

### 3.1 Credential Management ✅ Good

- `.env` is in `.gitignore` at root and per-package level
- `.env.example` files exist with placeholder values — `wazuh-mcp/.env.example` updated to use `YOUR_WAZUH_PASSWORD_HERE` instead of an actual default value
- `ai-soc-agent/.gitignore` added (was missing)
- No hardcoded secrets in codebase

**Verify** no `.env` files were committed in git history:
```bash
git log --all --full-history -- "**/.env"
git log --all --full-history -- ".env"
```

### 3.2 Agent Security ✅ Good

- `MCP_READONLY=true` default — agent cannot write to any data source
- `isToolAllowed()` blocklist prevents write tools from being called even if the LLM attempts to
- `enforcePolicy()` post-validates the Gemini decision — confidence thresholds cannot be bypassed by a jailbroken or confused LLM
- Zod schema enforcement on the final decision means malformed LLM output is rejected, not executed

### 3.3 Network Security ⚠️ Lab Constraints

The following are acceptable for a lab but must be explicitly documented:

| Issue | Lab Acceptable | Production Fix |
|---|---|---|
| `WAZUH_VERIFY_SSL=false` | ✅ | Use proper CA-signed certs or internal CA |
| `/investigate` has no authentication | ✅ | Add API key header or mTLS |
| pfSense self-signed cert | ✅ | Use internal CA or public cert |
| n8n with Basic Auth only | ✅ | Add SSO (Tailscale + n8n OAuth) |

### 3.4 Input Validation ✅ Good

All HTTP endpoints use Zod schemas. MCP tool inputs are validated before Wazuh/Zeek API calls. The `investigationRequestSchema` enforces IP format validation (`z.ipv4() | z.ipv6()`).

**Issue:** The `src_ip` in `investigationRequestSchema` uses `z.union([z.ipv4(), z.ipv6()])`. Zod v4 `z.ipv4()` does not reject private ranges or loopback. An adversary sending `src_ip: "127.0.0.1"` would trigger an investigation of the agent's own host. Add a validator that rejects loopback (`127.0.0.0/8`, `::1`) for the `src_ip` field.

---

## 4. Test Coverage

| Package | Tests | Coverage Assessment |
|---|---|---|
| `zeek-mcp` | 110 | Good — parsers, query engine, analytics, filters |
| `suricata-mcp` | 158 | Excellent — all major modules covered |
| `wazuh-mcp` | Present | Good — API client, tool handlers |
| `mitre-mcp` | Present | Good — STIX parser, mapping, correlation |
| `ai-soc-agent` | **None** | ❌ Missing — highest-risk component has no tests |

**Critical gap:** The `ai-soc-agent` has no tests. This is the component that makes final security decisions. At minimum, unit tests should cover:

1. `enforcePolicy()` — verify confidence thresholds produce correct actions
2. `InvestigationService` — verify correct response shape, timing fields
3. `McpHub` — verify `isToolAllowed()` blocks write tools in readonly mode
4. `GeminiSocReasoner` — verify JSON extraction handles edge cases (markdown fences, preamble text)

These don't require a live Gemini API — mock the `generate()` method.

---

## 5. Documentation Quality

| Document | Assessment |
|---|---|
| `NIDS_Full_Milestone_Guide.md` | ✅ Excellent — most detailed implementation guide seen in an undergraduate project |
| Per-package `README.md` | ✅ Good — tool reference tables, configuration, architecture sections |
| Root `README.md` | ✅ (Now created) — architecture diagram, quick start, components |
| `docs/architecture.md` | ✅ (Now created) — detailed design rationale |
| `CONTRIBUTING.md` | ✅ (Now created) |
| `CHANGELOG.md` | ✅ (Now created) |
| `SECURITY.md` | ✅ (Now created) |
| CI workflow | ✅ (Now created) |
| Inline code comments | ⚠️ Sparse — `GeminiSocReasoner.ts` and `McpHub.ts` would benefit from JSDoc on public methods |

---

## 6. What's Missing Before Thesis Defence

### Priority 1 — Must Fix

- [ ] **Add tests for `ai-soc-agent`** — at minimum test `enforcePolicy()`, `McpHub.isToolAllowed()`, and JSON extraction
- [ ] **Validate `src_ip` is not loopback/reserved** in `investigationRequestSchema`
- [ ] **Fill in Phase 6 results** in `README.md` metrics table after running all 5 attack scenarios
- [ ] **Record demo video** — 10+ minutes showing full attack-to-block pipeline

### Priority 2 — Should Fix

- [ ] **Extract shared `stripUnsupported`** from `GeminiSocReasoner.ts` and `McpHub.ts` into `src/utils/schema.ts`
- [ ] **Add `express-rate-limit`** to the `/investigate` endpoint
- [ ] **Replace raw `https.request`** in `GeminiSocReasoner` with `undici` or `node-fetch`
- [ ] **Document production deployment changes** (SSL verify, authentication, dedicated subnet router)
- [x] ~~**Clean up placeholder references** to "OpenClaw" in `mitre-mcp/README.md`~~ — Fixed (also removed from `wazuh-mcp/README.md`)

### Priority 3 — Nice to Have

- [ ] Add JSDoc to public methods in `McpHub.ts` and `GeminiSocReasoner.ts`
- [ ] Calibrate confidence thresholds empirically during Phase 6 and document chosen values
- [ ] Add `/metrics` endpoint to the AI agent for Prometheus scraping
- [ ] Consider adding `docker-compose.yml` for demo reproducibility

---

## 7. Strengths Summary

1. **Genuine architectural novelty** — MCP as NIDS intelligence layer is not found in prior work
2. **Production-grade features** in MCP servers — streaming parsers, JWT refresh, retry logic, privacy-first defaults
3. **Well-structured TypeScript** — strict mode, Zod validation, clean separation of concerns
4. **158 + 110 tests** in the MCP servers — above average for undergraduate projects
5. **Comprehensive implementation guide** (`NIDS_Full_Milestone_Guide.md`) — reproducible by a third party
6. **Safety-by-design** — read-only mode, `enforcePolicy()` post-validation, policy enforcement separation
7. **Realistic infrastructure design** — pfSense VLANs, Tailscale mesh, dual-sensor detection reflect real-world SOC architecture
8. **Strong academic argument** — supervised autonomy, cross-sensor validation, and quantitative comparison to baseline are all publishable contributions

---

## 8. Comparison to Published NIDS Research

| Metric | Published Average (2023–2025) | This Project (Target) |
|---|---|---|
| Detection Rate | 85–97% (ML models on CICIDS2017) | ≥ 80% (5 real attack scenarios) |
| False Positive Rate | 2–8% (ML) / 15–25% (signature-only) | ≤ 15% |
| MTTR | 15–45 min (human analyst) | ≤ 30 s |
| Training data required | Yes (all ML approaches) | **No** (key novelty) |
| Multi-sensor corroboration | Rarely | ✅ (Zeek + Suricata + Wazuh) |

**Note:** Direct comparison to ML-based NIDS (CICIDS2017 benchmark results) is not appropriate because this project uses real attack scenarios on a live lab environment, not a labelled dataset. The thesis should make this distinction clearly and argue that real-environment evaluation is a _more rigorous_ test than dataset evaluation.

---

## 9. Final Verdict

This project demonstrates:
- A clear understanding of real-world SOC architecture
- Original thinking in applying MCP to the NIDS problem
- Above-average implementation quality for an undergraduate project
- A strong thesis argument built on measurable, reproducible results

The primary gap is the absence of tests for `ai-soc-agent` — the highest-risk component — and the missing Phase 6 results. Both are completable before submission.

**Recommended grade: Distinction** (subject to completing Phase 6 results and addressing Priority 1 items).
