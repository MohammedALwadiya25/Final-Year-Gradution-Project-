# Security Policy

## Supported Versions

This is a final-year graduation project. Active security fixes are applied to the `main` branch only.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ Yes |
| Older commits | ❌ No |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security issue in any component (MCP servers, AI agent, configuration), please report it privately:

1. **Email:** Open a private security advisory via GitHub → **Security → Advisories → New draft advisory**
2. Include a clear description of the issue, steps to reproduce, and potential impact
3. You will receive a response within **72 hours**

---

## Scope

Security issues in scope include:

- **Credential exposure** — `.env` files, API keys, passwords committed to the repo
- **Injection vulnerabilities** — in MCP tool inputs, EVE JSON parsing, Wazuh API queries
- **Unsafe deserialization** — in JSON parsers (Zeek/Suricata/MITRE log processing)
- **Path traversal** — in log file path handling (`ZEEK_LOG_DIR`, `SURICATA_EVE_LOG`)
- **Authentication bypass** — in the AI agent `/investigate` endpoint

Out of scope:

- Vulnerabilities in third-party dependencies (report upstream to the package maintainer)
- Lab infrastructure (pfSense, Wazuh, n8n) — report to their respective projects
- Theoretical attacks without a working proof of concept

---

## Security Defaults in This Project

| Component | Default | Rationale |
|---|---|---|
| AI agent | `MCP_READONLY=true` | Agent recommends actions; n8n executes them |
| Wazuh MCP | IPs/hashes hidden by default | Sensitive output opt-in |
| Agent inputs | Zod schema validation | Reject malformed payloads |
| Credentials | `.env` in `.gitignore` | Never committed to the repo |
| WAZUH_VERIFY_SSL | `false` (lab only) | Self-signed certs in the lab; set `true` in production |

---

## Known Limitations (Lab Environment)

This project is designed for a controlled lab environment. For production deployment, the following changes are required:

- Set `WAZUH_VERIFY_SSL=true` and `WAZUH_INDEXER_VERIFY_SSL=true`
- Put the `/investigate` endpoint behind authentication (API key or mTLS)
- Run MCP servers with a dedicated low-privilege OS user
- Rotate Gemini API keys regularly
- Audit pfSense API tokens and restrict to MGMT VLAN only
