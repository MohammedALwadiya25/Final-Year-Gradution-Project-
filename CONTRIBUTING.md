# Contributing

Thank you for your interest in contributing! This is a final-year graduation project, but external contributions to the MCP server components are welcome.

---

## Development Setup

### Requirements

- **Node.js 20+**
- **npm 10+**
- **TypeScript** (installed per package as dev dependency)

### Clone and Install

```bash
git clone https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-.git
cd Final-Year-Gradution-Project-

# Install and build all packages
for pkg in zeek-mcp suricata-mcp wazuh-mcp mitre-mcp ai-soc-agent; do
  echo "→ $pkg"
  cd $pkg && npm install && npm run build && cd ..
done
```

---

## Repository Layout

| Directory | Description |
|---|---|
| `zeek-mcp/` | Zeek behavioral analysis MCP server |
| `suricata-mcp/` | Suricata IDS MCP server |
| `wazuh-mcp/` | Wazuh SIEM MCP server |
| `mitre-mcp/` | MITRE ATT&CK intelligence MCP server |
| `ai-soc-agent/` | AI reasoning + orchestration agent |
| `docs/` | Architecture and design documentation |

---

## Branching Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable, tested code only |
| `dev` | Integration branch for new work |
| `feature/<name>` | Individual features |
| `fix/<name>` | Bug fixes |

Create feature branches from `dev`:

```bash
git checkout dev
git pull
git checkout -b feature/your-feature-name
```

---

## Commit Conventions

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]
[optional footer]
```

**Types:**

| Type | When to use |
|---|---|
| `feat` | New tool, feature, or capability |
| `fix` | Bug fix |
| `docs` | Documentation changes only |
| `test` | Adding or fixing tests |
| `refactor` | Code restructuring without behaviour change |
| `chore` | Build scripts, CI, dependency updates |
| `perf` | Performance improvements |

**Examples:**

```
feat(zeek-mcp): add zeek_query_dhcp tool for asset discovery
fix(wazuh-mcp): handle JWT token expiry on 401 response
docs(suricata-mcp): update EVE JSON field reference table
test(mitre-mcp): add campaign profile generation tests
```

---

## Running Tests

```bash
# Run all tests in a package
cd zeek-mcp && npm test

# Watch mode during development
cd zeek-mcp && npm run test:watch

# Type-check without building
cd zeek-mcp && npm run lint
```

All tests must pass before submitting a PR.

---

## Pull Request Process

1. **Fork** the repository
2. Create a branch from `dev` (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run tests (`npm test`)
5. Run type-check (`npm run lint` or `npm run typecheck`)
6. Commit with a conventional commit message
7. Push to your fork
8. Open a PR against `dev` (not `main`)

### PR Checklist

- [ ] Tests pass (`npm test`)
- [ ] TypeScript compiles (`npm run build`)
- [ ] New tools documented in the component `README.md`
- [ ] `.env` keys not committed (use `.env.example`)
- [ ] PR description explains what changed and why

---

## Adding a New MCP Tool

Each MCP server (`zeek-mcp`, `suricata-mcp`, etc.) follows the same pattern:

1. Add the tool definition in `src/tools/<category>.ts`
2. Register the tool in `src/index.ts`
3. Add Zod input validation
4. Write tests in `tests/tools.test.ts`
5. Document the tool in the component `README.md` tools table

---

## Code Style

- **TypeScript strict mode** — no `any` without justification
- **Zod validation** — all tool inputs validated before use
- **Error messages** — descriptive, no raw stack traces in MCP responses
- **No hardcoded credentials** — use environment variables and `.env.example`
- **Streaming parsers** — large log files (EVE JSON, Zeek) must not be fully loaded into memory

---

## Questions

Open a [GitHub Discussion](https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-/discussions) for questions about the architecture or implementation.
