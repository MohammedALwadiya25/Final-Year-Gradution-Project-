# Deployment Guide

This document covers three deployment scenarios:

1. [Lab (VMware + Azure)](#1-lab-vmware--azure) — thesis evaluation environment
2. [Docker Compose (Demo)](#2-docker-compose-demo) — quick local demo
3. [Production Considerations](#3-production-considerations) — what would change in a real environment

---

## 1. Lab (VMware + Azure)

The full lab environment is documented in detail in [`NIDS_Full_Milestone_Guide.md`](../NIDS_Full_Milestone_Guide.md). This section summarises the deployment steps.

### Prerequisites

```
VMware Workstation Pro/Player
Azure account (free credit sufficient)
Tailscale account (free tier, up to 100 devices)
Node.js 20+ on MCP VM and Azure Agent VM
Google AI Studio account (free Gemini API key)
```

### Deployment Order

```
Week 1–2:  pfSense → Zeek/Suricata VM → Tailscale → Wazuh (Azure)
Week 3–4:  Custom Suricata rules → Custom Wazuh correlation rules
Week 5–6:  MCP servers on 192.168.80.12 → PM2 configuration
Week 7–8:  AI agent on 100.64.0.3 (Azure) → Smoke tests
Week 9–10: n8n SOAR workflow → pfSense API integration → Telegram bot
Week 11–12: Attack simulation → Metrics collection
```

### MCP Server Configuration (192.168.80.12)

```bash
# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs git
sudo npm install -g pm2

# Clone and build all MCP servers
mkdir -p ~/mcp-servers && cd ~/mcp-servers
git clone https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-.git
cd Final-Year-Gradution-Project-

for pkg in zeek-mcp suricata-mcp wazuh-mcp mitre-mcp; do
  cd $pkg && npm install && npm run build && cd ..
done

# Configure PM2
pm2 start scripts/ecosystem.config.js
pm2 save && pm2 startup
```

### AI Agent Configuration (100.64.0.3)

```bash
cd ai-soc-agent
cp .env.example .env
# Fill in GEMINI_API_KEY, WAZUH_URL, WAZUH_USERNAME, WAZUH_PASSWORD

npm install && npm run build

pm2 start dist/server.js --name ai-soc-agent
pm2 save
```

### Verification

```bash
# From Azure VM
bash scripts/health-check.sh 192.168.80.12 localhost

# Run canonical test cases
bash scripts/test-investigate.sh localhost:3000
```

---

## 2. Docker Compose (Demo)

For evaluation demos without the full lab, Docker Compose runs all 5 components in a single container network.

### Limitations

- MCP servers connect to Wazuh API over the network — requires a reachable Wazuh instance
- Sample/test log data is used for Zeek and Suricata (not live traffic)
- pfSense blocking is not available in this mode

### Setup

```bash
# Copy and configure environment
cp ai-soc-agent/.env.example .env

# Edit .env — minimum required:
# GEMINI_API_KEY=<your key>
# WAZUH_URL=https://<your-wazuh>:55000
# WAZUH_USERNAME=wazuh-wui
# WAZUH_PASSWORD=<your-password>

# Build and start all services
docker compose up --build

# Check agent health
curl http://localhost:3000/health

# Run test investigation
bash scripts/test-investigate.sh
```

### Each MCP Server Dockerfile

Each MCP package needs a `Dockerfile`. Example for `zeek-mcp`:

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY dist/ ./dist/
USER node
CMD ["node", "dist/index.js"]
```

Build before composing:

```bash
cd zeek-mcp && npm run build && cd ..
# repeat for other packages
```

---

## 3. Production Considerations

This project is designed for a lab environment. The following changes are required before any production deployment:

### Security

| Change | Why |
|---|---|
| Set `WAZUH_VERIFY_SSL=true` | Lab uses self-signed certs; production needs valid CA |
| Add authentication to `/investigate` | Currently unauthenticated; add API key header or mTLS |
| Add rate limiting | `express-rate-limit` to prevent API quota exhaustion |
| Rotate Gemini API keys | Use a secrets manager (Vault, AWS Secrets Manager) |
| Run MCP servers as non-root | Dedicated `mcp-runner` OS user with minimal permissions |

### Architecture

| Change | Why |
|---|---|
| Replace Tailscale with site-to-site VPN | Production does not rely on a laptop being powered on |
| Deploy on ESXi/Proxmox | Dedicated hypervisor replaces VMware Workstation |
| Add Redis for investigation caching | Avoid duplicate investigations for the same src_ip within a TTW |
| Add `/metrics` Prometheus endpoint | For production observability |
| Use HAProxy in front of AI agent | TLS termination, load balancing across multiple agent instances |

### Monitoring

```
Recommended production monitoring stack:
  Prometheus → scrape /metrics from ai-soc-agent
  Grafana → dashboard: decisions/hour, confidence distribution, path split, latency P95
  Alertmanager → alert if agent error rate > 5% or latency P95 > 15s
```
