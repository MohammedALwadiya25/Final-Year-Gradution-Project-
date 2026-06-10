# 🎓 AI-Powered SOC Agent NIDS for E-Commerce
## Complete Corrected Milestone Guide
### Final Year Graduation Project — Mohammed ALwadiya

> **⚠️ CRITICAL:** This guide replaces `NIDS_Full_Milestone_Guide.md` in your repo. The original contains errors that will break your setup. Follow this guide exactly.

---

## 📋 Project Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AZURE CLOUD (Tailscale Overlay)                   │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  Wazuh + AI Agent + n8n VM (100.64.0.2)                          │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │  │
│  │  │ Wazuh 4.14.5│  │ AI Agent    │  │ n8n SOAR Workflow       │   │  │
│  │  │ - Indexer   │  │ - Gemini    │  │ - 11 nodes              │   │  │
│  │  │ - Manager   │  │ - 54 Tools  │  │ - Telegram + pfSense    │   │  │
│  │  │ - Dashboard │  │ - PM2       │  │ - AbuseIPDB + VT        │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                              │                                          │
│                              │ NFS (read-only)                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  Sensor VM (192.168.80.11) — On-Prem via Tailscale                  │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │  │
│  │  │ Zeek LTS    │  │ Suricata    │  │ Wazuh Agent 4.14.5      │   │  │
│  │  │ - TSV logs  │  │ - eve.json  │  │ - Suricata forwarding   │   │  │
│  │  │ - NFS export│  │ - NFS export│  │ - Zeek forwarding       │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────┘   │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                              │                                          │
│                              │ Mirror Port (SPAN)                       │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │  Network Infrastructure                                               │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │  │
│  │  │ pfSense     │  │ Kali Linux  │  │ DVWA        │  │ Windows   │ │  │
│  │  │ - VLANs     │  │ - Attacker  │  │ - Target    │  │ - Victim  │ │  │
│  │  │ - SPAN      │  │ - 100.64.0.4│  │ - 192.168.80.13│ - 192.168.80.14│ │  │
│  │  │ - API block │  │             │  │             │  │           │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔴 Critical Corrections vs. Original Milestone Guide

| # | Issue | Original Says | Correct | Risk if Wrong |
|---|---|---|---|---|
| 1 | Zeek `local.zeek` paths | `@load policy/tuning/defaults` | **Remove** — not in zeek-lts | Zeek fails to start |
| 2 | NFS export subnet | `192.168.80.0/24` | `100.64.0.2` (Tailscale IP) | Agent VM cannot mount |
| 3 | Zeek NFS mount path | `/opt/zeek/logs` | `/opt/zeek/spool/zeek` | Symlink breaks over NFS |
| 4 | Wazuh webhook script | `sys.argv[3]` | `sys.argv[1]` | Script fails silently |
| 5 | Wazuh API username | `wazuh-admin` | `wazuh-wui` | API authentication fails |
| 6 | Wazuh parent SID | `31101` | `86601` (Suricata EVE) | Rules never fire |
| 7 | fstab `_netdev` | Missing | Required | VM hangs on boot |
| 8 | `build-essential` | Missing | Required | Native npm modules fail |
| 9 | `.gitignore` `.env` | Not warned | **MANDATORY** | API keys public on GitHub |
| 10 | n8n webhook path | `soc-alert` | `wazuh-alert` | Webhook never triggers |
| 11 | NFS `no_root_squash` | Missing | Required | Permission denied |
| 12 | UFW port 111 | Missing | Required | NFS fallback fails |
| 13 | Wazuh 4.14.5 auth | Basic Auth | Bearer token | API calls fail |
| 14 | Agent fallback logic | Confidence 75 for sev 10 | Confidence 85 for sev 10 | No auto-block |

---

# Phase 1 — Network Infrastructure (Weeks 1–2)

## 1.1 pfSense Configuration

### VLAN Setup
```
VLAN 10: Management — 192.168.80.0/24
VLAN 20: DMZ — 192.168.20.0/24 (if needed)
WAN: DHCP from your ISP
```

### SPAN Port Configuration
```
Interfaces → Assignments → VLANs → Add
  Parent: LAN
  VLAN Tag: 10
  Description: Management

Interfaces → Assignments → Add
  Interface: VLAN10
  Enable: ✓
  IPv4: Static
  IP: 192.168.80.10/24

Services → DHCP Server → VLAN10
  Enable: ✓
  Range: 192.168.80.11 - 192.168.80.254

Interfaces → Switches → VLANs
  Add SPAN port for IDS traffic
```

### pfSense API Token (for Phase 5)
```
System → Package Manager → Available Packages
  Install: pfSense-pkg-API

Diagnostics → API → Version 2
  Create API token
  Save token securely (never commit to Git)
```

## 1.2 DVWA Setup (192.168.80.13)
```bash
# Install on Ubuntu VM
sudo apt install -y apache2 mysql-server php libapache2-mod-php php-mysql

# Download DVWA
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git
sudo mv DVWA dvwa
sudo chmod -R 755 dvwa

# Configure database
sudo mysql -u root -p
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Edit config
sudo cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
sudo nano /var/www/html/dvwa/config/config.inc.php
# Set: $_DVWA['db_user'] = 'dvwa';
# Set: $_DVWA['db_password'] = 'p@ssw0rd';

# Access: http://192.168.80.13/dvwa
# Login: admin / password
# Set Security Level: LOW (for SQL injection testing)
```

## 1.3 Kali Linux Setup (100.64.0.4)
```bash
# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Install tools
sudo apt update
sudo apt install -y nmap hydra sqlmap hping3 nikto

# Verify connectivity to DVWA
curl http://192.168.80.13/dvwa
```

## 1.4 Phase 1 Deliverables
```
□ pfSense VLANs configured
□ SPAN port mirroring IDS traffic
□ DVWA accessible at 192.168.80.13
□ Kali Linux on Tailscale (100.64.0.4)
□ Windows VM on management VLAN (192.168.80.14)
□ All VMs can ping each other
```

---

# Phase 2 — Sensor Deployment (Weeks 3–4)

## 2.1 Zeek Installation (Sensor VM 192.168.80.11)

```bash
# Install Zeek LTS
sudo apt install -y zeek-lts

# Configure node
echo 'export PATH=/opt/zeek/bin:$PATH' | sudo tee /etc/profile.d/zeek.sh
source /etc/profile.d/zeek.sh

# Edit local.zeek — USE THESE EXACT LINES
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

```zeek
# This script logs which scripts were loaded during startup.
@load misc/loaded-scripts

# Apply tuning defaults for common settings.
# NOTE: Do NOT use @load policy/tuning/defaults — it doesn't exist in zeek-lts

# Enable logging of memory, packet and lag statistics.
@load misc/stats

# Load the scan detection script.
@load misc/scan

# Detect traceroute.
# NOTE: detect-traceroute is a directory, not a script — do NOT load it

# Generate notices when vulnerable versions of software are discovered.
@load frameworks/software/vulnerable

# Apply default hardening.
@load frameworks/software/version-changes

# This script enables SSL/TLS certificate validation.
@load protocols/ssl/known-certs

# This script provides the heartbleed attack detector.
@load protocols/ssl/heartbleed

# This script detects the SSLv3 POODLE attack.
@load protocols/ssl/poodle

# This script detects the SSLv2 POODLE attack.
@load protocols/ssl/sslv2

# This script detects the FREAK attack.
@load protocols/ssl/freak

# This script detects the LogJam attack.
@load protocols/ssl/logjam

# This script detects TLS session resumption with bad/non-ephemeral keys.
@load protocols/ssl/weak-keys

# This script detects the Zeek software framework.
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/geo-data
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/software

# Detect SQL injection in HTTP traffic.
@load protocols/http/detect-sql-injection

# Detect SQL injection in HTTP headers.
@load protocols/http/detect-sqli

# Software framework which enables detection of vulnerabilities in software.
@load frameworks/software/vulnerable

# Detect software changes.
@load frameworks/software/version-changes
```

```bash
# Deploy Zeek
sudo zeekctl deploy
sudo zeekctl status  # Should show: running

# Verify logs
ls -la /opt/zeek/logs/current/
```

## 2.2 Suricata Installation

```bash
sudo apt install -y suricata

# Configure for interface
cat /opt/zeek/etc/node.cfg | grep interface
# Use the same interface for Suricata

sudo nano /etc/suricata/suricata.yaml
# Set:
#   HOME_NET: "[192.168.80.0/24]"
#   interface: eth0 (or your sniffing interface)

# Add custom rules
sudo nano /etc/suricata/rules/local.rules
```

```suricata
# SSH Brute Force
alert tcp any any -> $HOME_NET 22 (
    msg:"CUSTOM SSH BRUTE FORCE ATTEMPT";
    flags:S;
    threshold: type both, track by_src, count 5, seconds 60;
    classtype:attempted-admin;
    sid:9000001;
    rev:1;
    metadata:mitre_technique T1110.001;
)

# SQL Injection Detection
alert tcp any any -> $HOME_NET any (
    msg:"CUSTOM SQL INJECTION DETECTED";
    content:"union"; http_uri; nocase;
    content:"select"; http_uri; nocase;
    classtype:web-application-attack;
    sid:9000002;
    rev:1;
    metadata:mitre_technique T1190;
)

# DDoS SYN Flood
alert tcp any any -> $HOME_NET any (
    msg:"CUSTOM DDOS SYN FLOOD DETECTED";
    flags:S;
    threshold: type both, track by_src, count 100, seconds 10;
    classtype:denial-of-service;
    sid:9000003;
    rev:2;
    metadata:mitre_technique T1498;
)

# C2 DNS Beaconing
alert udp any any -> any 53 (
    msg:"CUSTOM DNS QUERY C2 BEACONING";
    content:"|01 00 00 01 00 00 00 00 00 00|";
    threshold: type both, track by_src, count 10, seconds 60;
    classtype:trojan-activity;
    sid:9000004;
    rev:1;
    metadata:mitre_technique T1071.004;
)

# Internal Port Scan (Lateral Movement)
alert tcp $HOME_NET any -> $HOME_NET any (
    msg:"CUSTOM PORT SCAN LATERAL MOVEMENT";
    flags:S;
    threshold: type both, track by_src, count 20, seconds 10;
    classtype:attempted-recon;
    sid:9000005;
    rev:1;
    metadata:mitre_technique T1046;
)
```

```bash
# Update Suricata rules
sudo suricata-update
sudo systemctl restart suricata
sudo systemctl status suricata

# Verify EVE JSON logs
ls -lh /var/log/suricata/eve.json
```

## 2.3 Wazuh Agent Installation

```bash
# Install Wazuh agent
curl -so wazuh-agent.deb https://packages.wazuh.com/4.14/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.5-1_amd64.deb
sudo WAZUH_MANAGER='100.64.0.2' dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Configure log forwarding
sudo nano /var/ossec/etc/ossec.conf
```

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/opt/zeek/logs/current/conn.log</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent
```

## 2.4 Phase 2 Deliverables
```
□ Zeek running and logging to /opt/zeek/spool/zeek/
□ Suricata running with 5 custom rules (SIDs 9000001–9000005)
□ Wazuh agent enrolled to manager at 100.64.0.2
□ Suricata EVE JSON forwarded to Wazuh
□ Zeek conn.log forwarded to Wazuh
```

---

# Phase 3 — MCP Runtime Setup (Weeks 5–6)

## 3.1 Pre-Phase 3 Verification

```bash
# On Sensor VM (192.168.80.11)
sudo zeekctl status                                    # running
sudo systemctl status suricata --no-pager | head -4   # active
sudo systemctl status wazuh-agent --no-pager | head -4 # active

ls -lh /opt/zeek/logs/current/
ls -lh /var/log/suricata/eve.json

tailscale status
tailscale ip -4   # Note this IP
```

## 3.2 NFS Export — Sensor VM

```bash
# On 192.168.80.11
sudo apt install -y nfs-kernel-server

sudo nano /etc/exports
```

```
# /etc/exports — read-only exports to Wazuh VM Tailscale IP
/opt/zeek/spool/zeek  100.64.0.2(ro,sync,no_subtree_check,no_root_squash)
/var/log/suricata      100.64.0.2(ro,sync,no_subtree_check,no_root_squash)
```

```bash
sudo exportfs -ra
sudo exportfs -v
sudo systemctl enable nfs-kernel-server
sudo systemctl restart nfs-kernel-server

# Firewall
sudo ufw allow from 100.64.0.2 to any port 2049
sudo ufw allow from 100.64.0.2 to any port 111

sudo ss -tlnp | grep 2049
```

## 3.3 NFS Mount — Wazuh VM (100.64.0.2)

```bash
# On 100.64.0.2
sudo apt install -y nfs-common

sudo mkdir -p /mnt/zeek-logs
sudo mkdir -p /mnt/suricata-logs

# Replace 100.104.57.29 with your sensor VM's Tailscale IP
sudo mount -v -t nfs -o ro,noatime,nfsvers=4 100.104.57.29:/opt/zeek/spool/zeek /mnt/zeek-logs
sudo mount -v -t nfs -o ro,noatime,nfsvers=4 100.104.57.29:/var/log/suricata /mnt/suricata-logs

# Verify
ls -la /mnt/zeek-logs/
ls -lh /mnt/suricata-logs/eve.json

# Make persistent
echo '100.104.57.29:/opt/zeek/spool/zeek /mnt/zeek-logs     nfs ro,noatime,nfsvers=4,_netdev 0 0' | sudo tee -a /etc/fstab
echo '100.104.57.29:/var/log/suricata    /mnt/suricata-logs nfs ro,noatime,nfsvers=4,_netdev 0 0' | sudo tee -a /etc/fstab

sudo mount -a
df -h | grep mnt
```

## 3.4 Node.js Setup

```bash
# On 100.64.0.2
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs git build-essential

node --version    # v20.x.x
npm --version     # v10.x.x+

sudo npm install -g pm2
pm2 --version
```

## 3.5 Clone and Build Monorepo

```bash
cd ~
git clone https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-.git
cd Final-Year-Gradution-Project-

npm install
# If peer dependency errors: npm install --legacy-peer-deps

npm run build

# Verify all 5 outputs
ls -la zeek-mcp/dist/index.js
ls -la suricata-mcp/dist/index.js
ls -la wazuh-mcp/dist/index.js
ls -la mitre-mcp/dist/index.js
ls -la ai-soc-agent/dist/server.js
```

## 3.6 Configure .env

```bash
cp ai-soc-agent/.env.example ai-soc-agent/.env
nano ai-soc-agent/.env
```

**Fill in ALL placeholders. See `.env.example` for structure.**

**CRITICAL SECURITY CHECK:**
```bash
cat .gitignore | grep .env
# Must show: .env
# If missing: echo ".env" >> .gitignore
```

## 3.7 Smoke Test

```bash
npm run smoke --workspace=ai-soc-agent
```

**Expected:**
```
Smoke test passed: MCP tools discovered
  zeek-mcp:     16 tools
  suricata-mcp: 18 tools
  wazuh-mcp:    11 tools
  mitre-mcp:    9 tools
  Total:        54 tools
```

## 3.8 Start Agent with PM2

```bash
cd ai-soc-agent

pm2 start dist/server.js   --name ai-soc-agent   --env production   --max-memory-restart 400M   --restart-delay 3000   --max-restarts 10

pm2 save
pm2 startup
# Run the command pm2 prints with sudo
```

## 3.9 Health Check

```bash
curl http://localhost:3000/health | python3 -m json.tool
```

**Expected:**
```json
{
  "status": "ok",
  "service": "ai-soc-agent",
  "ai_provider": "gemini",
  "model": "gemini-2.5-flash",
  "readonly_mcp": true,
  "tools": 54
}
```

## 3.10 Phase 3 Deliverables
```
□ NFS server on sensor VM exporting to 100.64.0.2
□ NFS mounts on Wazuh VM working and persistent in fstab
□ Node.js v20 + PM2 installed
□ Monorepo cloned, built, 5 dist files exist
□ .env configured and in .gitignore
□ Smoke test passes with 54 tools
□ Agent running under PM2
□ /health returns status ok, tools 54
```

---

# Phase 4 — AI Agent Development (Weeks 7–8)

## 4.1 System Prompt Verification

Verify these 7 policy lines in `ai-soc-agent/src/prompts/systemPrompt.ts`:

1. "Always start with Wazuh context when Wazuh tools are available"
2. "Always map suspected behavior to MITRE ATT&CK"
3. "Query Zeek and Suricata ONLY when Wazuh/MITRE evidence is inconclusive"
4. "confidence >= 80 means auto-block"
5. "40-79 confidence means analyst-review"
6. "confidence < 40 means monitor"
7. "The agent only recommends action; n8n performs pfSense/Telegram/Wazuh response"

## 4.2 Response Schema Verification

Verify `ai-soc-agent/src/types.ts` has these fields:

| Field | Type | Allowed Values |
|---|---|---|
| `decision.action` | string | `auto-block`, `analyst-review`, `monitor` |
| `decision.confidence` | number | 0–100 |
| `decision.mitre_technique` | string | Any valid MITRE ID |
| `decision.threat_type` | string | `brute-force`, `c2`, `lateral-movement`, `web-attack`, `ddos`, `unknown` |
| `decision.recommended_block_duration` | string | `none`, `1h`, `24h`, `7d`, `permanent` |

## 4.3 Fallback Logic Fix (CRITICAL)

In `ai-soc-agent/src/llm/GeminiSocReasoner.ts`, the `fallbackDecision` function must have:

```typescript
if (severity >= 10) {
  return socDecisionSchema.parse({
    threat_confirmed: true,
    confidence: 85,        // Was 75, now 85 for auto-block
    action: "auto-block",  // Was "analyst-review", now "auto-block"
    // ... rest of fields
  });
}

if (severity >= 8) {
  return socDecisionSchema.parse({
    threat_confirmed: true,
    confidence: 75,
    action: "analyst-review",
    // ...
  });
}

if (severity >= 5) {
  return socDecisionSchema.parse({
    threat_confirmed: true,
    confidence: 60,
    action: "analyst-review",
    // ...
  });
}

// severity < 5
return socDecisionSchema.parse({
  threat_confirmed: false,
  confidence: 30,
  action: "monitor",
  // ...
});
```

## 4.4 Three-Path Smoke Test

### TEST 1 — Fast Path: SSH Brute Force → auto-block
```bash
curl -s -X POST http://localhost:3000/investigate   -H "Content-Type: application/json"   -d '{
    "alert_id": "PHASE4-TEST-001",
    "src_ip": "203.0.113.55",
    "alert_type": "ssh-bruteforce",
    "rule_id": "100001",
    "severity": 10,
    "timestamp": "2026-06-09T12:00:00Z"
  }' | python3 -m json.tool
```
**Expected:** `action: "auto-block"`, `confidence >= 80`, `duration_ms ~5000`

### TEST 2 — Deep Path: Ambiguous → analyst-review
```bash
curl -s -X POST http://localhost:3000/investigate   -H "Content-Type: application/json"   -d '{
    "alert_id": "PHASE4-TEST-002",
    "src_ip": "192.168.80.50",
    "alert_type": "suspicious-outbound",
    "rule_id": "31101",
    "severity": 5,
    "timestamp": "2026-06-09T03:15:00Z"
  }' | python3 -m json.tool
```
**Expected:** `action: "analyst-review"`, `confidence 40-79`, `duration_ms ~5000-15000`

### TEST 3 — Low Severity → monitor
```bash
curl -s -X POST http://localhost:3000/investigate   -H "Content-Type: application/json"   -d '{
    "alert_id": "PHASE4-TEST-003",
    "src_ip": "192.168.80.100",
    "alert_type": "web-scan",
    "rule_id": "31151",
    "severity": 2,
    "timestamp": "2026-06-09T09:00:00Z"
  }' | python3 -m json.tool
```
**Expected:** `action: "monitor"`, `confidence < 40`, `duration_ms ~5000`

## 4.5 Phase 4 Deliverables
```
□ System prompt reviewed and matches thesis policy
□ npm run build passes with zero errors
□ Smoke test discovers 54 MCP tools
□ Agent running on port 3000 via PM2 with memory limit
□ /health returns status ok, tools 54, readonly_mcp true
□ /tools returns all 4 MCP server tool lists
□ /investigate returns valid InvestigationResponse
□ All 3 decision paths verified with test curls
□ PM2 save and startup configured for reboot survival
□ .env is in .gitignore and NEVER committed
```

---

# Phase 5 — SOAR Pipeline & n8n (Weeks 9–10)

## 5.1 n8n Deployment

```bash
# On 100.64.0.2
sudo npm install -g n8n

sudo tee /etc/systemd/system/n8n.service << 'EOF'
[Unit]
Description=n8n workflow automation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=azureuser
Environment=N8N_PORT=5678
Environment=N8N_HOST=0.0.0.0
Environment=N8N_PROTOCOL=http
Environment=WEBHOOK_URL=http://localhost:5678
Environment=N8N_BASIC_AUTH_ACTIVE=false
ExecStart=/usr/bin/env n8n start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable n8n
sudo systemctl start n8n
```

> ⚠️ **First launch:** Visit `http://100.64.0.2:5678` and create an owner account.

## 5.2 Telegram Bot Setup

```
1. Open Telegram → search @BotFather
2. Send: /newbot
3. Name: SOC Alert Bot
4. Username: your_soc_alert_bot (must end in 'bot')
5. Copy API token → save as TELEGRAM_BOT_TOKEN
6. Send /start to your bot
7. Get chat ID: https://api.telegram.org/bot<TOKEN>/getUpdates
```

## 5.3 pfSense Pre-Configuration

```
# In pfSense WebGUI (https://192.168.80.10)

# Step 1: Create blocklist alias
Firewall → Aliases → IP → Add
  Name: ai_soc_blocklist
  Type: Host(s)
  Description: Managed by AI SOC Agent via API

# Step 2: Create block rule
Firewall → Rules → WAN → Add
  Action: Block
  Interface: WAN
  Protocol: Any
  Source: Single host or alias → ai_soc_blocklist
  Destination: Any
  Description: AI SOC Agent auto-block rule

# Step 3: Create whitelist alias (CRITICAL)
Firewall → Aliases → IP → Add
  Name: ai_soc_whitelist
  Type: Host(s)
  Description: Never block these IPs
  IP/FQDN:
    - 100.64.0.4 (Kali)
    - 100.64.0.1 (your laptop Tailscale IP)
    - Your home public IP (curl ifconfig.me)

# Step 4: Create whitelist rule (MUST be ABOVE block rule)
Firewall → Rules → WAN → Add
  Action: Pass
  Interface: WAN
  Protocol: Any
  Source: Single host or alias → ai_soc_whitelist
  Destination: Any
  Description: AI SOC Agent whitelist — never block

# Step 5: Verify rule order
# Whitelist rule MUST be above blocklist rule. Drag to reorder if needed.
```

## 5.4 n8n Workflow — 11 Nodes

### Node 1 — Webhook Trigger
```
Type: Webhook
HTTP Method: POST
Path: wazuh-alert
Authentication: None
Response Mode: Last Node
Response Code: 200
```

### Node 2 — Extract Alert Fields (Set)
```
Fields:
  src_ip      = {{ $json.body.data.srcip || $json.body.data.src_ip }}
  alert_type  = {{ $json.body.rule.description }}
  alert_id    = {{ $json.body.id }}
  rule_id     = {{ $json.body.rule.id }}
  severity    = {{ $json.body.rule.level }}
  timestamp   = {{ $json.body.timestamp }}
  raw_alert   = {{ JSON.stringify($json.body) }}
```

### Node 3 — Call AI Agent (HTTP Request)
```
Method: POST
URL: http://localhost:3000/investigate
Body (JSON):
{
  "alert_id": "={{ $json.alert_id }}",
  "src_ip": "={{ $json.src_ip }}",
  "alert_type": "={{ $json.alert_type }}",
  "rule_id": "={{ $json.rule_id }}",
  "severity": "={{ $json.severity }}",
  "timestamp": "={{ $json.timestamp }}",
  "raw_alert": "={{ $json.raw_alert }}"
}
Timeout: 60000
```

### Node 4 — Parse Agent Decision (Set)
```
Fields:
  investigation_id   = {{ $json.investigation_id }}
  duration_ms      = {{ $json.duration_ms }}
  confidence       = {{ $json.decision.confidence }}
  action           = {{ $json.decision.action }}
  src_ip           = {{ $json.decision.src_ip }}
  mitre_technique  = {{ $json.decision.mitre_technique }}
  mitre_tactic     = {{ $json.decision.mitre_tactic }}
  report           = {{ $json.decision.incident_report }}
  threat_type      = {{ $json.decision.threat_type }}
  block_duration   = {{ $json.decision.recommended_block_duration }}
  threat_confirmed = {{ $json.decision.threat_confirmed }}
```

### Node 5 — Confidence Switch
```
Rule 1 (Output 0): {{ $json.confidence }} >= 80  → auto-block path
Rule 2 (Output 1): {{ $json.confidence }} >= 40  → analyst-review path
Rule 3 (Output 2): (fallback)                    → monitor path
```

### Node 6a — AbuseIPDB Enrichment (HTTP Request)
```
Method: GET
URL: https://api.abuseipdb.com/api/v2/check
Query: ipAddress={{ $('Parse Agent Decision').item.json.src_ip }}, maxAgeInDays=90
Headers: Key: {{ $env.ABUSEIPDB_API_KEY }}, Accept: application/json
```

### Node 6b — VirusTotal Enrichment (HTTP Request)
```
Method: GET
URL: https://www.virustotal.com/api/v3/ip_addresses/{{ $('Parse Agent Decision').item.json.src_ip }}
Headers: x-apikey: {{ $env.VIRUSTOTAL_API_KEY }}
```

### Node 7 — Merge Enrichment (Merge)
```
Mode: Combine
```

### Node 8a — pfSense Block (HTTP Request) — from Switch Output 0
```
Method: POST
URL: https://192.168.80.10/api/v2/firewall/alias
Auth: Header Auth, Name: Authorization, Value: Bearer {{ $env.PFSENSE_API_TOKEN }}
Body (JSON):
{
  "name": "ai_soc_blocklist",
  "type": "host",
  "address": [{"value": "{{ $('Parse Agent Decision').item.json.src_ip }}"}],
  "detail": [{"value": "AI SOC Agent block - {{ $now }}"}]
}
Options: Ignore SSL Issues: true
```

### Node 8b — Apply pfSense Rules (HTTP Request)
```
Method: POST
URL: https://192.168.80.10/api/v2/firewall/apply
Auth: Header Auth, Name: Authorization, Value: Bearer {{ $env.PFSENSE_API_TOKEN }}
Body: {}
Options: Ignore SSL Issues: true
```

### Node 9 — Telegram Alert (Telegram)
```
Credential: Your Bot Token
Operation: Send Message
Chat ID: {{ $env.TELEGRAM_CHAT_ID }}
Text:
🚨 SECURITY ALERT — {{ $('Parse Agent Decision').item.json.threat_type.toUpperCase() }}

📍 Source IP: {{ $('Parse Agent Decision').item.json.src_ip }}
🎯 Confidence: {{ $('Parse Agent Decision').item.json.confidence }}%
⚡ Action: {{ $('Parse Agent Decision').item.json.action.toUpperCase() }}
🗺️ MITRE: {{ $('Parse Agent Decision').item.json.mitre_technique }}
⏱ Duration: {{ $('Parse Agent Decision').item.json.duration_ms }}ms

📋 Report:
{{ $('Parse Agent Decision').item.json.report }}

🛡️ AbuseIPDB: {{ $('Merge Enrichment').item.json.data.abuseConfidenceScore || 'N/A' }}%
🦠 VT: {{ $('Merge Enrichment').item.json.data.data.attributes.last_analysis_stats.malicious || 'N/A' }}/90

{{ $('Parse Agent Decision').item.json.action == 'auto-block' ? '✅ Auto-blocked' : '⏳ Reply /approve or /deny' }}
```

### Node 10 — Analyst Approval (Telegram Trigger + IF)
```
Telegram Trigger: Message Received
IF Node: {{ $json.message.text == '/approve' }}
  TRUE → Execute pfSense block (same as Node 8a)
  FALSE → Send "❌ Block denied. Alert logged."

Wait Node: 5 minutes timeout
  If no response → auto-escalate if confidence 70-79%
```

### Node 11 — Error Handler (Error Trigger → Telegram)
```
Error Trigger → Telegram Send Message
Text: ❌ n8n error on alert {{ $json.alert_id }}: {{ $json.error.message }}
```

## 5.5 Wazuh Decision Logging

```bash
# Back to Wazuh Indexer
Method: POST
URL: https://localhost:9200/ai-soc-decisions/_doc
Auth: Basic admin / {{ $env.WAZUH_INDEXER_PASSWORD }}
Body (JSON):
{
  "event": "AI_SOC_AGENT_DECISION",
  "src_ip": "{{ $('Parse Agent Decision').item.json.src_ip }}",
  "action": "{{ $('Parse Agent Decision').item.json.action }}",
  "confidence": {{ $('Parse Agent Decision').item.json.confidence }},
  "mitre_technique": "{{ $('Parse Agent Decision').item.json.mitre_technique }}",
  "duration_ms": {{ $('Parse Agent Decision').item.json.duration_ms }},
  "investigation_id": "{{ $('Parse Agent Decision').item.json.investigation_id }}",
  "timestamp": "{{ $now }}"
}
Options: Ignore SSL Issues: true
```

## 5.6 Phase 5 Deliverables
```
□ n8n running on port 5678
□ n8n owner account created
□ Telegram bot created, token and chat_id saved
□ pfSense ai_soc_blocklist alias created
□ pfSense ai_soc_whitelist alias created (CRITICAL)
□ pfSense block rule using blocklist
□ pfSense whitelist rule ABOVE block rule
□ All 11 n8n nodes configured and connected
□ Error handler node added
□ AbuseIPDB and VirusTotal API keys saved as credentials
□ End-to-end test: manual curl → Telegram message received
□ Auto-block test: high confidence → pfSense alias updated
□ Analyst-review test: /approve → pfSense block applied
□ Wazuh logging final decisions
□ Full pipeline timing: alert → block < 30 seconds
```

---

# Phase 6 — Attack Simulation & Validation (Weeks 11–12)

## 6.1 Pre-Attack Safety Checklist

```bash
# Safety Rule 1: Whitelist Kali VM
# In pfSense: Firewall → Rules → WAN → Add at TOP
# Action: Pass, Source: 100.64.0.4, Description: Kali whitelist

# Safety Rule 2: VM Snapshots
# pfsense-vlans-span-done
# zeek-suricata-running
# wazuh-agent-enrolled
# all-mcp-servers-running
# n8n-workflow-complete

# Safety Rule 3: One attack at a time
# Safety Rule 4: Only attack DVWA (192.168.80.13)
# Safety Rule 5: Have console access ready
```

## 6.2 Metrics Collection Spreadsheet

| attack_name | attack_start_time | wazuh_alert_time | agent_decision_time | action_taken | confidence | duration_ms | block_applied_time | correct_decision | mttd_seconds | mttr_seconds |
|---|---|---|---|---|---|---|---|---|---|---|
| SSH Brute Force | | | | | | | | | | |
| SQL Injection | | | | | | | | | | |
| DDoS SYN Flood | | | | | | | | | | |
| C2 DNS Beaconing | | | | | | | | | | |
| Lateral Movement | | | | | | | | | | |

**Formulas:**
```
MTTD = wazuh_alert_time - attack_start_time
MTTR = block_applied_time - wazuh_alert_time
Detection Rate = (attacks with wazuh_alert_time) / 5 × 100
False Positive Rate = (wrong auto-blocks) / (total auto-blocks) × 100
Agent Accuracy = (correct_decision == "Yes") / 5 × 100
```

## 6.3 Attack Scenarios

### Attack 1 — SSH Brute Force
```bash
# On Kali (100.64.0.4)
echo "Attack 1 started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.80.13 -t 10 -V
# Expected: auto-block, confidence >=80, MITRE T1110.001, MTTD <30s, MTTR <15s
```

### Attack 2 — SQL Injection
```bash
# On Kali (100.64.0.4)
echo "Attack 2 started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
# DVWA: Security Level LOW
sqlmap -u "http://192.168.80.13/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"   --cookie="PHPSESSID=YOUR_SESSION;security=low" --batch --level=3 --risk=2
# Expected: auto-block, MITRE T1190
```

### Attack 3 — DDoS SYN Flood
```bash
# On Kali (100.64.0.4)
echo "Attack 3 started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
timeout 30 sudo hping3 -S --flood -V -p 80 192.168.80.13
# Expected: auto-block, MITRE T1498
```

### Attack 4 — C2 DNS Beaconing
```bash
# On Kali (100.64.0.4)
cat > ~/c2_dns_beacon.sh << 'EOF'
#!/bin/bash
TARGET_DOMAIN="beacon.test"
for i in {1..10}; do
  SUBDOMAIN=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 35)
  dig +short ${SUBDOMAIN}.${TARGET_DOMAIN} @192.168.80.10
  sleep $((25 + RANDOM % 10))
done
EOF
chmod +x ~/c2_dns_beacon.sh
./c2_dns_beacon.sh
# Expected: analyst-review or auto-block, MITRE T1071.004
```

### Attack 5 — Lateral Movement
```bash
# From Windows VM (192.168.80.14) — most realistic
nmap -sS -T4 -p 22,80,443,3306,5432,8080 192.168.80.0/24
# Expected: analyst-review, MITRE T1046
```

## 6.4 Baseline Comparison (Suricata-Only)

```bash
# Step 1: Disable AI agent workflow in n8n
# Step 2: Temporarily disable Wazuh webhook
# Step 3: Run all 5 attacks, record detection only
# Step 4: Re-enable everything
# Step 5: Run all 5 attacks AGAIN with AI agent
# Step 6: Fill comparison table
```

| Metric | Suricata-Only | AI Agent Pipeline | Improvement |
|---|---|---|---|
| Detection Rate | X% | Y% | Y - X = Δ |
| Avg MTTD | Xs | Ys | X - Y = Δ |
| Avg MTTR | N/A (manual) | Ys | Your contribution |
| False Positives | X | Y | X - Y = Δ |
| Auto-response Rate | 0% | Y% | Your contribution |

## 6.5 Demo Video Recording (10–15 minutes)

```
0:00  — Title slide
0:30  — Architecture diagram
1:00  — Live dashboard: Wazuh healthy
1:30  — Live dashboard: n8n workflow visible
2:00  — Attack 1: SSH Brute Force (Kali → Wazuh alert → n8n → Telegram → pfSense block)
4:00  — Attack 2: SQL Injection
6:00  — Attack 3: DDoS
7:30  — Attack 4: C2 Beaconing (deep path, analyst-review)
9:30  — Attack 5: Lateral Movement
11:00 — Metrics spreadsheet
11:30 — Baseline comparison table
12:00 — Conclusion: "MTTR reduced from 30 min to < 30 sec"
```

> 🔴 **ALWAYS have backup video. Never rely solely on live demo.**

## 6.6 Thesis Chapter Writing Order

```
Week 11, Day 1-2:  Chapter 3 — System Architecture
Week 11, Day 3-4:  Chapter 4 — Implementation
Week 11, Day 5-6:  Chapter 5 — Experimental Methodology
Week 11, Day 7:    Chapter 6 — Results and Analysis
Week 12, Day 1-2:  Chapter 2 — Literature Review
Week 12, Day 3-4:  Chapter 1 — Introduction
Week 12, Day 5-6:  Chapter 7 — Discussion
Week 12, Day 5-6:  Chapter 8 — Conclusion
Week 12, Day 7:    Abstract, TOC, References
```

## 6.7 Key Thesis Argument

> "This project reduces Mean Time to Respond (MTTR) from 20–40 minutes (industry benchmark for human analysts) to under 30 seconds, while maintaining a Detection Rate ≥ 80% and False Positive Rate ≤ 15%, by using a Wazuh-Primary Hybrid AI agent with MCP-based cross-sensor validation."

## 6.8 Phase 6 Deliverables
```
□ All 5 attacks executed with timestamps recorded
□ Baseline (Suricata-only) results recorded
□ Metrics spreadsheet complete
□ Comparison table: AI Agent vs Suricata-Only
□ Demo video recorded (10-15 minutes)
□ Backup video saved to cloud storage
□ All 8 thesis chapters written
□ Abstract written (250-300 words)
□ References formatted (IEEE or APA)
□ Final system snapshots saved
□ Code repository frozen (GitHub release/tag)
```

---

# Global Risk Register

| Risk | Severity | Mitigation |
|---|---|---|
| `.env` committed to GitHub | 🔴 HIGH | Check `.gitignore` before first commit. Run `git diff --cached \| grep -i key` before every push. |
| Gemini API rate limit during demo | 🟠 MEDIUM | Free tier: ~60 RPM. Test during off-peak. Have backup video. |
| Gemini API down during defense | 🔴 HIGH | Pre-recorded backup video. Test 48 hours before defense. |
| n8n workflow crashes on malformed response | 🟠 MEDIUM | Add Error Trigger node after AI Agent HTTP node. |
| Telegram approval timeout | 🟠 MEDIUM | Add 5-minute Wait node. Auto-escalate if no response. |
| pfSense blocks your Kali IP | 🔴 HIGH | Whitelist `100.64.0.4` at TOP of pfSense rules before ANY attack. |
| pfSense API token expires | 🟠 MEDIUM | Token lasts until revoked. Document generation in thesis appendix. |
| MCP child process spawns slowly | 🟡 LOW | Normal — first call takes 10–15s. Subsequent calls faster. |
| Wazuh webhook not triggering n8n | 🟠 MEDIUM | Test with `curl -X POST http://localhost:5678/webhook/wazuh-alert -d '{}'` |
| Sensor VM Tailscale IP changes | 🟡 LOW | Tailscale IPs are stable. Update `/etc/exports` if needed. |
| NFS mount fails after VM reboot | 🟠 MEDIUM | Use `_netdev` fstab option. |
| Azure VM deallocated | 🟡 LOW | Document: `az vm start --name wazuh-server --resource-group YOUR_RG` |
| DVWA session expires during SQLi | 🟡 LOW | Save PHPSESSID. Set session timeout to 3600s. |
| VM disk space exhausted | 🟠 MEDIUM | Set Zeek log rotation to 7 days. Monitor weekly. |
| Tailscale disconnects mid-test | 🟡 LOW | Auto-reconnects within seconds. |
| Laptop powers off during live demo | 🔴 HIGH | Record backup video in Week 11. |
| Thesis plagiarism check fails | 🔴 HIGH | Write your own analysis. Cite all sources. Use Turnitin. |

---

# Daily Operations Quick Reference

```bash
# Check all services
pm2 status
sudo systemctl status wazuh-manager --no-pager | head -4
sudo systemctl status wazuh-indexer --no-pager | head -4
sudo systemctl status n8n --no-pager | head -4

# Check NFS mounts
df -h | grep mnt
ls /mnt/zeek-logs/ && echo "Zeek OK"
ls /mnt/suricata-logs/eve.json && echo "Suricata OK"

# Test full pipeline
curl -s -X POST http://localhost:3000/investigate   -H "Content-Type: application/json"   -d '{"alert_id":"DAILY-CHECK","src_ip":"203.0.113.100","alert_type":"ssh-bruteforce","rule_id":"100001","severity":10,"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}'   | python3 -m json.tool | grep -E "action|confidence|duration"

# Rebuild after code changes
cd ~/Final-Year-Gradution-Project-
git pull
npm run build
pm2 restart ai-soc-agent

# Check for exposed secrets before push
git diff --cached | grep -iE "key|password|token|secret|api"
# MUST return nothing
```

---

# Final Success Criteria

## Minimum Viable Project (Must Achieve All)
```
□ Full pipeline runs end-to-end without manual intervention
□ At least 4 of 5 attacks detected (DR ≥ 80%)
□ MTTR < 30 seconds for auto-block path
□ Agent produces valid JSON for every alert
□ MITRE ATT&CK tags on all confirmed threats
□ Comparison table: AI Agent vs Suricata-only complete
□ Demo video recorded and backed up
```

## Full Project (Achieve As Many As Possible)
```
□ FPR < 15%
□ Agent accuracy ≥ 85%
□ Deep-path correctly resolves at least 1 ambiguous case
□ Telegram analyst-approval flow demonstrated live
□ AbuseIPDB + VirusTotal enrichment in all alerts
□ 10-minute demo video showing full attack-to-block cycle
□ All 8 thesis chapters written and reviewed
□ Thesis successfully defended
```

---

*Complete Corrected Milestone Guide*
*Project: AI-Powered SOC Agent NIDS for E-Commerce*
*Author: Mohammed ALwadiya — Final Year Graduation Project*
*Generated: June 2026*
*Replaces: NIDS_Full_Milestone_Guide.md*
