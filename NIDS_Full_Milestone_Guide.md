# 🛡️ AI-Powered SOC Agent NIDS — Full Milestone & Configuration Guide

> **Project:** Design and Implementation of an AI-Powered SOC Agent Using MCP Servers for Intelligent Intrusion Detection and Automated Response in E-Commerce Environments  
> **Stack:** pfSense · Zeek · Suricata · Wazuh · n8n · Google Gemini · MCP Servers  
> **Network:** VMware Workstation (Laptop) + Azure (Tailscale mesh)  
> **Duration:** 12 Weeks · 6 Phases  
> **Architecture:** Wazuh-Primary Hybrid AI Agent  

---

## 📑 Table of Contents

1. [Project Overview](#1-project-overview)
2. [Infrastructure Map](#2-infrastructure-map)
3. [Phase 1 — Infrastructure & Network Foundation](#3-phase-1--infrastructure--network-foundation-weeks-12)
4. [Phase 2 — Detection Rule Engineering](#4-phase-2--detection-rule-engineering-weeks-34)
5. [Phase 3 — MCP Server Setup](#5-phase-3--mcp-server-setup-weeks-56)
6. [Phase 4 — AI Agent Development](#6-phase-4--ai-agent-development-weeks-78)
7. [Phase 5 — SOAR Pipeline & n8n](#7-phase-5--soar-pipeline--n8n-weeks-910)
8. [Phase 6 — Attack Simulation & Validation](#8-phase-6--attack-simulation--validation-weeks-1112)
9. [Global Risk Register](#9-global-risk-register)
10. [Accounts & Tools Checklist](#10-accounts--tools-checklist)
11. [Metrics & Success Criteria](#11-metrics--success-criteria)

---

## 1. Project Overview

### Architecture — Wazuh-Primary Hybrid

The agent uses a two-path investigation model. Wazuh is always queried first because it already aggregates and correlates data from both Zeek and Suricata. The agent only queries Zeek and Suricata directly when Wazuh data is ambiguous.

```
ALERT ARRIVES
      │
      ▼
   ┌─────┐
   │ n8n │  ← Receives Wazuh webhook, triggers investigation
   └──┬──┘
      │
      ▼
┌───────────────────────────────────────────────────┐
│              AI SOC AGENT                         │
│                                                   │
│  STEP 1 — ALWAYS (Fast Path)                      │
│  wazuh-mcp: get_alerts + search_alerts            │
│  mitre-mcp: map_technique                         │
│  → Calculate preliminary confidence               │
│                                                   │
│  STEP 2 — CONDITIONAL (Deep Path)                 │
│  ONLY if confidence = 40–79%                      │
│  zeek-mcp:     behavioral analysis                │
│  suricata-mcp: raw alert detail                   │
│  → Recalculate final confidence                   │
│                                                   │
│  STEP 3 — ALWAYS                                  │
│  Output structured JSON decision                  │
└───────────────────────────────────────────────────┘
      │
      ▼
   ┌─────┐
   │ n8n │  ← Executes: block / notify / log
   └──┬──┘
      │
  ┌───┼───────────┐
  ▼   ▼           ▼
pfSense  Telegram  Wazuh
(block)  (alert)   (log)
```

### Confidence Decision Table

| Confidence | Path | Action | Avg Time |
|---|---|---|---|
| ≥ 80% | Fast Path | `auto-block` | ~3 seconds |
| 40–79% | Deep Path | `analyst-review` | ~8 seconds |
| < 40% | Fast Path | `monitor` | ~3 seconds |

### MCP Server Roles

The current code does not expose the MCP servers as HTTP services on ports 3001-3004. The AI agent starts each MCP server as a local stdio child process through `McpHub`.

| MCP Server | Transport | Called When | Key Tools |
|---|---|---|---|
| `wazuh-mcp` | stdio child process | Every alert | `wazuh__get_alerts`, `wazuh__search_alerts`, rules/syscheck/diagnostics tools |
| `mitre-mcp` | stdio child process | Every alert | `mitre__mitre_map_alert_to_technique`, ATT&CK technique/tactic tools |
| `zeek-mcp` | stdio child process | Confidence 40-79% only | `zeek__zeek_ssh_bruteforce`, `zeek__zeek_detect_beaconing`, `zeek__zeek_suspicious_http`, `zeek__zeek_detect_anomalies` |
| `suricata-mcp` | stdio child process | Confidence 40-79% only | `suricata__suricata_query_alerts`, `suricata__suricata_beaconing_detection`, `suricata__suricata_lateral_movement_detection` |

The only HTTP service exposed by the current project is the AI agent:

- `GET /health`
- `GET /tools`
- `POST /investigate`

---

## 2. Infrastructure Map

### VM Inventory

| VM | Location | OS | CPU | RAM | Disk | IP Address | Role |
|---|---|---|---|---|---|---|---|
| pfSense | VMware Local | pfSense 2.7 | 2 | 2 GB | 20 GB | `192.168.80.10` | Firewall + Gateway + VLAN + SPAN |
| Zeek + Suricata | VMware Local | Ubuntu 22.04 | 4 | 4 GB | 50 GB | `192.168.80.11` | Detection Engine |
| Agent/MCP Runtime | Azure or VMware | Ubuntu 22.04 | 2 | 4 GB | 30 GB | Prefer `100.64.0.3` with the AI Agent | Repo checkout; AI agent spawns all 4 MCP servers over stdio |
| DVWA Web Server | VMware Local | Ubuntu 22.04 | 2 | 2 GB | 20 GB | `192.168.80.13` | Attack Target (DMZ) |
| Windows Client | VMware Local | Windows 10 | 2 | 4 GB | 60 GB | `192.168.80.14` | Insider Threat Sim |
| Wazuh Server | Azure | Ubuntu 22.04 | 4 | 8 GB | 100 GB | `100.64.0.2` (Tailscale) | SIEM |
| n8n + AI Agent | Azure | Ubuntu 22.04 | 2 | 4 GB | 30 GB | `100.64.0.3` (Tailscale) | SOAR + Agent |
| Kali Linux | Azure | Kali 2024 | 2 | 4 GB | 30 GB | `100.64.0.4` (Tailscale) | Attacker |

### Network Segmentation

```
pfSense VLANs:
  DMZ  VLAN10  →  192.168.80.13  (DVWA Web Server)
  LAN  VLAN20  →  192.168.80.14  (Windows Client)
  MGMT VLAN30  →  192.168.80.11  (Zeek+Suricata)
                  192.168.80.12  (optional repo/runtime VM; no HTTP MCP ports)

Tailscale Overlay (WireGuard encrypted):
  Laptop (Subnet Router)  →  100.64.0.1
  Wazuh Server            →  100.64.0.2
  n8n + AI Agent          →  100.64.0.3
  Kali Linux              →  100.64.0.4

Laptop advertises 192.168.80.0/24 via Tailscale subnet routing.
Azure VMs reach all local VMs using 192.168.80.x directly.
```

### Port Reference

```
MCP runtime:
  Current code uses stdio MCP child processes spawned by ai-soc-agent.
  No MCP HTTP ports 3001-3004 are exposed.

Azure Services (on 100.64.0.2 / 100.64.0.3):
  Wazuh API     → :55000
  Wazuh Indexer → :9200
  Wazuh Dashboard → :443
  n8n           → :5678
  AI Agent      → :3000

pfSense API (on 192.168.80.10):
  pfSense API   → :443
```

---

## 3. Phase 1 — Infrastructure & Network Foundation (Weeks 1–2)

### Objectives
- Deploy all 7 VMs with correct networking
- Configure pfSense VLANs and SPAN mirroring
- Install and verify Zeek and Suricata
- Set up Tailscale hybrid connectivity
- Deploy Wazuh server and enroll first agent

---

### 3.1 VMware Workstation Configuration

**Before creating any VM:**

```
VMware Workstation → Edit → Virtual Network Editor
  → Change VMnet8 (NAT) subnet to: 192.168.80.0
  → Subnet mask: 255.255.255.0
  → Apply

All VMs → Settings → Network Adapter → NAT
  (Use NAT for every VM — not Bridged, not Host-only)
```

**VM creation order:**
```
1. pfSense      (ISO: pfSense-CE-2.7.x-amd64.iso)
2. Ubuntu VMs   (ISO: ubuntu-22.04-server-amd64.iso) — create 4 copies
3. Windows 10   (ISO: Windows 10 evaluation)
```

---

### 3.2 pfSense Configuration

**Initial setup via console:**
```
WAN interface → em0 (gets DHCP from VMware NAT: 192.168.80.x)
LAN interface → em1 (set static: 192.168.80.10/24)
```

**VLAN configuration (WebGUI → Interfaces → Assignments → VLANs):**
```
VLAN 10  →  Parent: em1  →  Tag: 10  →  Description: DMZ
VLAN 20  →  Parent: em1  →  Tag: 20  →  Description: LAN
VLAN 30  →  Parent: em1  →  Tag: 30  →  Description: MGMT
```

**SPAN mirror for Zeek/Suricata (WebGUI → Interfaces → Assignments):**
```
Add interface em2 → rename to SPAN
Interfaces → SPAN → Enable → Static IP → 192.168.80.50/24

SPAN Mirror Setup (for Zeek/Suricata packet capture):

Method 1 - Dedicated NIC (Recommended):
 1. Add a 3rd NIC to the pfSense VM (em2)
 2. In VMware: Edit VM Settings → Network Adapter 3
    → Connect to: Host-only or Custom (VMnet)
    → Promiscuous Mode: Accept
 3. In pfSense WebGUI: Interfaces → Assignments
    → Add em2, enable it, name it "SPAN"
 4. Connect Zeek/Suricata VM to this same VMnet
 5. Zeek/Suricata will see all traffic on this interface

Method 2 - Port Mirroring (if using managed switch):
  → Configure switch SPAN port to mirror traffic to the Zeek VM port

⚠️  The bridge method described in older guides does NOT create a true SPAN mirror for IDS. Zeek and Suricata must see raw packets.
```

**Firewall rules (Firewall → Rules):**
```
DMZ → LAN:    BLOCK  (DMZ cannot initiate to internal)
DMZ → WAN:    ALLOW  (web server needs internet)
LAN → DMZ:    ALLOW  (internal users reach web server)
LAN → WAN:    ALLOW  (internal internet access)
MGMT → ANY:   ALLOW  (management access everywhere)
ANY → MGMT:   BLOCK  (nothing reaches MGMT uninvited)
```

**Install pfSense API package:**
```
System → Package Manager → Available Packages
  → Search: pfSense-pkg-API
  → Install
  → After install: System → API → Enable API → Generate token
  → Save token — you need it in Phase 5
```

> ✅ **Tip:** Take a pfSense VM snapshot after each major config step. Label it clearly: `pfsense-vlans-done`, `pfsense-api-installed`.

> ⚠️ **Risk:** If pfSense WebGUI is unreachable after VLAN setup — connect via console and run `pfctl -d` to temporarily disable firewall, then fix rules.

---

### 3.3 Zeek Installation and Configuration

```bash
# On 192.168.80.11 (Ubuntu 22.04)

# Install Zeek
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install -y zeek

# Configure interface (replace eth1 with your SPAN interface name)
sudo nano /opt/zeek/etc/node.cfg
```

```ini
# /opt/zeek/etc/node.cfg
[zeek]
type=standalone
host=localhost
interface=eth1        # ← SPAN mirror interface (verify with: ip a)
```

```bash
# Configure local networks
sudo nano /opt/zeek/etc/networks.cfg
```

```
192.168.80.0/24    Local VMware network
10.0.0.0/8         Azure private range
```

```bash
# Enable useful scripts in local.zeek
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

```zeek
# Add these lines to local.zeek
@load policy/tuning/defaults
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/http/detect-sqli
@load policy/protocols/dns/detect-external-names
@load policy/frameworks/notice/weird
@load policy/misc/detect-traceroute
@load policy/frameworks/files/hash-all-files
```

```bash
# Deploy and start
sudo /opt/zeek/bin/zeekctl deploy

# Verify logs are generating
tail -f /opt/zeek/logs/current/conn.log
tail -f /opt/zeek/logs/current/http.log
tail -f /opt/zeek/logs/current/dns.log

# If logs are empty — check interface name:
ip a    # find the SPAN mirror interface (usually eth1 or ens37)
```

> ✅ **Tip:** Run `zeekctl status` — if it shows "running" but logs are empty, the SPAN interface is wrong. Try each interface until traffic appears in conn.log.

> ⚠️ **Risk:** Zeek logs rotate hourly. The zeek-mcp server must point to `/opt/zeek/logs/current/` (symlink), not a dated directory.

---

### 3.4 Suricata Installation and Configuration

```bash
# On 192.168.80.11 (same VM as Zeek)

# Install Suricata
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata

# Install Emerging Threats Open rules
sudo suricata-update

# Configure Suricata
sudo nano /etc/suricata/suricata.yaml
```

```yaml
# Key sections to configure in suricata.yaml:

vars:
  address-groups:
    HOME_NET: "[192.168.80.0/24,10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,443,8080,8443"
    SSH_PORTS: "22"

af-packet:
  - interface: eth1       # ← same SPAN interface as Zeek
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
        - stats
```

```bash
# Test configuration syntax
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Start Suricata
sudo systemctl enable suricata
sudo systemctl start suricata

# Verify alerts generating
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool | head -50

# Update rules weekly (add to crontab)
echo "0 3 * * 1 /usr/bin/suricata-update && systemctl reload suricata" \
  | sudo crontab -
```

> ✅ **Tip:** Run `sudo suricata -T -c /etc/suricata/suricata.yaml` before every start. It catches syntax errors instantly. A bad yaml crashes Suricata silently.

> ⚠️ **Risk:** Suricata and Zeek both reading the same SPAN interface can cause packet drops on low-end hardware. If drops appear in `suricata.log`, increase `af-packet` ring-size or dedicate separate VMs.

---

### 3.5 Tailscale Setup

**On your laptop (host OS — Windows or Mac, NOT inside any VM):**

```powershell
# Windows PowerShell (Run as Administrator)

# Step 1: Install Tailscale from https://tailscale.com/download

# Step 2: Enable subnet routing for your VMware network
tailscale up --advertise-routes=192.168.80.0/24 --accept-routes

# Step 3: Check your Tailscale IP
tailscale ip -4
# Example output: 100.64.0.1
```

```bash
# macOS Terminal
tailscale up --advertise-routes=192.168.80.0/24 --accept-routes
```

**In Tailscale web dashboard (https://login.tailscale.com/admin/machines):**
```
→ Find your laptop in the machines list
→ Click the three dots → Edit route settings
→ Enable: 192.168.80.0/24
→ Save

This approves subnet routing — must be done manually.
```

**On each Azure VM:**
```bash
# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Connect to your Tailscale network
sudo tailscale up --accept-routes

# Verify your Tailscale IP
tailscale ip -4
# Wazuh VM:  should get something like 100.64.0.2
# n8n VM:    100.64.0.3
# Kali VM:   100.64.0.4
```

**Verify connectivity:**
```bash
# From Wazuh Azure VM — ping a local VMware VM
ping 192.168.80.11    # Should respond if Tailscale routing works

# From Agent runtime VM — reach Wazuh API
curl http://100.64.0.2:55000
# Should return Wazuh JSON response

# From n8n VM — reach AI agent
curl http://100.64.0.3:3000/health
```

> ✅ **Tip:** If pings work but curl times out — check Azure NSG (Network Security Group). Allow inbound TCP from `100.64.0.0/10` on ports `55000, 9200, 5678, 3000`. The MCP servers do not need inbound ports in the current stdio architecture.

> ⚠️ **Risk:** Your laptop must be powered on for Azure to reach VMware VMs. Document this as a "lab constraint" in your thesis. In production, a dedicated server (Proxmox/ESXi) would eliminate this.

---

### 3.6 Wazuh Server Deployment (Azure VM)

```bash
# On Azure VM — Ubuntu 22.04 (100.64.0.2)
# Minimum: 4 CPU / 8 GB RAM / 100 GB disk

# Download Wazuh installer
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.x/config.yml

# Edit config.yml with your server details
nano config.yml
```

```yaml
# config.yml
nodes:
  indexer:
    - name: node-1
      ip: 127.0.0.1          # Localhost — single node install

  server:
    - name: wazuh-1
      ip: 127.0.0.1

  dashboard:
    - name: dashboard
      ip: 127.0.0.1
```

```bash
# Generate certificates and install
sudo bash wazuh-install.sh --generate-config-files
sudo bash wazuh-install.sh --wazuh-indexer node-1
sudo bash wazuh-install.sh --start-cluster
sudo bash wazuh-install.sh --wazuh-server wazuh-1
sudo bash wazuh-install.sh --wazuh-dashboard dashboard

# Save the admin password printed at the end — you need it
# Access dashboard: https://100.64.0.2 (Tailscale IP)
```

**Enroll Zeek/Suricata VM agent:**
```bash
# On Wazuh server — get enrollment token
sudo /var/ossec/bin/manage_agents

# On 192.168.80.11 (Zeek VM) — install agent
curl -so wazuh-agent.deb \
  "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/$(curl -s https://packages.wazuh.com/4.x/apt/dists/stable/main/binary-amd64/Packages | grep -m1 'Filename:.*wazuh-agent.*amd64.deb' | awk '{print $2}' | xargs basename)"
sudo WAZUH_MANAGER='100.64.0.2' dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

# Download specific Wazuh agent version (check https://packages.wazuh.com for latest)
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb

# Install with Wazuh manager IP
sudo WAZUH_MANAGER='100.64.0.2' dpkg -i wazuh-agent_4.9.2-1_amd64.deb

# Alternative: Use Wazuh deployment wizard
# 1. Open Wazuh Dashboard → Agents → Deploy new agent
# 2. Select OS (Debian/Ubuntu)
# 3. Copy the generated command and run it

# Edit Wazuh agent configuration
sudo nano /var/ossec/etc/ossec.conf

# Add these localfile entries inside <ossec_config>:
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/opt/zeek/logs/current/conn.log</location>
</localfile>

# For Zeek JSON logs (if using json format):
<localfile>
  <log_format>json</log_format>
  <location>/opt/zeek/logs/current/*.log</location>
</localfile>

```bash
sudo systemctl restart wazuh-agent

# Verify in Wazuh dashboard:
# Modules → Security Events → should show Suricata alerts
```

### Phase 1 Deliverables Checklist

```
□ All 7 VMs created with correct IP addresses
□ pfSense: 3 VLANs configured (DMZ/LAN/MGMT)
□ pfSense: SPAN mirror sending traffic to Zeek interface
□ pfSense: API package installed and token generated
□ Zeek: Running, generating conn.log / http.log / dns.log
□ Suricata: Running, generating eve.json alerts
□ Tailscale: Laptop as subnet router, all Azure VMs connected
□ Connectivity test: ping 192.168.80.11 from Azure succeeds
□ Wazuh: Server running, dashboard accessible
□ Wazuh: Zeek/Suricata agent enrolled and active
□ Wazuh: Suricata eve.json alerts visible in dashboard
□ DVWA: Installed and accessible from Kali
□ VM snapshots saved for all components
```

---

## 4. Phase 2 — Detection Rule Engineering (Weeks 3–4)

### Objectives
- Write 5 custom Suricata rules — one per threat type
- Write 5 custom Wazuh correlation rules with MITRE ATT&CK mapping
- Test every rule with its corresponding attack tool
- Verify alerts appear in Wazuh dashboard

---

### 4.1 Custom Suricata Rules

```bash
# On 192.168.80.11
sudo nano /etc/suricata/rules/local.rules
```

```bash
# ── RULE 1: SSH BRUTE FORCE ──────────────────────────────────────
# Detects: Repeated SSH connection attempts from same source
# MITRE: T1110.001 — Brute Force: Password Guessing
# Test with: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.80.13 -t 10
alert tcp any any -> $HOME_NET 22 (
  msg:"CUSTOM SSH BRUTE FORCE ATTEMPT";
  flow:to_server,established;
  threshold: type threshold, track by_src, count 5, seconds 60;
  classtype:attempted-admin;
  sid:9000001;
  rev:1;
  metadata:mitre_technique T1110.001, affected_product OpenSSH;
)

# ── RULE 2: SQL INJECTION ────────────────────────────────────────
# Detects: SQL injection patterns in HTTP URI and body
# MITRE: T1190 — Exploit Public-Facing Application
# Test with: sqlmap -u "http://192.168.80.13/login.php" --forms --batch
alert http any any -> $HTTP_SERVERS any (
 msg:"CUSTOM SQL INJECTION ATTEMPT";
 flow:established,to_server;
 http.uri; content:"union"; fast_pattern; nocase;
 http.uri; pcre:"/union\s+select/i";
 classtype:web-application-attack;
 sid:9000002;
 rev:1;
 metadata:mitre_technique T1190;
)

# ── RULE 3: DDoS SYN FLOOD ───────────────────────────────────────
# Detects: High volume SYN packets from single source
# MITRE: T1498 — Network Denial of Service
# Test with: hping3 -S --flood -V -p 80 192.168.80.13
alert tcp any any -> $HOME_NET any (
  msg:"CUSTOM DDOS SYN FLOOD DETECTED";
  flags:S;
  threshold: type both, track by_src, count 100, seconds 10;
  classtype:denial-of-service;
  sid:9000003;
  rev:1;
  metadata:mitre_technique T1498;
)

# ── RULE 4: C2 DNS BEACONING ─────────────────────────────────────
# Detects: Unusually long DNS queries (possible DNS tunneling/C2)
# MITRE: T1071.004 — Application Layer Protocol: DNS
# Test with: python3 c2_beacon_sim.py
alert dns any any -> any any (
  msg:"CUSTOM SUSPICIOUS LONG DNS QUERY C2";
  dns.query;
  pcre:"/[a-z0-9\-]{30,}\./i";
  threshold: type threshold, track by_src, count 5, seconds 120;
  classtype:trojan-activity;
  sid:9000004;
  rev:1;
  metadata:mitre_technique T1071.004;
)

# ── RULE 5: INTERNAL PORT SCAN (LATERAL MOVEMENT) ────────────────
# Detects: Internal host scanning multiple ports
# MITRE: T1046 — Network Service Discovery
# Test with: nmap -sS -T4 192.168.80.0/24 from Windows VM
alert tcp $HOME_NET any -> $HOME_NET any (
  msg:"CUSTOM INTERNAL PORT SCAN LATERAL MOVEMENT";
  flags:S;
  threshold: type threshold, track by_src, count 20, seconds 5;
  classtype:network-scan;
  sid:9000005;
  rev:1;
  metadata:mitre_technique T1046;
)
```

```bash
# Enable local rules in suricata.yaml
sudo nano /etc/suricata/suricata.yaml
```

```yaml
rule-files:
  - suricata.rules
  - local.rules          # ← Add this line
```

```bash
# Test rule syntax
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Reload rules without restart
sudo kill -USR2 $(pidof suricata)
# Or:
sudo systemctl reload suricata

# Verify rules loaded
sudo suricata --list-rules | grep "CUSTOM"
```

---

### 4.2 Custom Wazuh Correlation Rules

```bash
# On Wazuh server (100.64.0.2)
sudo nano /var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="custom_nids,">
  <!-- SSH Brute Force -->
  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5716</if_matched_sid>
    <same_source_ip />
    <description>SSH Brute Force: 5+ failed logins from $(srcip) in 60s</description>
    <group>authentication_failures,pci_dss_11.4,mitre_t1110.001,</group>
  </rule>

  <!-- SQL Injection -->
  <rule id="100002" level="6">
    <if_sid>31101</if_sid>
    <field name="alert.signature">SQL Injection</field>
    <description>Web Application Attack: $(alert.signature) from $(srcip)</description>
    <group>web_attack,pci_dss_6.6,mitre_t1190,</group>
  </rule>

  <!-- C2 Beaconing -->
  <rule id="100003" level="6">
    <if_sid>31101</if_sid>
    <field name="alert.signature">C2 Beaconing</field>
    <description>C2 Beaconing detected from $(srcip): $(alert.signature)</description>
    <group>malware,c2_beacon,pci_dss_11.4,mitre_t1071.004,</group>
  </rule>

  <!-- DDoS -->
  <rule id="100004" level="6">
    <if_sid>31101</if_sid>
    <field name="alert.signature">DDoS</field>
    <description>DDoS attack detected from $(srcip): $(alert.signature)</description>
    <group>ddos,availability,mitre_t1498,</group>
  </rule>

  <!-- Lateral Movement -->
  <rule id="100005" level="6">
    <if_sid>31101</if_sid>
    <field name="alert.signature">Lateral Movement</field>
    <description>Internal lateral movement scan from $(srcip): $(alert.signature)</description>
    <group>lateral_movement,pci_dss_11.2,mitre_t1046,</group>
  </rule>

  <!-- High Severity SOAR Trigger -->
  <rule id="100010" level="10">
    <if_matched_group>custom_nids</if_matched_group>
    <description>HIGH SEVERITY NIDS EVENT — Triggering SOAR</description>
    <group>soar_trigger,high_severity,</group>
  </rule>
</group>
```

```bash
# Test rules without restart
sudo /var/ossec/bin/ossec-logtest

# Paste a test Suricata log line, verify rule fires:
# Example input:
# {"timestamp":"2026-06-07T10:00:00","event_type":"alert","src_ip":"1.2.3.4","alert":{"signature":"ET SCAN SSH BruteForce","category":"Attempted User Privilege Gain","severity":2}}

# Restart Wazuh manager to apply rules
sudo systemctl restart wazuh-manager

# Verify rules loaded
sudo /var/ossec/bin/ossec-logtest -V | grep "Rules loaded"
```

**Configure Wazuh webhook (to trigger n8n):**

Wazuh's `<integration>` block with `<name>custom-webhook</name>` requires an executable script at `/var/ossec/integrations/custom-webhook`. Create it first:

```bash
sudo tee /var/ossec/integrations/custom-webhook << 'SCRIPT'
#!/usr/bin/env python3
# /var/ossec/integrations/custom-webhook
# Wazuh → n8n webhook integration

import sys
import json
import os
import requests
import logging
from datetime import datetime

# Setup logging
log_file = "/var/ossec/logs/integrations.log"
logging.basicConfig(filename=log_file, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    try:
        # Read alert from stdin (Wazuh passes alert as argument 3)
        alert_file = sys.argv[3] if len(sys.argv) > 3 else None
        if not alert_file or not os.path.exists(alert_file):
            logging.error(f"Alert file not found: {alert_file}")
            sys.exit(1)

        with open(alert_file, 'r') as f:
            alert_json = json.load(f)

        # n8n webhook URL
        hook_url = "http://100.64.0.3:5678/webhook/soc-alert"

        # Send to n8n with timeout and retry
        for attempt in range(3):
            try:
                response = requests.post(
                    hook_url,
                    json=alert_json,
                    timeout=10,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                logging.info(f"Webhook sent successfully: {response.status_code}")
                sys.exit(0)
            except requests.exceptions.RequestException as e:
                logging.warning(f"Webhook attempt {attempt + 1} failed: {e}")
                if attempt < 2:
                    import time
                    time.sleep(2 ** attempt)  # Exponential backoff

        logging.error("All webhook attempts failed")
        sys.exit(1)

    except Exception as e:
        logging.error(f"Integration error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
SCRIPT
sudo chmod 750 /var/ossec/integrations/custom-webhook
sudo chown root:wazuh /var/ossec/integrations/custom-webhook
```

Then add the integration config:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

```xml
<!-- Add inside <ossec_config> -->
<integration>
  <name>custom-webhook</name>
  <hook_url>http://100.64.0.3:5678/webhook/wazuh-alert</hook_url>
  <level>10</level>
  <rule_id>100001,100002,100003,100004,100005,100010</rule_id>
  <alert_format>json</alert_format>
</integration>
```

```bash
sudo systemctl restart wazuh-manager
```

> ✅ **Tip:** Use `ossec-logtest` to test every rule before restarting Wazuh. Paste real log lines and verify the rule ID that fires. Restart is slow — batch your rule changes.

> ⚠️ **Risk:** Rule `if_matched_group` values must exactly match Wazuh's internal group names. Run `cat /var/ossec/etc/rules/*.xml | grep "group name"` to find correct group names for SSH failures on your Wazuh version.

### Phase 2 Deliverables Checklist

```
□ 5 custom Suricata rules in /etc/suricata/rules/local.rules
□ Rules syntax verified: suricata -T passes with no errors
□ Each rule tested with corresponding attack tool from Kali
□ All 5 rules generate alerts in /var/log/suricata/eve.json
□ 5 custom Wazuh rules in /var/ossec/etc/rules/local_rules.xml
□ ossec-logtest confirms each rule fires on matching input
□ MITRE ATT&CK tags visible in Wazuh dashboard alerts
□ Wazuh webhook configured and pointing to n8n URL
□ Rules log spreadsheet updated with test results
```

---

## 5. Phase 3 — MCP Runtime Setup (Weeks 5-6)

### Objectives
- Clone the current monorepo and build all five workspaces
- Configure the AI agent so it can spawn all four MCP servers over stdio
- Give the stdio MCP child processes access to Zeek, Suricata, Wazuh, and MITRE data
- Verify tool discovery through the agent `/health`, `/tools`, and smoke test

---

### 5.1 Use the Current Monorepo

The current project is a single npm workspace repository. Do not fork and deploy four separate HTTP MCP services for this codebase.

```bash
git clone https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-.git
cd Final-Year-Gradution-Project-
```

The repo contains:

```
zeek-mcp/          # stdio MCP server for Zeek logs
suricata-mcp/      # stdio MCP server for Suricata EVE logs
wazuh-mcp/         # stdio MCP server for Wazuh API / Indexer
mitre-mcp/         # stdio MCP server for MITRE ATT&CK
ai-soc-agent/      # Express API; spawns all MCP servers via stdio
```

---

### 5.2 Runtime VM Preparation

Run the current code where the AI agent will live. In the planned lab this is the n8n + AI Agent VM, `100.64.0.3`.

```bash
# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs git
node --version   # must be v20.x.x
npm --version    # must be v10.x.x or newer

# Optional process manager for the AI agent only
sudo npm install -g pm2
```

---

### 5.3 Build All Workspaces

```bash
cd Final-Year-Gradution-Project-
npm install
npm run build
```

Expected build outputs:

```
zeek-mcp/dist/index.js
suricata-mcp/dist/index.js
wazuh-mcp/dist/index.js
mitre-mcp/dist/index.js
ai-soc-agent/dist/server.js
```

---

### 5.4 Configure the Agent and MCP Child Processes

Create the agent environment file from the repo template:

```bash
cp ai-soc-agent/.env.example ai-soc-agent/.env
nano ai-soc-agent/.env
```

Required values:

```env
# Gemini AI
AI_PROVIDER=gemini
GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE
GEMINI_MODEL=gemini-2.5-flash
AI_MAX_TOKENS=1600
AGENT_MAX_TOOL_ROUNDS=8

# Agent HTTP API
NODE_ENV=production
PORT=3000
LOG_LEVEL=info
MCP_READONLY=true

# Local stdio MCP commands
ZEEK_MCP_COMMAND=node
ZEEK_MCP_ARGS=../zeek-mcp/dist/index.js
SURICATA_MCP_COMMAND=node
SURICATA_MCP_ARGS=../suricata-mcp/dist/index.js
WAZUH_MCP_COMMAND=node
WAZUH_MCP_ARGS=../wazuh-mcp/dist/index.js
MITRE_MCP_COMMAND=node
MITRE_MCP_ARGS=../mitre-mcp/dist/index.js

# Sensor logs
ZEEK_LOG_DIR=/opt/zeek/logs/current
ZEEK_LOG_PATH=/opt/zeek/logs/current
ZEEK_LOG_FORMAT=tsv
SURICATA_EVE_LOG=/var/log/suricata/eve.json
EVE_JSON_PATH=/var/log/suricata/eve.json
ZEEK_LOGS_DIR=/opt/zeek/logs/current

# Wazuh
WAZUH_URL=https://100.64.0.2:55000
WAZUH_USERNAME=wazuh-admin
WAZUH_PASSWORD=YOUR_WAZUH_ADMIN_PASSWORD
WAZUH_VERIFY_SSL=false
WAZUH_INDEXER_URL=https://100.64.0.2:9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=YOUR_WAZUH_INDEXER_PASSWORD
WAZUH_INDEXER_VERIFY_SSL=false

# MITRE ATT&CK cache
MITRE_MATRICES=enterprise
```

Important: because the MCP servers are stdio children, they read local paths from the machine where `ai-soc-agent` runs. If Zeek and Suricata run on `192.168.80.11` but the agent runs on `100.64.0.3`, mount the sensor logs onto the agent VM over NFS, SSHF

# On Zeek/Suricata VM (NFS Server):
sudo apt install nfs-kernel-server -y

# Create export directory
sudo mkdir -p /opt/zeek/logs
sudo mkdir -p /var/log/suricata

# Edit exports file
sudo nano /etc/exports

# Add these lines:
/opt/zeek/logs  192.168.80.0/24(ro,sync,no_subtree_check,no_root_squash)
/var/log/suricata  192.168.80.0/24(ro,sync,no_subtree_check,no_root_squash)

# Apply exports
sudo exportfs -a
sudo systemctl restart nfs-kernel-server

# Open firewall (if UFW is active)
sudo ufw allow from 192.168.80.0/24 to any port nfs
sudo ufw allow from 192.168.80.0/24 to any port 2049

# On n8n/Agent VM (NFS Client):
sudo apt install nfs-common -y

# Create mount points
sudo mkdir -p /mnt/zeek-logs
sudo mkdir -p /mnt/suricata-logs

# Add to fstab for persistence
echo '192.168.80.11:/opt/zeek/logs /mnt/zeek-logs nfs defaults 0 0' | sudo tee -a /etc/fstab
echo '192.168.80.11:/var/log/suricata /mnt/suricata-logs nfs defaults 0 0' | sudo tee -a /etc/fstab

# Mount all
sudo mount -a

# Verify
ls -la /mnt/zeek-logs/current/
ls -la /mnt/suricata-logs/

# If permission denied, check NFS server exports and try:
sudo mount -v -t nfs 192.168.80.11:/opt/zeek/logs /mnt/zeek-logsS, or another read-only sync mechanism and point `ZEEK_LOG_DIR` / `SURICATA_EVE_LOG` to those mounted paths.

Example NFS mount:

```bash
# On 192.168.80.11
sudo apt install nfs-kernel-server
echo "/opt/zeek/logs 100.64.0.3(ro,sync,no_subtree_check)" | sudo tee -a /etc/exports
echo "/var/log/suricata 100.64.0.3(ro,sync,no_subtree_check)" | sudo tee -a /etc/exports
sudo exportfs -ra

# On 100.64.0.3
sudo apt install nfs-common
sudo mkdir -p /mnt/zeek-logs /mnt/suricata
sudo mount 192.168.80.11:/opt/zeek/logs /mnt/zeek-logs
sudo mount 192.168.80.11:/var/log/suricata /mnt/suricata
```

Then set:

```env
ZEEK_LOG_DIR=/mnt/zeek-logs/current
ZEEK_LOG_PATH=/mnt/zeek-logs/current
ZEEK_LOGS_DIR=/mnt/zeek-logs/current
SURICATA_EVE_LOG=/mnt/suricata/eve.json
EVE_JSON_PATH=/mnt/suricata/eve.json
```

---

### 5.5 Integration Test — Stdio MCP Tool Discovery

```bash
cd Final-Year-Gradution-Project-
npm run smoke --workspace=ai-soc-agent
```

Expected result:

```
Smoke test passed: MCP tools discovered
```

The current code should discover roughly this tool split:

- Zeek: 16 tools
- Suricata: 18 tools
- Wazuh: 11 tools
- MITRE: 9 tools
- Total: 54 tools in readonly mode

If smoke fails before Wazuh is deployed, set temporary placeholder Wazuh values only for local tool discovery:

```bash
export WAZUH_URL=https://127.0.0.1:55000
export WAZUH_USERNAME=dummy
export WAZUH_PASSWORD=dummy
export WAZUH_VERIFY_SSL=false
npm run smoke --workspace=ai-soc-agent
```

---

### 5.6 Run the AI Agent

```bash
cd Final-Year-Gradution-Project-/ai-soc-agent
npm start
```

Verify:

```bash
curl http://localhost:3000/health
curl http://localhost:3000/tools | python3 -m json.tool | head -40
```

Expected `/health` shape:

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

---

### 5.7 PM2 Production Configuration

Only the AI agent needs PM2. The four MCP servers are child processes created by the agent.

```bash
cd Final-Year-Gradution-Project-/ai-soc-agent
pm2 start dist/server.js --name ai-soc-agent
pm2 logs ai-soc-agent --lines 50
pm2 save
pm2 startup
```

### Phase 3 Deliverables Checklist

```
□ Monorepo cloned on the runtime VM
□ npm install completed at repo root
□ npm run build passes for all workspaces
□ ai-soc-agent/.env created from .env.example and filled with Gemini + Wazuh values
□ Zeek and Suricata log paths are readable from the agent VM
□ npm run smoke --workspace=ai-soc-agent discovers MCP tools
□ curl /health on the agent returns status ok and tool count
□ curl /tools lists Zeek, Suricata, Wazuh, and MITRE tools
□ PM2 manages ai-soc-agent only
□ .env files are NOT committed to GitHub
```

---

## 6. Phase 4 — AI Agent Development (Weeks 7-8)

### Objectives
- Use the current built-in Gemini system prompt in `ai-soc-agent/src/prompts/systemPrompt.ts`
- Build and deploy the existing TypeScript agent server
- Test investigation requests through `POST /investigate`
- Verify structured JSON output matches the current Zod schemas

---

### 6.1 System Prompt

The current code already stores the production prompt in `ai-soc-agent/src/prompts/systemPrompt.ts`. Keep this file as the source of truth.

Do not paste a separate prompt into a new `system-prompt.txt` file unless you intentionally refactor the code. The Gemini reasoner imports the prompt from TypeScript and combines it with tool definitions discovered from MCP.

Current decision policy:

- Always start with Wazuh context when Wazuh tools are available
- Always map suspected behavior to MITRE ATT&CK
- Query Zeek and Suricata only when Wazuh/MITRE evidence is inconclusive
- `confidence >= 80` means `auto-block`
- `40-79` confidence means `analyst-review`
- `confidence < 40` means `monitor`
- The agent only recommends action; n8n performs pfSense/Telegram/Wazuh response

---

### 6.2 Agent Code

Do not create a separate `index.js` agent from this guide. The current repo already contains the TypeScript implementation:

```
ai-soc-agent/
├── src/server.ts                         # Express API: /health, /tools, /investigate
├── src/config.ts                         # Gemini, MCP stdio, Wazuh, and sensor env config
├── src/mcp/McpHub.ts                     # Spawns all MCP servers over stdio
├── src/llm/GeminiSocReasoner.ts          # Gemini tool-use reasoning
├── src/prompts/systemPrompt.ts           # System prompt source of truth
├── src/services/InvestigationService.ts  # Investigation response wrapper
└── .env.example
```

Use the repo scripts:

```bash
cd Final-Year-Gradution-Project-
npm run build
npm run smoke --workspace=ai-soc-agent
cd ai-soc-agent
npm start
```

The agent accepts this request shape:

```json
{
  "alert_id": "test-001",
  "src_ip": "203.0.113.55",
  "alert_type": "ssh-bruteforce",
  "rule_id": "100001",
  "severity": 10,
  "timestamp": "2026-06-07T10:00:00Z",
  "raw_alert": {}
}
```

The response wraps the validated SOC decision:

```json
{
  "investigation_id": "uuid",
  "received_at": "ISO timestamp",
  "completed_at": "ISO timestamp",
  "duration_ms": 8421,
  "decision": {
    "threat_confirmed": true,
    "confidence": 85,
    "action": "auto-block",
    "mitre_technique": "T1110.001",
    "mitre_tactic": "credential-access",
    "src_ip": "203.0.113.55",
    "threat_type": "brute-force",
    "evidence": ["specific tool-backed evidence"],
    "incident_report": "Plain English summary.",
    "recommended_block_duration": "24h"
  }
}
```

Current decision schema values:

- `action`: `auto-block`, `analyst-review`, or `monitor`
- `threat_type`: `brute-force`, `c2`, `lateral-movement`, `web-attack`, `ddos`, or `unknown`
- `recommended_block_duration`: `none`, `1h`, `24h`, `7d`, or `permanent`

---

### 6.3 Deployment on Azure VM (100.64.0.3)

```bash
# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs git

# Clone and build current repo
git clone https://github.com/MohammedALwadiya25/Final-Year-Gradution-Project-.git
cd Final-Year-Gradution-Project-
npm install
npm run build

# Configure
cp ai-soc-agent/.env.example ai-soc-agent/.env
nano ai-soc-agent/.env

# Start with PM2
cd ai-soc-agent
pm2 start dist/server.js --name ai-soc-agent
pm2 logs ai-soc-agent --lines 50

# Verify health and tool discovery
curl http://localhost:3000/health
curl http://localhost:3000/tools | python3 -m json.tool | head -40
```

---

### 6.4 Test Scenarios

The endpoint calls Gemini and the MCP tools, so these tests require `GEMINI_API_KEY`, Wazuh configuration, and readable sensor paths.

```bash
# TEST 1 — Fast path, auto-block candidate
curl -X POST http://localhost:3000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-001",
    "src_ip": "203.0.113.55",
    "alert_type": "ssh-bruteforce",
    "rule_id": "100001",
    "severity": 10,
    "timestamp": "2026-06-07T14:23:00Z"
  }'

# TEST 2 — Ambiguous suspicious outbound candidate
curl -X POST http://localhost:3000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-002",
    "src_ip": "198.51.100.22",
    "alert_type": "suspicious-outbound",
    "rule_id": "31101",
    "severity": 6,
    "timestamp": "2026-06-07T03:15:00Z"
  }'

# TEST 3 — Low severity monitor candidate
curl -X POST http://localhost:3000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-003",
    "src_ip": "192.168.80.50",
    "alert_type": "web-scan",
    "rule_id": "31151",
    "severity": 3,
    "timestamp": "2026-06-07T09:00:00Z"
  }'
```

Check the returned `decision.action`, `decision.confidence`, `decision.evidence`, and `duration_ms`. The code does not currently return top-level `investigation_path` or `deep_investigation_used`; do not make n8n depend on those fields unless they are added to the implementation.

### Phase 4 Deliverables Checklist

```
□ ai-soc-agent/src/prompts/systemPrompt.ts reviewed and matches the thesis policy
□ npm run build passes
□ npm run smoke --workspace=ai-soc-agent discovers MCP tools
□ Agent running on Azure VM port 3000 via PM2
□ /health endpoint returns current JSON shape
□ /tools endpoint lists all allowed readonly MCP tools
□ /investigate returns an InvestigationResponse with a nested decision object
□ n8n workflow reads fields from decision.action, decision.confidence, and decision.src_ip
```

---

## 7. Phase 5 — SOAR Pipeline & n8n (Weeks 9–10)

### Objectives
- Deploy n8n on Azure VM
- Build the complete SOAR workflow
- Integrate pfSense API for automated blocking
- Set up Telegram bot for analyst notifications
- Add AbuseIPDB and VirusTotal enrichment
- Test full end-to-end pipeline

---

### 7.1 n8n Deployment (Azure VM — 100.64.0.3)

```bash
# On Azure VM where AI Agent is also running

# Install n8n
sudo npm install -g n8n

# Create a systemd service for n8n
sudo nano /etc/systemd/system/n8n.service
```

```ini
[Unit]
Description=n8n workflow automation
After=network.target

[Service]
Type=simple
User=azureuser
Environment=N8N_PORT=5678
Environment=N8N_HOST=0.0.0.0
Environment=N8N_PROTOCOL=http
Environment=WEBHOOK_URL=http://100.64.0.3:5678
# n8n v1.0+ uses built-in user management, not basic auth
# On first launch, go to http://100.64.0.3:5678 and create owner account
ExecStart=/usr/bin/env n8n start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable n8n
sudo systemctl start n8n

# Access n8n at: http://100.64.0.3:5678
# Login with admin / YOUR_SECURE_PASSWORD
```

---

### 7.2 Telegram Bot Setup

```
1. Open Telegram → search @BotFather
2. Send: /newbot
3. Name: SOC Alert Bot
4. Username: your_soc_alert_bot
5. Copy the API token — save it as: TELEGRAM_BOT_TOKEN

6. Send /start to your new bot (required before it can message you)
7. Get your chat ID:
   Visit: https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   Find: result[0].message.chat.id
   Save as: TELEGRAM_CHAT_ID
```

---

### 7.3 n8n Workflow — Node by Node

Build this workflow in the n8n GUI. Create nodes in this order:

**Node 1 — Webhook Trigger**
```
Type: Webhook
HTTP Method: POST
Path: wazuh-alert
Authentication: None (Wazuh sends to this)
Response Mode: Last Node
```

**Node 2 — Extract Alert Fields**
```
Type: Set
Mode: Define below for each field

Fields to set:
  src_ip       = {{ $json.body.data.srcip }}
  alert_type   = {{ $json.body.rule.description }}
  alert_id     = {{ $json.body.id }}
  rule_id      = {{ $json.body.rule.id }}
  timestamp    = {{ $json.body.timestamp }}
  raw_alert    = {{ $json.body }}
```

**Node 3 — Call AI Agent**
```
Type: HTTP Request
Method: POST
URL: http://localhost:3000/investigate
Body Type: JSON
Body:
{
  "alert_id": "{{ $json.alert_id }}",
  "src_ip": "{{ $json.src_ip }}",
  "alert_type": "{{ $json.alert_type }}",
  "rule_id": "{{ $json.rule_id }}",
  "timestamp": "{{ $json.timestamp }}",
  "raw_alert": {{ JSON.stringify($json.raw_alert) }}
}
Timeout: 60000 (60 seconds)
```

**Node 4 — Parse Agent Decision**
```
Type: Set
Fields:
  investigation_id = {{ $json.investigation_id }}
  duration_ms      = {{ $json.duration_ms }}
  confidence       = {{ $json.decision.confidence }}
  action           = {{ $json.decision.action }}
  src_ip           = {{ $json.decision.src_ip }}
  mitre            = {{ $json.decision.mitre_technique }}
  report           = {{ $json.decision.incident_report }}
  threat_type      = {{ $json.decision.threat_type }}
  block_duration   = {{ $json.decision.recommended_block_duration }}
```

**Node 5 — Confidence Switch**
```
Type: Switch
Mode: Rules

Rule 1: {{ $json.confidence }} >= 80  → Output 0 (auto-block)
Rule 2: {{ $json.confidence }} >= 40  → Output 1 (analyst-review)
Rule 3: (fallback)                    → Output 2 (monitor)
```

**Node 6a — AbuseIPDB Enrichment** (connect from all Switch outputs)
```
Type: HTTP Request
Method: GET
URL: https://api.abuseipdb.com/api/v2/check
Query Params:
  ipAddress = {{ $('Parse Agent Decision').item.json.src_ip }}
  maxAgeInDays = 90
Headers:
  Key: {{ YOUR_ABUSEIPDB_KEY }}
  Accept: application/json
```

**Node 6b — VirusTotal Enrichment** (parallel with AbuseIPDB)
```
Type: HTTP Request
Method: GET
URL: https://www.virustotal.com/api/v3/ip_addresses/{{ $('Parse Agent Decision').item.json.src_ip }}
Headers:
  x-apikey: {{ YOUR_VT_KEY }}
```

**Node 7 — Merge Enrichment**
```
Type: Merge
Mode: Combine
```

**Node 8a — pfSense Block** (from Switch output 0 — auto-block only)
```
# First, check your pfSense API version:
curl -k -H "Authorization: Bearer YOUR_TOKEN" https://192.168.80.10/api/v2/firewall/alias

# For pfSense-pkg-API v2 (recommended):
POST https://192.168.80.10/api/v2/firewall/alias
Body:
{
  "name": "ai_soc_blocklist",
  "type": "host",
  "address": [
    { "value": "{{ $('Parse Agent Decision').item.json.src_ip }}" }
  ],
  "detail": [
    { "value": "AI SOC Agent block - {{ $now }}" }
  ]
}

# For pfSense-pkg-API v1 (legacy):
PUT https://192.168.80.10/api/v1/firewall/alias/entry
Body:
{
  "name": "ai_soc_blocklist",
  "address": "{{ $('Parse Agent Decision').item.json.src_ip }}"
}

# Note: You must first create the alias in pfSense:
# Firewall → Aliases → IP → Add
# Name: ai_soc_blocklist
# Type: Host(s)
# Then apply the alias to a block rule
```

**Node 8b — Apply pfSense Rules** (after adding to alias)
```
Type: HTTP Request
Method: POST
URL: https://192.168.80.10/api/v1/firewall/apply
Authentication: Bearer YOUR_PFSENSE_TOKEN
Body: {}
```

**Node 9 — Telegram Alert** (from all paths)
```
Type: Telegram
Credential: Your Bot Token
Operation: Send Message
Chat ID: YOUR_CHAT_ID
Text:
🚨 SECURITY ALERT — {{ $('Parse Agent Decision').item.json.threat_type.toUpperCase() }}

📍 Source IP:  {{ $('Parse Agent Decision').item.json.src_ip }}
🎯 Confidence: {{ $('Parse Agent Decision').item.json.confidence }}%
⚡ Action:     {{ $('Parse Agent Decision').item.json.action.toUpperCase() }}
🗺️ MITRE:      {{ $('Parse Agent Decision').item.json.mitre }}
⏱ Duration:   {{ $('Parse Agent Decision').item.json.duration_ms }}ms

📋 Report:
{{ $('Parse Agent Decision').item.json.report }}

🛡️ AbuseIPDB Score: {{ $('Merge Enrichment').item.json.data.abuseConfidenceScore }}%
🦠 VT Detections:   {{ $('Merge Enrichment').item.json.data.last_analysis_stats.malicious }}/90

{{ $('Parse Agent Decision').item.json.action == 'auto-block' ? '✅ Auto-blocked by AI Agent' : '⏳ Reply /approve or /deny' }}
```

**Node 10 — Analyst Approval** (from Switch output 1 — analyst-review only)
```
Type: Telegram Trigger
Watch: Messages
Bot: Your Bot Token

After receiving message:
  If text == '/approve':
    → Execute pfSense block (same as Node 8a)
    → Send Telegram: "✅ Block approved and applied for {{ src_ip }}"
  If text == '/deny':
    → Send Telegram: "❌ Block denied. Alert logged for review."
```

**Node 11 — Log to Wazuh** (final node — all paths)
```
# Wazuh API does NOT have /events endpoint. Use the Indexer API (Elasticsearch-compatible)
# or the Wazuh analysis engine via a local log file.

# Method A: Indexer API (Direct to storage)
POST https://100.64.0.2:9200/ai-soc-decisions/_doc
Authentication: Basic Auth (admin / YOUR_INDEXER_PASSWORD)
Body:
{
  "event": "AI_SOC_AGENT_DECISION",
  "src_ip": "{{ $('Parse Agent Decision').item.json.src_ip }}",
  "action": "{{ $('Parse Agent Decision').item.json.action }}",
  "confidence": {{ $('Parse Agent Decision').item.json.confidence }},
  "mitre_technique": "{{ $('Parse Agent Decision').item.json.mitre }}",
  "duration_ms": {{ $('Parse Agent Decision').item.json.duration_ms }},
  "investigation_id": "{{ $('Parse Agent Decision').item.json.investigation_id }}",
  "incident_report": "{{ $('Parse Agent Decision').item.json.report }}",
  "timestamp": "{{ $now }}"
}

# Method B: Custom Log File (Monitored by Wazuh Agent)
# 1. On n8n VM, append to /var/log/ai_agent_decisions.log
# 2. Add <localfile> to ossec.conf to monitor this file
```

---

### 7.4 pfSense Blocklist Setup

```bash
# Before n8n can block IPs, create the alias in pfSense:

# WebGUI → Firewall → Aliases → Add
Name:        ai_soc_blocklist
Type:        Host(s)
Description: Managed by AI SOC Agent via API
IP/FQDN:     (leave empty — n8n will populate)
Save

# Create a firewall rule that uses this alias:
# Firewall → Rules → WAN → Add
Action:      Block
Interface:   WAN
Source:      Single host or alias → ai_soc_blocklist
Destination: any
Description: AI SOC Agent auto-block rule
Save → Apply Changes
```

> ✅ **Tip:** Add a "never block" alias for your own management IPs (your Tailscale IP, your home public IP). Add a rule ABOVE the blocklist rule that allows these IPs. This prevents you from locking yourself out during testing.

> ⚠️ **Risk:** If the Telegram approval node times out without a response, the alert is dropped. Add a fallback branch: after 5 minutes with no response, auto-escalate to auto-block if confidence was 70–79%, or dismiss if 40–69%.

### Phase 5 Deliverables Checklist

```
□ n8n running on Azure VM port 5678, accessible via Tailscale
□ Telegram bot created, token and chat_id saved
□ pfSense ai_soc_blocklist alias created
□ pfSense block rule using the alias created and active
□ All 11 n8n workflow nodes configured and connected
□ End-to-end test: manual curl to /investigate → Telegram message received
□ Auto-block test: high confidence alert → pfSense alias updated
□ Analyst-review test: /approve via Telegram → pfSense block applied
□ AbuseIPDB and VirusTotal enrichment returning data
□ Wazuh logging final decisions from n8n
□ Full pipeline timing measured: alert → block < 30 seconds
```

---

## 8. Phase 6 — Attack Simulation & Validation (Weeks 11–12)

### Objectives
- Execute 5 controlled attacks from Kali Linux
- Record timestamps for all metrics
- Run Suricata-only baseline for comparison
- Write thesis chapters
- Record demo video

---

### 8.1 Pre-Attack Setup

```bash
# On Kali Linux (100.64.0.4)
# Install all attack tools
sudo apt update
sudo apt install -y hydra sqlmap hping3 nmap metasploit-framework python3

# Create metrics spreadsheet columns:
# attack_name | attack_start | wazuh_alert_time | agent_decision_time |
# action_taken | block_applied_time | confidence | path | correct?
```

**Safety rules before every attack:**
```
1. Whitelist your Kali Tailscale IP in pfSense so it cannot be permanently blocked:
   Firewall → Rules → Add at TOP → Allow → Source: 100.64.0.4 → ANY
   
2. Only attack DVWA (192.168.80.13) — never attack Azure infrastructure
3. Have a VM snapshot of every VM ready to restore
4. One attack at a time — wait for full pipeline cycle before running next
```

---

### 8.2 Attack Scenarios

**Attack 1 — SSH Brute Force**
```bash
# On Kali (100.64.0.4)
# Record attack_start timestamp first
echo "Attack 1 started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://192.168.80.13 -t 10 -V

# Expected detection chain:
# Suricata SID 9000001 → Wazuh rule 100001 → Agent fast-path
# Expected action: auto-block, confidence ≥80
# MITRE: T1110.001
```

**Attack 2 — SQL Injection**
```bash
echo "Attack 2 started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# DVWA must be set to Security: Low
# Access DVWA at http://192.168.80.13/dvwa
# Set security level to LOW in DVWA Security menu

sqlmap -u "http://192.168.80.13/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=YOUR_DVWA_SESSION;security=low" \
  --batch --level=3 --risk=2

# Expected: Suricata SID 9000002 → Wazuh rule 100002
# MITRE: T1190
```

**Attack 3 — DDoS SYN Flood**
```bash
echo "Attack 3 started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Run for 30 seconds then stop
timeout 30 sudo hping3 -S --flood -V -p 80 192.168.80.13

# Expected: Suricata SID 9000003 → Wazuh rule 100004
# MITRE: T1498
```

**Attack 4 — C2 Beaconing Simulation**
```bash
# C2 DNS Beaconing Simulation
# This matches Suricata rule 9000004 (long DNS queries)

# Install dnsutils
sudo apt install -y dnsutils

# Create DNS beaconing test script
cat > ~/c2_dns_beacon.sh << 'EOF'
#!/bin/bash
# C2 DNS Beaconing Simulation
# Sends encoded data in DNS queries to trigger Suricata SID 9000004

TARGET_DOMAIN="beacon.test"
VICTIM_IP="192.168.80.13"

echo "Starting C2 DNS beaconing simulation..."
echo "Target: $VICTIM_IP"
echo "Domain: $TARGET_DOMAIN"
echo ""

for i in {1..10}; do
  # Generate long subdomain (30+ chars) to trigger the rule
  SUBDOMAIN=$(head /dev/urandom | tr -dc 'a-z0-9' | head -c 35)

  echo "Beacon $i/10: ${SUBDOMAIN}.${TARGET_DOMAIN}"
  dig +short ${SUBDOMAIN}.${TARGET_DOMAIN} @192.168.80.10

  # Random interval 25-35 seconds to simulate beaconing
  SLEEP_TIME=$((25 + RANDOM % 10))
  echo "Sleeping ${SLEEP_TIME}s..."
  sleep $SLEEP_TIME
done

echo "C2 beaconing simulation complete."
EOF

chmod +x ~/c2_dns_beacon.sh

# Run the test
./c2_dns_beacon.sh

# Expected: Suricata SID 9000004 → Wazuh → Agent deep-path
# MITRE: T1071.004
```

**Attack 5 — Lateral Movement (Internal Scan)**
```bash
# Run this FROM the Windows VM (192.168.80.14)
# Open PowerShell on Windows VM

# Use nmap from Kali but with source spoofed to internal range
# OR: install nmap on Windows VM and run from there

# From Windows VM:
nmap -sS -T4 -p 22,80,443,3306,5432,8080 192.168.80.0/24

echo "Attack 5 started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Expected: Suricata SID 9000005 → Wazuh rule 100005
# Internal IP → confidence will be lower → likely analyst-review
# MITRE: T1046
```

---

### 8.3 Baseline Comparison (Suricata-Only)

```bash
# Run BEFORE connecting AI agent — or temporarily disable agent in n8n

# In n8n: deactivate the workflow
# In Wazuh: remove the webhook integration temporarily

# Run all 5 attacks
# Record: which ones Suricata detected, alert time, no response time

# Re-enable AI agent workflow
# Run all 5 attacks again
# Record: detection, agent path, response time, action
```

---

### 8.4 Metrics Collection Template

```
For every attack run, record in a spreadsheet:

| Field                  | Record How                                      |
|------------------------|-------------------------------------------------|
| attack_name            | e.g. "SSH Brute Force"                          |
| attack_start_time      | echo $(date -u) before running attack tool      |
| wazuh_alert_time       | Wazuh dashboard alert timestamp                 |
| agent_decision_time    | agent response `completed_at` timestamp         |
| action_taken           | agent response `decision.action` field          |
| confidence             | agent response `decision.confidence` field      |
| duration_ms            | agent response `duration_ms` field              |
| block_applied_time     | n8n execution log timestamp                     |
| correct_decision       | Yes/No (manual review)                          |
| MTTD (seconds)         | wazuh_alert_time - attack_start_time            |
| MTTR (seconds)         | block_applied_time - wazuh_alert_time           |
```

**Calculate final metrics:**
```
Detection Rate    = (attacks detected / 5) × 100
False Pos Rate    = (false auto-blocks / total auto-blocks) × 100
Avg MTTD          = sum of all MTTD / count
Avg MTTR          = sum of all MTTR / count
Agent Accuracy    = (correct decisions / total decisions) × 100
AI vs Baseline DR = AI Detection Rate - Suricata-only Detection Rate
```

---

### 8.5 Thesis Chapter Outline

```
Chapter 1 — Introduction
  1.1 Background and Motivation
  1.2 Problem Statement (3 gaps: intelligence, triage, response)
  1.3 Research Objectives
  1.4 Scope and Limitations
  1.5 Document Structure

Chapter 2 — Literature Review
  2.1 Evolution of NIDS (signature → anomaly → AI)
  2.2 SOAR Platforms and Automation
  2.3 LLM Agents in Cybersecurity (2024–2026)
  2.4 Model Context Protocol (MCP)
  2.5 MITRE ATT&CK Framework
  2.6 Gap Analysis — What This Project Contributes

Chapter 3 — System Architecture
  3.1 High-Level Architecture Overview
  3.2 Network Topology and VLAN Design
  3.3 Hybrid Infrastructure (VMware + Azure + Tailscale)
  3.4 Detection Layer (Zeek + Suricata)
  3.5 SIEM Layer (Wazuh)
  3.6 AI Agent Design — Wazuh-Primary Hybrid Model
  3.7 MCP Server Integration
  3.8 SOAR Layer (n8n)

Chapter 4 — Implementation
  4.1 Infrastructure Setup
  4.2 Detection Rule Engineering
  4.3 MCP Server Deployment and Configuration
  4.4 AI Agent Development (System Prompt + Code)
  4.5 SOAR Pipeline (n8n Workflow)
  4.6 Tailscale Zero Trust Network

Chapter 5 — Experimental Methodology
  5.1 Attack Scenarios Design
  5.2 Metrics Definition (MTTD, MTTR, DR, FPR)
  5.3 Baseline Comparison Method (Suricata-only)
  5.4 Test Environment Configuration

Chapter 6 — Results and Analysis
  6.1 Per-Attack Detection Results
  6.2 MTTD and MTTR Measurements
  6.3 Agent Accuracy and Path Distribution
  6.4 AI Agent vs Suricata-Only Comparison
  6.5 False Positive Analysis

Chapter 7 — Discussion
  7.1 Interpretation of Results
  7.2 Hybrid Architecture Effectiveness
  7.3 Limitations and Constraints
  7.4 Comparison with Published NIDS Research

Chapter 8 — Conclusion and Future Work
  8.1 Summary of Contributions
  8.2 Answers to Research Objectives
  8.3 Future Work (ML hybrid, production deployment, multi-agent)
```

### Phase 6 Deliverables Checklist

```
□ All 5 attacks executed with timestamps recorded
□ Baseline (Suricata-only) results recorded for all 5 attacks□ Metrics spreadsheet complete: MTTD, MTTR, DR, FPR, accuracy per attack
□ Comparison table: AI Agent vs Suricata-Only complete
□ Demo video recorded (minimum 10 minutes showing full pipeline)
□ All 8 thesis chapters written and reviewed
□ All figures and tables finalized
□ Final system snapshot saved and backed up to cloud storage
```

---

## 9. Global Risk Register

| Risk | Severity | Mitigation |
|---|---|---|
| Laptop powers off during live demo | 🔴 HIGH | Record a backup video in Week 11. Never rely solely on live demo for your defense. |
| Gemini API returns non-JSON response | 🟠 MEDIUM | Strip markdown fences before `JSON.parse`. Log raw response on every failure for debugging. |
| Gemini API down during thesis defense | 🔴 HIGH | Pre-recorded backup video. Test demo setup 48 hours before defense. Always have Plan B. |
| pfSense permanently blocks your Kali IP | 🔴 HIGH | Add a permanent ALLOW rule at the TOP of pfSense rules for Tailscale IPs before any attack testing. |
| Azure costs exceed student budget | 🟡 LOW | Set billing alert at $20. Stop Azure VMs when not actively testing. Use `az vm deallocate`. |
| MCP server reads stale Zeek logs | 🟠 MEDIUM | Always point `ZEEK_LOG_PATH` to `/opt/zeek/logs/current/` symlink, never to a dated directory. |
| Wazuh webhook not triggering n8n | 🟠 MEDIUM | Test webhook with `curl -X POST http://100.64.0.3:5678/webhook/wazuh-alert -d '{}'` directly. Check Wazuh integration config in `ossec.conf`. |
| VM disk space exhausted | 🟠 MEDIUM | Set Zeek log rotation to 7 days max. Set Suricata log rotation. Monitor weekly with `df -h`. |
| Tailscale disconnects mid-test | 🟡 LOW | Tailscale auto-reconnects within seconds. Keep `tailscale status` in a terminal during all tests. |
| npm install fails for MCP repo | 🟡 LOW | Try `npm install --legacy-peer-deps`. Check the repo's `package.json` for required Node.js version. |
| API key accidentally committed to GitHub | 🔴 HIGH | Add `.env` to `.gitignore` on Day 1 of every repo. Never hardcode credentials. Use environment variables only. |
| Suricata and Zeek packet drops on same interface | 🟠 MEDIUM | Monitor with `suricata --stats`. If drops exceed 5%, increase `af-packet` ring-size or move Zeek to a separate VM. |
| Supervisor unfamiliar with MCP and LLM agents | 🟠 MEDIUM | Prepare a one-page visual explainer: "What is an AI Agent" before your proposal meeting. |
| DVWA session expires during SQLi test | 🟡 LOW | Save the PHPSESSID cookie. Set PHP session timeout to 3600s in DVWA config. |
| n8n workflow crashes on malformed agent response | 🟠 MEDIUM | Add an error branch after the agent HTTP node. Any non-200 response triggers Telegram alert and logs to Wazuh. |

---

## 10. Accounts & Tools Checklist

### Create All Accounts — Week 1, Day 1

```
Service                Purpose                              Free Tier Limit
────────────────────────────────────────────────────────────────────────────
tailscale.com          Hybrid networking (Subnet Router)    100 devices
portal.azure.com       Cloud VMs (Wazuh + n8n + Kali)      $200 free credit
aistudio.google.com    Gemini API key — agent brain        Free-tier friendly
abuseipdb.com          Threat intel enrichment              1,000 checks/day
virustotal.com         Threat intel enrichment              500 requests/day
Telegram @BotFather    Create SOC Alert Bot                 Free
github.com             Fork all 4 MCP repos                 Free
```

> ⚠️ **Critical:** Add `.env` to `.gitignore` before your very first `git commit`. Never push API keys to GitHub — even private repos.

---

### Software to Install

```
On your laptop (host OS):
  □ VMware Workstation Pro / Player (latest)
  □ Tailscale for Windows or macOS — host OS only, NOT inside VMs

On all Ubuntu VMs (run after first boot):
  □ sudo apt update && sudo apt upgrade -y
  □ sudo apt install -y git curl wget net-tools htop unzip

On Kali Linux Azure VM:
  □ Tailscale (install via: curl -fsSL https://tailscale.com/install.sh | sh)
  □ All attack tools pre-installed in Kali — verify: which hydra sqlmap hping3 nmap msfconsole
```

---

### VM Snapshot Schedule

```
After every major milestone — take a labeled snapshot:

Phase 1:
  □ pfsense-vlans-span-done
  □ zeek-suricata-running
  □ tailscale-mesh-verified
  □ wazuh-agent-enrolled

Phase 2:
  □ suricata-custom-rules-tested
  □ wazuh-correlation-rules-done

Phase 3:
  □ all-mcp-servers-running
  □ mcp-integration-test-passed

Phase 4:
  □ agent-deployed-tested
  □ all-3-paths-verified

Phase 5:
  □ n8n-workflow-complete
  □ full-pipeline-end-to-end-tested

Phase 6:
  □ all-attacks-complete-FINAL
```

---

## 11. Metrics & Success Criteria

### Target Metrics Table

| Metric | Formula | Minimum Target | How to Measure |
|---|---|---|---|
| Detection Rate (DR) | Attacks detected / 5 × 100 | ≥ 80% | Count `decision.threat_confirmed: true` in agent/n8n responses |
| False Positive Rate (FPR) | Wrong auto-blocks / total auto-blocks × 100 | ≤ 15% | Manual review of each auto-block decision |
| Mean Time to Detect (MTTD) | avg(wazuh\_alert\_time − attack\_start\_time) | ≤ 60 seconds | Spreadsheet calculation |
| Mean Time to Respond (MTTR) | avg(block\_applied\_time − wazuh\_alert\_time) | ≤ 30 seconds | n8n execution log timestamps |
| Agent Accuracy | Correct decisions / total decisions × 100 | ≥ 85% | Compare action vs expected action per scenario |
| AI vs Baseline DR Delta | AI DR − Suricata-only DR | Positive value | Baseline run vs full pipeline run |
| Agent avg response | avg(`duration_ms`) across investigation responses | ≤ 15,000 ms | Use agent responses or n8n execution logs |
| Tool discovery health | `/health` and `/tools` return all expected MCP tools | 54 readonly tools | `curl /health` and `curl /tools` |

---

### Expected Results Table (Fill During Phase 6)

| Attack | Expected Action | Expected Path | Expected MTTD | Expected MTTR |
|---|---|---|---|---|
| SSH Brute Force | auto-block | fast-path | < 30s | < 15s |
| SQL Injection | auto-block | fast-path | < 45s | < 20s |
| DDoS SYN Flood | auto-block | fast-path | < 20s | < 10s |
| C2 Beaconing | analyst-review or auto-block | deep-path | < 60s | < 30s |
| Lateral Movement | analyst-review | fast-path or deep-path | < 60s | N/A (human decision) |

---

### Thesis Key Argument — Two Numbers

```
Number 1 — MTTR Improvement:
  Human analyst average MTTR: 20–40 minutes (published SOC benchmark)
  Your system MTTR:           < 30 seconds
  Improvement:                ~99.7% reduction in response time

Number 2 — FPR Reduction:
  Suricata-only FPR (baseline): measure during baseline test
  AI Agent FPR:                 measure during full pipeline test
  Improvement:                  delta = your academic contribution

These two numbers ARE your thesis conclusion.
Everything else supports them.
```

---

### Academic Contribution Summary

| Contribution | Why It Is Novel |
|---|---|
| MCP-as-SOC-intelligence layer | First undergraduate thesis using MCP servers as the reasoning backbone of a NIDS |
| Wazuh-Primary Hybrid model | Architecturally justified two-phase design — Wazuh first, raw sources only when ambiguous |
| Reasoning agent replaces static ML | No training data, no retraining cycles — immediately deployable in any environment |
| Cross-sensor validation | Requires Zeek + Suricata + Wazuh agreement — formally reduces FPR vs single-sensor |
| Supervised autonomy model | Confidence-threshold human-in-loop design — academically defensible safety argument |
| Zero Trust network layer | Tailscale WireGuard mesh — legitimate security architecture contribution beyond NIDS |
| Quantitative comparison | AI Agent vs Suricata-only baseline — measurable, defensible, publishable results |
| Open-source-only stack | Zero licensing cost — real-world applicability for SME e-commerce businesses |

---

### Project Success Criteria — Final Checklist

```
Minimum Viable Project (must achieve all):
  □ Full pipeline runs end-to-end without manual intervention
  □ At least 4 of 5 attacks detected (DR ≥ 80%)
  □ MTTR < 30 seconds for auto-block path
  □ Agent produces valid JSON for every alert
  □ MITRE ATT&CK tags on all confirmed threats
  □ Comparison table: AI Agent vs Suricata-only complete

Full Project (achieve as many as possible):
  □ FPR < 15%
  □ Agent accuracy ≥ 85%
  □ Deep-path correctly resolves at least 1 ambiguous case
  □ Telegram analyst-approval flow demonstrated live
  □ AbuseIPDB + VirusTotal enrichment in all alerts
  □ 10-minute demo video showing full attack-to-block cycle
  □ All 8 thesis chapters written
```

---

## Quick Reference — All IP Addresses and Ports

```
═══════════════════════════════════════════════════════════════
LOCAL VMWARE NETWORK (192.168.80.0/24)
═══════════════════════════════════════════════════════════════
192.168.80.10   pfSense Firewall
                  WebGUI:      https://192.168.80.10
                  API:         https://192.168.80.10/api/v1/...
                  API Token:   (generated in Phase 1)

192.168.80.11   Zeek + Suricata
                  Zeek logs:   /opt/zeek/logs/current/
                  EVE JSON:    /var/log/suricata/eve.json
                  Wazuh agent: enrolled to 100.64.0.2

192.168.80.12   Optional runtime/helper VM
                  Current code does not expose MCP HTTP ports.
                  If used, it should run the monorepo and ai-soc-agent,
                  or provide mounted sensor logs to the agent VM.

192.168.80.13   DVWA Web Server (DMZ)
                  HTTP:        http://192.168.80.13
                  DVWA:        http://192.168.80.13/dvwa
                  Default creds: admin / password

192.168.80.14   Windows Client (LAN)
                  RDP:         192.168.80.14:3389

═══════════════════════════════════════════════════════════════
AZURE CLOUD (Tailscale 100.64.0.0/10)
═══════════════════════════════════════════════════════════════
100.64.0.2      Wazuh Server
                  Dashboard:   https://100.64.0.2
                  API:         https://100.64.0.2:55000
                  Indexer:     https://100.64.0.2:9200
                  Agent enroll port: 1514, 1515
                  Default creds: admin / (from install output)

100.64.0.3      n8n + AI Agent
                  n8n GUI:     http://100.64.0.3:5678
                  AI Agent:    http://100.64.0.3:3000
                  Agent health: http://100.64.0.3:3000/health
                  Webhook:     http://100.64.0.3:5678/webhook/wazuh-alert

100.64.0.4      Kali Linux (Attacker)
                  SSH:         ssh kali@100.64.0.4
                  Tools:       hydra, sqlmap, hping3, nmap, msfconsole

═══════════════════════════════════════════════════════════════
YOUR LAPTOP (Tailscale Subnet Router)
═══════════════════════════════════════════════════════════════
100.64.0.1      Laptop Tailscale IP
                  Advertised subnet: 192.168.80.0/24
                  Command: tailscale up --advertise-routes=192.168.80.0/24 --accept-routes
```

---

## Quick Reference — Critical Commands

```bash
# ── CHECK ALL SERVICES RUNNING ────────────────────────────────

# On 192.168.80.11 (Zeek + Suricata VM)
sudo /opt/zeek/bin/zeekctl status          # Zeek status
sudo systemctl status suricata             # Suricata status
sudo systemctl status wazuh-agent          # Wazuh agent status
tail -f /opt/zeek/logs/current/conn.log    # Live Zeek traffic
tail -f /var/log/suricata/eve.json         # Live Suricata alerts

# MCP servers
# Current code uses stdio child processes spawned by ai-soc-agent.
# Check them through the agent instead of ports 3001-3004.

# On 100.64.0.3 (Azure — n8n + Agent VM)
pm2 status                                  # Agent status
pm2 logs ai-soc-agent --lines 20           # Agent logs
curl http://localhost:3000/health           # Agent health
curl http://localhost:3000/tools            # MCP tool discovery through agent
sudo systemctl status n8n                   # n8n status

# On 100.64.0.2 (Wazuh VM)
sudo systemctl status wazuh-manager        # Wazuh manager
sudo systemctl status wazuh-indexer        # Indexer
sudo systemctl status wazuh-dashboard      # Dashboard
sudo tail -f /var/ossec/logs/ossec.log     # Wazuh live log
sudo /var/ossec/bin/ossec-logtest          # Test rules interactively

# Tailscale (on any machine)
tailscale status                            # Show all connected peers
tailscale ping 192.168.80.11               # Test latency to Zeek VM
```

---

## Daily Checklist — Use During Testing Phases

```
Before every test session:
  □ Tailscale status shows all peers connected
  □ curl /tools on agent lists Zeek, Suricata, Wazuh, and MITRE tools
  □ pm2 status on Agent VM shows ai-soc-agent online
  □ curl /health on agent returns {"status":"ok"}
  □ Wazuh dashboard accessible
  □ n8n workflow is active (toggle in n8n GUI)
  □ Telegram bot responding (send /start)
  □ pfSense accessible and api_soc_blocklist alias exists
  □ Zeek generating logs (check conn.log timestamp < 1 min ago)
  □ Suricata running (check eve.json timestamp < 1 min ago)

After every test session:
  □ Copy agent response or n8n execution output to metrics spreadsheet
  □ Note attack_start, wazuh_alert, agent_decision, block_applied timestamps
  □ Record confidence, action, and duration_ms
  □ Verify pfSense blocklist (remove test IPs if needed for next test)
  □ Take VM snapshot if major changes were made
```

---

*Document Version 1.0 — June 2026*  
*Generated from full discovery + design session*  
*Project: AI-Powered SOC Agent NIDS for E-Commerce Infrastructure*  
*Stack: pfSense · Zeek · Suricata · Wazuh · n8n · Google Gemini · MCP Servers*  
*Network: VMware Workstation + Azure + Tailscale Zero Trust Mesh*
