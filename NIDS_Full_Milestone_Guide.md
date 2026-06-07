# 🛡️ AI-Powered SOC Agent NIDS — Full Milestone & Configuration Guide

> **Project:** Design and Implementation of an AI-Powered SOC Agent Using MCP Servers for Intelligent Intrusion Detection and Automated Response in E-Commerce Environments  
> **Stack:** pfSense · Zeek · Suricata · Wazuh · n8n · Claude API · MCP Servers  
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
| 40–79% | Deep Path | `analyst-review` or `auto-block` | ~8 seconds |
| < 40% | Fast Path | `monitor` | ~3 seconds |

### MCP Server Roles

| MCP Server | Port | Called When | Key Tools |
|---|---|---|---|
| `wazuh-mcp` | 3003 | Every alert | `get_alerts`, `search_alerts`, `get_fim_files` |
| `mitre-mcp` | 3004 | Every alert | `map_technique`, `threat_group_profiling` |
| `zeek-mcp` | 3001 | Confidence 40–79% only | `zeek_ssh_bruteforce`, `zeek_detect_beaconing`, `zeek_suspicious_http`, `zeek_detect_anomalies` |
| `suricata-mcp` | 3002 | Confidence 40–79% only | `suricata_query_alerts`, `suricata_beaconing_detection`, `suricata_lateral_movement_detection` |

---

## 2. Infrastructure Map

### VM Inventory

| VM | Location | OS | CPU | RAM | Disk | IP Address | Role |
|---|---|---|---|---|---|---|---|
| pfSense | VMware Local | pfSense 2.7 | 2 | 2 GB | 20 GB | `192.168.80.10` | Firewall + Gateway + VLAN + SPAN |
| Zeek + Suricata | VMware Local | Ubuntu 22.04 | 4 | 4 GB | 50 GB | `192.168.80.11` | Detection Engine |
| MCP Servers | VMware Local | Ubuntu 22.04 | 2 | 4 GB | 30 GB | `192.168.80.12` | All 4 MCP servers |
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
                  192.168.80.12  (MCP Servers)

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
MCP Servers (on 192.168.80.12):
  zeek-mcp      → :3001
  suricata-mcp  → :3002
  wazuh-mcp     → :3003
  mitre-mcp     → :3004

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

Then: Firewall → Traffic Shaper → Limiters
  → Not needed. Use pfSense bridge mirror instead:

Interfaces → Bridges → Add
  → Member interfaces: LAN, DMZ, WAN
  → Enable Span port: SPAN (em2)
  → Save

Zeek/Suricata VM listens on the interface connected to em2.
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
@load frameworks/files/hash-all-files
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

# From MCP VM — reach Wazuh API
curl http://100.64.0.2:55000
# Should return Wazuh JSON response

# From n8n VM — reach MCP servers
curl http://192.168.80.12:3001/health
```

> ✅ **Tip:** If pings work but curl times out — check Azure NSG (Network Security Group). Allow inbound TCP from `100.64.0.0/10` on ports `55000, 9200, 5678, 3000, 3001-3004`.

> ⚠️ **Risk:** Your laptop must be powered on for Azure to reach VMware VMs. Document this as a "lab constraint" in your thesis. In production, a dedicated server (Proxmox/ESXi) would eliminate this.

---

### 3.6 Wazuh Server Deployment (Azure VM)

```bash
# On Azure VM — Ubuntu 22.04 (100.64.0.2)
# Minimum: 4 CPU / 8 GB RAM / 100 GB disk

# Download Wazuh installer
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

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
  https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
sudo WAZUH_MANAGER='100.64.0.2' dpkg -i ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

**Configure Filebeat to ship Suricata eve.json to Wazuh:**
```bash
# On 192.168.80.11 (Zeek VM)
sudo nano /var/ossec/etc/ossec.conf
```

```xml
<!-- Add inside <ossec_config> -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>

<localfile>
  <log_format>zeek</log_format>
  <location>/opt/zeek/logs/current/conn.log</location>
</localfile>

<localfile>
  <log_format>zeek</log_format>
  <location>/opt/zeek/logs/current/http.log</location>
</localfile>

<localfile>
  <log_format>zeek</log_format>
  <location>/opt/zeek/logs/current/dns.log</location>
</localfile>
```

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
  http.uri;
  pcre:"/(\%27|\'|(\%3D)|(=))[^\n]*((\%27|\')|(\-\-)|(\%3B)|(;))/i";
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
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="custom_nids,">

  <!-- RULE 1: SSH Brute Force -->
  <!-- Fires when 5+ SSH failures from same IP in 60 seconds -->
  <!-- MITRE T1110.001: Brute Force: Password Guessing -->
  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_source_ip />
    <description>SSH Brute Force: 5+ failed logins from $(srcip) in 60s</description>
    <options>no_full_log</options>
    <group>authentication_failures,pci_dss_11.4,mitre_t1110.001,</group>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

  <!-- RULE 2: Web Application Attack (SQLi/XSS) -->
  <!-- Fires on Suricata web attack SIDs -->
  <rule id="100002" level="12">
    <if_sid>86600</if_sid>
    <field name="alert.category">Web Application Attack</field>
    <description>Web Application Attack detected: $(alert.signature) from $(srcip)</description>
    <group>web_attack,pci_dss_6.6,mitre_t1190,</group>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- RULE 3: C2 Beaconing -->
  <!-- Fires on Suricata C2/trojan-activity category -->
  <rule id="100003" level="13">
    <if_sid>86600</if_sid>
    <field name="alert.category">Trojan Activity</field>
    <description>C2 Beaconing detected from $(srcip): $(alert.signature)</description>
    <group>malware,c2_beacon,pci_dss_11.4,mitre_t1071.004,</group>
    <mitre>
      <id>T1071.004</id>
    </mitre>
  </rule>

  <!-- RULE 4: DDoS Detection -->
  <!-- Fires on Suricata denial-of-service category -->
  <rule id="100004" level="10">
    <if_sid>86600</if_sid>
    <field name="alert.category">Denial of Service Attack</field>
    <description>DDoS attack detected from $(srcip): $(alert.signature)</description>
    <group>ddos,availability,mitre_t1498,</group>
    <mitre>
      <id>T1498</id>
    </mitre>
  </rule>

  <!-- RULE 5: Lateral Movement / Internal Scan -->
  <!-- Fires on Suricata network-scan category from internal IP -->
  <rule id="100005" level="11">
    <if_sid>86600</if_sid>
    <field name="alert.category">Network Scan</field>
    <description>Internal lateral movement scan from $(srcip): $(alert.signature)</description>
    <group>lateral_movement,pci_dss_11.2,mitre_t1046,</group>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <!-- RULE 6: High Severity Composite — fires Wazuh webhook -->
  <!-- Aggregates any rule 100001-100005 for webhook trigger -->
  <rule id="100010" level="15" frequency="1" timeframe="10">
    <if_matched_rule_id>100001,100002,100003,100004,100005</if_matched_rule_id>
    <description>HIGH SEVERITY NIDS EVENT: $(rule.description) — Triggering SOAR</description>
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
```bash
sudo nano /var/ossec/etc/ossec.conf
```

```xml
<!-- Add inside <ossec_config> -->
<integration>
  <name>custom-webhook</name>
  <hook_url>http://100.64.0.3:5678/webhook/wazuh-alert</hook_url>
  <level>12</level>
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

## 5. Phase 3 — MCP Server Setup (Weeks 5–6)

### Objectives
- Fork all 4 MCP repos to your GitHub on Day 1
- Clone, build, and configure each MCP server in order
- Test each server independently before integration
- Run all 4 servers with PM2

---

### 5.1 Fork Repos — Do This First

```
1. Go to https://github.com/solomonneas
2. Fork these 4 repos to your account:
   → zeek-mcp
   → suricata-mcp
   → wazuh-mcp
   → mitre-mcp

Work from YOUR fork, not the original.
This protects you if the original repo changes.
```

---

### 5.2 MCP VM Preparation (192.168.80.12)

```bash
# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs git
node --version   # must be v20.x.x

# Install PM2
sudo npm install -g pm2

# Create workspace
mkdir -p ~/mcp-servers && cd ~/mcp-servers
```

---

### 5.3 MCP Server Installation Order

**Install in this exact order. Test each before moving to the next.**

#### Step 1 — zeek-mcp (install first — no external dependencies)

```bash
cd ~/mcp-servers
git clone https://github.com/YOUR_GITHUB/zeek-mcp
cd zeek-mcp
npm install
```

```bash
# Create .env file
cat > .env << 'ENVEOF'
ZEEK_LOG_PATH=/opt/zeek/logs/current
ZEEK_MCP_PORT=3001
ZEEK_MCP_HOST=0.0.0.0
ENVEOF
```

> ⚠️ **Important:** The zeek-mcp server needs to read Zeek logs. But Zeek runs on `192.168.80.11` and MCP servers run on `192.168.80.12`. You have two options:
>
> **Option A (Recommended — simpler):** Run zeek-mcp on the Zeek VM itself (`192.168.80.11`) on port 3001. Adjust all IP references accordingly.
>
> **Option B:** Mount Zeek logs via NFS from `.11` to `.12`:
> ```bash
> # On 192.168.80.11 (Zeek VM) — share logs
> sudo apt install nfs-kernel-server
> echo "/opt/zeek/logs 192.168.80.12(ro,sync,no_subtree_check)" | sudo tee -a /etc/exports
> sudo exportfs -ra
>
> # On 192.168.80.12 (MCP VM) — mount logs
> sudo apt install nfs-common
> sudo mkdir -p /mnt/zeek-logs
> sudo mount 192.168.80.11:/opt/zeek/logs /mnt/zeek-logs
> # Then set: ZEEK_LOG_PATH=/mnt/zeek-logs/current
> ```

```bash
npm run build
npm start &   # Test in foreground first

# Test zeek-mcp
curl http://localhost:3001/health
# Expected: {"status":"ok"} or tool list JSON

# Stop and move to next
Ctrl+C
```

#### Step 2 — suricata-mcp

```bash
cd ~/mcp-servers
git clone https://github.com/YOUR_GITHUB/suricata-mcp
cd suricata-mcp
npm install
```

```bash
cat > .env << 'ENVEOF'
EVE_JSON_PATH=/var/log/suricata/eve.json
SURICATA_RULES_PATH=/etc/suricata/rules
SURICATA_MCP_PORT=3002
SURICATA_MCP_HOST=0.0.0.0
ENVEOF
```

> ⚠️ **Same issue as zeek-mcp:** Suricata runs on `192.168.80.11`. Either run suricata-mcp on `.11` as well, or NFS-mount the eve.json directory to `.12`.

```bash
npm run build
npm start &

curl http://localhost:3002/health
Ctrl+C
```

#### Step 3 — wazuh-mcp

```bash
cd ~/mcp-servers
git clone https://github.com/YOUR_GITHUB/wazuh-mcp
cd wazuh-mcp
npm install
```

```bash
cat > .env << 'ENVEOF'
WAZUH_URL=https://100.64.0.2:55000
WAZUH_USER=wazuh-admin
WAZUH_PASS=YOUR_WAZUH_ADMIN_PASSWORD
WAZUH_VERIFY_SSL=false
WAZUH_MCP_PORT=3003
WAZUH_MCP_HOST=0.0.0.0
ENVEOF
```

```bash
npm run build
npm start &

curl http://localhost:3003/health
# Test actual Wazuh connection:
curl -X POST http://localhost:3003/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"get_alerts","params":{"limit":5}}'
Ctrl+C
```

#### Step 4 — mitre-mcp

```bash
cd ~/mcp-servers
git clone https://github.com/YOUR_GITHUB/mitre-mcp
cd mitre-mcp
npm install
```

```bash
cat > .env << 'ENVEOF'
MITRE_MCP_PORT=3004
MITRE_MCP_HOST=0.0.0.0
ENVEOF
```

```bash
npm run build
npm start &

curl http://localhost:3004/health
# Test ATT&CK lookup:
curl -X POST http://localhost:3004/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"map_technique","params":{"behavior":"ssh_bruteforce"}}'
Ctrl+C
```

---

### 5.4 PM2 Production Configuration

```bash
# Create PM2 ecosystem file
cd ~/mcp-servers
cat > ecosystem.config.js << 'PMEOF'
module.exports = {
  apps: [
    {
      name: 'zeek-mcp',
      cwd: './zeek-mcp',
      script: 'npm',
      args: 'start',
      env_file: './zeek-mcp/.env',
      watch: false,
      restart_delay: 3000,
      max_restarts: 10,
    },
    {
      name: 'suricata-mcp',
      cwd: './suricata-mcp',
      script: 'npm',
      args: 'start',
      env_file: './suricata-mcp/.env',
      watch: false,
      restart_delay: 3000,
      max_restarts: 10,
    },
    {
      name: 'wazuh-mcp',
      cwd: './wazuh-mcp',
      script: 'npm',
      args: 'start',
      env_file: './wazuh-mcp/.env',
      watch: false,
      restart_delay: 3000,
      max_restarts: 10,
    },
    {
      name: 'mitre-mcp',
      cwd: './mitre-mcp',
      script: 'npm',
      args: 'start',
      env_file: './mitre-mcp/.env',
      watch: false,
      restart_delay: 3000,
      max_restarts: 10,
    },
  ],
};
PMEOF

# Start all servers
pm2 start ecosystem.config.js

# Verify all running
pm2 status
# Expected: 4 servers all showing "online"

# Check logs
pm2 logs --lines 20

# Save and enable autostart
pm2 save
pm2 startup
# Run the command PM2 prints
```

---

### 5.5 Integration Test — All 4 Servers

```bash
# Run this from the n8n Azure VM (100.64.0.3)
# to verify reachability over Tailscale

echo "Testing zeek-mcp..."
curl -s http://192.168.80.12:3001/health && echo " ✅ OK" || echo " ❌ FAIL"

echo "Testing suricata-mcp..."
curl -s http://192.168.80.12:3002/health && echo " ✅ OK" || echo " ❌ FAIL"

echo "Testing wazuh-mcp..."
curl -s http://192.168.80.12:3003/health && echo " ✅ OK" || echo " ❌ FAIL"

echo "Testing mitre-mcp..."
curl -s http://192.168.80.12:3004/health && echo " ✅ OK" || echo " ❌ FAIL"

# All 4 must return ✅ before proceeding to Phase 4
```

> ✅ **Tip:** If a server fails to start, check `pm2 logs zeek-mcp --lines 50`. The most common error is wrong file path in `.env`. Verify the path exists with `ls -la $ZEEK_LOG_PATH`.

> ⚠️ **Risk:** `npm install` may fail for a dependency. Fix with `npm install --legacy-peer-deps`. If still failing, check the `package.json` for the exact Node.js version required.

### Phase 3 Deliverables Checklist

```
□ All 4 repos forked to your GitHub account
□ zeek-mcp: running on port 3001, health check passes
□ suricata-mcp: running on port 3002, health check passes
□ wazuh-mcp: running on port 3003, health check passes, Wazuh connection verified
□ mitre-mcp: running on port 3004, health check passes, ATT&CK lookup works
□ PM2 managing all 4 servers with auto-restart
□ Integration test: all 4 servers reachable from Azure VM over Tailscale
□ PM2 save + startup configured for reboot persistence
□ .env files backed up securely (NOT committed to GitHub)
```

---

## 6. Phase 4 — AI Agent Development (Weeks 7–8)

### Objectives
- Write and validate the system prompt in Claude.ai
- Build and deploy the agent Node.js server
- Test all 3 investigation paths (fast/deep/monitor)
- Verify structured JSON output is consistent

---

### 6.1 System Prompt (system-prompt.txt)

> **Do this before writing any code.** Open Claude.ai, paste this as a system prompt, then test with the scenarios in section 6.3.

```
You are an expert SOC analyst for an e-commerce Network Intrusion Detection System.
You protect an e-commerce business from: brute-force attacks, C2/malware beaconing,
lateral movement, web application attacks (SQLi/XSS), and volumetric DDoS.

════════════════════════════════════════════════════════
INVESTIGATION ARCHITECTURE
════════════════════════════════════════════════════════

Wazuh is your PRIMARY source. It already aggregates and correlates data from
BOTH Zeek (behavioral logs) and Suricata (signature alerts).
A single Wazuh query gives you the merged picture of what both sensors saw.
Do NOT query Zeek or Suricata directly unless Wazuh data is inconclusive.

════════════════════════════════════════════════════════
INVESTIGATION PROCESS — FOLLOW THIS EXACTLY
════════════════════════════════════════════════════════

STEP 1 — ALWAYS (Primary Source):
Call wazuh-mcp → get_alerts(src_ip, time_window="10m")
Also call wazuh-mcp → search_alerts(query=src_ip, limit=20)
This returns the correlated picture: alert count, rules fired,
severity levels, affected hosts.

STEP 2 — ALWAYS (ATT&CK Mapping):
Call mitre-mcp → map_technique(behavior=alert_type)

STEP 3 — Calculate Preliminary Confidence from Wazuh data:

Factors that INCREASE confidence:
  + Multiple Wazuh rules firing for same src_ip  → +20
  + Alert count > 10 in 10 minutes              → +15
  + Multiple destination hosts targeted          → +20
  + Wazuh severity level 10–13                  → +25
  + Known malicious pattern in rule description → +15

Factors that DECREASE confidence:
  - Only 1 rule fired, low severity (< 6)       → -20
  - Alert count < 3                             → -15
  - Source IP is internal RFC1918 address       → -10
  - Alerts only at unusual hours, no other sign → -10

STEP 4 — CONDITIONAL Deep Investigation (ONLY if 40% ≤ confidence ≤ 79%):
Wazuh data is inconclusive. Now query raw sources.

For BRUTE-FORCE suspicion:
  Call zeek-mcp → zeek_ssh_bruteforce(src_ip, threshold=5)

For C2/BEACONING suspicion:
  Call zeek-mcp → zeek_detect_beaconing(src_ip)
  Call suricata-mcp → suricata_beaconing_detection(src_ip)

For WEB ATTACK suspicion:
  Call zeek-mcp → zeek_suspicious_http(src_ip)

For LATERAL MOVEMENT suspicion:
  Call suricata-mcp → suricata_lateral_movement_detection()

For UNKNOWN suspicion:
  Call zeek-mcp → zeek_detect_anomalies(src_ip)
  Call suricata-mcp → suricata_query_alerts(src_ip)

After deep-dive:
  If tools CONFIRM Wazuh data  → increase confidence by 15–25
  If tools show NOTHING        → decrease confidence by 20

STEP 5 — ALWAYS (Final Decision):
Output ONLY valid JSON. No preamble. No markdown. No explanation.

════════════════════════════════════════════════════════
DECISION RULES — NEVER DEVIATE
════════════════════════════════════════════════════════

confidence >= 80  →  action: "auto-block"
confidence 40–79  →  action: "analyst-review"
confidence < 40   →  action: "monitor"

If Wazuh returns ZERO alerts for src_ip:
  Set confidence to 20, action to "monitor", skip deep-dive.

════════════════════════════════════════════════════════
OUTPUT FORMAT — STRICT JSON ONLY
════════════════════════════════════════════════════════

{
  "threat_confirmed": true | false,
  "confidence": <integer 0-100>,
  "action": "auto-block" | "analyst-review" | "monitor",
  "deep_investigation_used": true | false,
  "investigation_path": "fast-path" | "deep-path",
  "mitre_technique": "TXXXX.XXX",
  "mitre_tactic": "<tactic name>",
  "threat_type": "brute-force" | "c2-beacon" | "web-attack" | "lateral-movement" | "ddos" | "unknown",
  "src_ip": "<ip address>",
  "affected_hosts": ["<host1>"],
  "alert_count": <integer>,
  "wazuh_severity": <integer>,
  "evidence": [
    "<evidence point 1 from Wazuh>",
    "<evidence point 2 from Wazuh>",
    "<evidence point 3 from deep-dive if used>"
  ],
  "recommended_block_duration": "1h" | "24h" | "7d" | "permanent",
  "incident_report": "<2-3 sentence plain English summary>",
  "processing_ms": <will be added by agent server>
}
```

---

### 6.2 Agent Code

**File structure:**
```
~/soc-agent/
├── index.js
├── system-prompt.txt   ← paste the prompt from 6.1 exactly
├── .env
├── package.json
└── logs/
    └── decisions.log
```

**package.json:**
```json
{
  "name": "soc-agent",
  "version": "2.0.0",
  "description": "AI SOC Agent — Wazuh-Primary Hybrid Architecture",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "dotenv": "^16.3.1",
    "winston": "^3.11.0",
    "node-fetch": "^2.7.0"
  }
}
```

**.env:**
```bash
# Anthropic API
ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE

# MCP Server Addresses
ZEEK_MCP_URL=http://192.168.80.12:3001
SURICATA_MCP_URL=http://192.168.80.12:3002
WAZUH_MCP_URL=http://192.168.80.12:3003
MITRE_MCP_URL=http://192.168.80.12:3004

# Agent Config
AGENT_PORT=3000
LOG_LEVEL=info

# Confidence Thresholds
AUTO_BLOCK_THRESHOLD=80
DEEP_DIVE_MIN=40
DEEP_DIVE_MAX=79
```

**index.js:**
```javascript
require('dotenv').config();
const express = require('express');
const fetch   = require('node-fetch');
const fs      = require('fs');
const path    = require('path');
const winston = require('winston');

// ── Logger ────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: './logs/decisions.log' })
  ]
});

// ── System Prompt ─────────────────────────────────────────────
const SYSTEM_PROMPT = fs.readFileSync(
  path.join(__dirname, 'system-prompt.txt'), 'utf8'
);

// ── MCP Server Sets ───────────────────────────────────────────
const MCP_PRIMARY = [
  { type: 'url', url: process.env.WAZUH_MCP_URL,  name: 'wazuh-mcp'  },
  { type: 'url', url: process.env.MITRE_MCP_URL,  name: 'mitre-mcp'  },
];

const MCP_DEEP = [
  ...MCP_PRIMARY,
  { type: 'url', url: process.env.ZEEK_MCP_URL,     name: 'zeek-mcp'     },
  { type: 'url', url: process.env.SURICATA_MCP_URL,  name: 'suricata-mcp' },
];

// ── Thresholds ────────────────────────────────────────────────
const AUTO_BLOCK = parseInt(process.env.AUTO_BLOCK_THRESHOLD) || 80;
const DEEP_MIN   = parseInt(process.env.DEEP_DIVE_MIN)        || 40;
const DEEP_MAX   = parseInt(process.env.DEEP_DIVE_MAX)        || 79;

// ── Claude API Call ───────────────────────────────────────────
async function callClaude(userMessage, useDeepPath = false) {
  const mcp_servers = useDeepPath ? MCP_DEEP : MCP_PRIMARY;

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'mcp-client-2025-04-04'
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userMessage }],
      mcp_servers
    })
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Claude API error ${response.status}: ${err}`);
  }

  return response.json();
}

// ── Parse Decision ────────────────────────────────────────────
function parseDecision(data) {
  const text = data.content
    .filter(block => block.type === 'text')
    .map(block => block.text)
    .join('');

  // Strip markdown fences if present
  const clean = text.replace(/```json|```/g, '').trim();

  try {
    return JSON.parse(clean);
  } catch (e) {
    logger.error('JSON parse failed', { raw: clean.slice(0, 300) });
    throw new Error('Agent returned invalid JSON: ' + clean.slice(0, 200));
  }
}

// ── Main Investigation Logic ──────────────────────────────────
async function investigate(alertData) {
  const { alert_id, src_ip, alert_type, wazuh_rule_id, timestamp } = alertData;
  const startTime = Date.now();

  logger.info('Investigation started', { alert_id, src_ip, alert_type });

  // Phase 1: Fast path — always runs first
  const fastPrompt = `
    Investigate this security alert:
    - Source IP:     ${src_ip}
    - Alert Type:    ${alert_type}
    - Wazuh Rule ID: ${wazuh_rule_id}
    - Alert ID:      ${alert_id}
    - Timestamp:     ${timestamp}

    Follow your investigation process.
    Use wazuh-mcp and mitre-mcp first.
    If confidence lands between ${DEEP_MIN}% and ${DEEP_MAX}%,
    set deep_investigation_used: true and also call zeek-mcp
    and suricata-mcp tools for behavioral analysis.
    Output only the final JSON decision.
  `;

  let data     = await callClaude(fastPrompt, false);
  let decision = parseDecision(data);

  // Phase 2: Deep path if confidence is ambiguous
  if (decision.confidence >= DEEP_MIN && decision.confidence <= DEEP_MAX) {
    logger.info('Ambiguous — escalating to deep path', {
      src_ip,
      preliminary_confidence: decision.confidence
    });

    const deepPrompt = `
      PRELIMINARY RESULT (wazuh-mcp + mitre-mcp):
      ${JSON.stringify(decision, null, 2)}

      Confidence is ${decision.confidence}% — inconclusive.
      Now use zeek-mcp and suricata-mcp for behavioral deep-dive.
      Focus on threat type: ${decision.threat_type}
      Source IP: ${src_ip}

      After deep investigation, output the FINAL JSON decision.
      Update confidence and evidence based on what deep-dive found.
    `;

    data     = await callClaude(deepPrompt, true);
    decision = parseDecision(data);
    decision.investigation_path = 'deep-path';
  } else {
    decision.investigation_path = 'fast-path';
  }

  // Add timing metadata
  decision.alert_id        = alert_id;
  decision.processing_ms   = Date.now() - startTime;
  decision.investigated_at = new Date().toISOString();

  logger.info('Investigation complete', {
    alert_id,
    src_ip,
    action:     decision.action,
    confidence: decision.confidence,
    path:       decision.investigation_path,
    ms:         decision.processing_ms
  });

  return decision;
}

// ── Express Server ────────────────────────────────────────────
const app = express();
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '2.0-hybrid',
    thresholds: { auto_block: AUTO_BLOCK, deep_min: DEEP_MIN, deep_max: DEEP_MAX },
    timestamp: new Date().toISOString()
  });
});

// Main investigation endpoint — called by n8n
app.post('/investigate', async (req, res) => {
  const { alert_id, src_ip, alert_type, wazuh_rule_id, timestamp } = req.body;

  if (!src_ip || !alert_type) {
    return res.status(400).json({
      error: 'Missing required fields: src_ip, alert_type'
    });
  }

  try {
    const decision = await investigate({
      alert_id:      alert_id || `auto-${Date.now()}`,
      src_ip,
      alert_type,
      wazuh_rule_id: wazuh_rule_id || 'unknown',
      timestamp:     timestamp || new Date().toISOString()
    });
    res.json(decision);

  } catch (err) {
    logger.error('Investigation failed', { error: err.message, src_ip });
    // Safe fallback — never fail silently, always escalate to analyst
    res.status(500).json({
      error:      'Investigation failed',
      message:    err.message,
      action:     'analyst-review',
      confidence: 0,
      src_ip,
      incident_report: 'Agent error — manual investigation required.'
    });
  }
});

// Create logs directory
if (!fs.existsSync('./logs')) fs.mkdirSync('./logs');

const PORT = process.env.AGENT_PORT || 3000;
app.listen(PORT, () => {
  logger.info(`AI SOC Agent v2.0 running on port ${PORT}`);
  logger.info('Architecture: Wazuh-Primary Hybrid');
  logger.info(`Thresholds: auto-block≥${AUTO_BLOCK}% | deep-dive ${DEEP_MIN}-${DEEP_MAX}%`);
});
```

---

### 6.3 Deployment on Azure VM (100.64.0.3)

```bash
# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version   # v20.x.x

# Install PM2
sudo npm install -g pm2

# Create agent directory and files
mkdir -p ~/soc-agent/logs
cd ~/soc-agent

# Create all 4 files:
# - index.js         (copy from section 6.2)
# - system-prompt.txt (copy from section 6.1)
# - package.json     (copy from section 6.2)
# - .env             (copy from section 6.2 — fill in your API key)

npm install

# Start with PM2
pm2 start index.js --name soc-agent
pm2 save
pm2 startup   # run the command it prints

# Verify health
curl http://localhost:3000/health
```

---

### 6.4 Test Scenarios

**Test all 3 paths before connecting n8n:**

```bash
# TEST 1 — Fast path, auto-block (confidence should be ≥80)
curl -X POST http://localhost:3000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-001",
    "src_ip": "203.0.113.55",
    "alert_type": "SSH Brute Force",
    "wazuh_rule_id": "100001",
    "timestamp": "2026-06-07T14:23:00Z"
  }'
# Expected: action: "auto-block", investigation_path: "fast-path"

# TEST 2 — Deep path (confidence should be 40-79, triggering deep-dive)
curl -X POST http://localhost:3000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-002",
    "src_ip": "198.51.100.22",
    "alert_type": "Suspicious outbound connection",
    "wazuh_rule_id": "31101",
    "timestamp": "2026-06-07T03:15:00Z"
  }'
# Expected: deep_investigation_used: true, investigation_path: "deep-path"

# TEST 3 — Monitor (confidence should be <40)
curl -X POST http://localhost:3000/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "TEST-003",
    "src_ip": "192.168.80.50",
    "alert_type": "Web scan detected",
    "wazuh_rule_id": "31151",
    "timestamp": "2026-06-07T09:00:00Z"
  }'
# Expected: action: "monitor", investigation_path: "fast-path"
```

> ✅ **Tip:** All 3 test scenarios must pass before connecting n8n. Especially verify the deep-path test returns `deep_investigation_used: true` — this confirms the two-phase logic is working.

> ⚠️ **Risk:** If JSON parsing fails, add `console.log(text)` before `JSON.parse(clean)` to see the raw Claude response. The most common issue is Claude adding a preamble sentence before the JSON.

### Phase 4 Deliverables Checklist

```
□ system-prompt.txt tested in Claude.ai with all 3 test scenarios
□ All 4 agent files created: index.js, system-prompt.txt, package.json, .env
□ npm install completes without errors
□ Agent running on Azure VM port 3000 via PM2
□ /health endpoint returns correct JSON
□ TEST-001 returns action: "auto-block" and investigation_path: "fast-path"
□ TEST-002 returns deep_investigation_used: true and investigation_path: "deep-path"
□ TEST-003 returns action: "monitor"
□ decisions.log file generating entries for each test
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
Environment=N8N_BASIC_AUTH_ACTIVE=true
Environment=N8N_BASIC_AUTH_USER=admin
Environment=N8N_BASIC_AUTH_PASSWORD=YOUR_SECURE_PASSWORD
ExecStart=/usr/bin/n8n start
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
  wazuh_rule_id = {{ $json.body.rule.id }}
  timestamp    = {{ $json.body.timestamp }}
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
  "wazuh_rule_id": "{{ $json.wazuh_rule_id }}",
  "timestamp": "{{ $json.timestamp }}"
}
Timeout: 60000 (60 seconds)
```

**Node 4 — Parse Agent Decision**
```
Type: Set
Fields:
  confidence   = {{ $json.confidence }}
  action       = {{ $json.action }}
  mitre        = {{ $json.mitre_technique }}
  report       = {{ $json.incident_report }}
  threat_type  = {{ $json.threat_type }}
  block_duration = {{ $json.recommended_block_duration }}
  inv_path     = {{ $json.investigation_path }}
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
Type: HTTP Request
Method: POST
URL: https://192.168.80.10/api/v1/firewall/alias/entry
Authentication: Generic Credential Type
  Header Auth: Authorization = Bearer YOUR_PFSENSE_TOKEN
SSL: Ignore SSL errors (self-signed cert)
Body:
{
  "name": "ai_soc_blocklist",
  "address": "{{ $('Parse Agent Decision').item.json.src_ip }}",
  "detail": "AI SOC Agent block - {{ $('Parse Agent Decision').item.json.mitre }} - {{ $now }}"
}
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
🚨 SECURITY ALERT — {{ $('Parse Agent Decision').item.json.threat_type | upper }}

📍 Source IP:  {{ $('Parse Agent Decision').item.json.src_ip }}
🎯 Confidence: {{ $('Parse Agent Decision').item.json.confidence }}%
⚡ Action:     {{ $('Parse Agent Decision').item.json.action | upper }}
🗺️ MITRE:      {{ $('Parse Agent Decision').item.json.mitre }}
🔍 Path:       {{ $('Parse Agent Decision').item.json.inv_path }}

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
Type: HTTP Request
Method: POST
URL: https://100.64.0.2:55000/events
Authentication: Bearer YOUR_WAZUH_TOKEN
SSL: Ignore SSL errors
Body:
{
  "event": "AI_SOC_AGENT_DECISION",
  "src_ip": "{{ $('Parse Agent Decision').item.json.src_ip }}",
  "action": "{{ $('Parse Agent Decision').item.json.action }}",
  "confidence": {{ $('Parse Agent Decision').item.json.confidence }},
  "mitre_technique": "{{ $('Parse Agent Decision').item.json.mitre }}",
  "investigation_path": "{{ $('Parse Agent Decision').item.json.inv_path }}",
  "incident_report": "{{ $('Parse Agent Decision').item.json.report }}",
  "timestamp": "{{ $now }}"
}
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
echo "Attack 4 started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Create a simple beaconing script
cat > ~/c2_beacon.py << 'PYEOF'
import requests
import time
import random

TARGET = "http://192.168.80.13"
INTERVAL = 30  # seconds between beacons

print(f"C2 beacon started — interval: {INTERVAL}s")
for i in range(10):
    try:
        # Beacon with encoded data in URI (simulates C2 check-in)
        jitter = random.randint(-3, 3)
        requests.get(f"{TARGET}/?beacon={i}&data={'A'*50}", timeout=5)
        print(f"Beacon {i+1}/10 sent")
    except:
        pass
    time.sleep(INTERVAL + jitter)
PYEOF

python3 ~/c2_beacon.py

# Expected: zeek_detect_beaconing fires → Wazuh → Agent deep-path
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
| agent_decision_time    | decisions.log → investigated_at field           |
| action_taken           | decisions.log → action field                    |
| confidence             | decisions.log → confidence field                |
| investigation_path     | decisions.log → investigation_path field        |
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
| Claude API returns non-JSON response | 🟠 MEDIUM | Strip markdown fences before `JSON.parse`. Log raw response on every failure for debugging. |
| Claude API down during thesis defense | 🔴 HIGH | Pre-recorded backup video. Test demo setup 48 hours before defense. Always have Plan B. |
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
console.anthropic.com  Claude API key — agent brain         Pay per token (~$0.003/1K)
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
| Detection Rate (DR) | Attacks detected / 5 × 100 | ≥ 80% | Count `threat_confirmed: true` in decisions.log |
| False Positive Rate (FPR) | Wrong auto-blocks / total auto-blocks × 100 | ≤ 15% | Manual review of each auto-block decision |
| Mean Time to Detect (MTTD) | avg(wazuh\_alert\_time − attack\_start\_time) | ≤ 60 seconds | Spreadsheet calculation |
| Mean Time to Respond (MTTR) | avg(block\_applied\_time − wazuh\_alert\_time) | ≤ 30 seconds | n8n execution log timestamps |
| Agent Accuracy | Correct decisions / total decisions × 100 | ≥ 85% | Compare action vs expected action per scenario |
| AI vs Baseline DR Delta | AI DR − Suricata-only DR | Positive value | Baseline run vs full pipeline run |
| Fast-path avg response | avg(processing\_ms) where path = fast-path | ≤ 5,000 ms | Filter decisions.log by investigation\_path |
| Deep-path avg response | avg(processing\_ms) where path = deep-path | ≤ 15,000 ms | Filter decisions.log by investigation\_path |

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

192.168.80.12   MCP Servers
                  zeek-mcp:     http://192.168.80.12:3001
                  suricata-mcp: http://192.168.80.12:3002
                  wazuh-mcp:    http://192.168.80.12:3003
                  mitre-mcp:    http://192.168.80.12:3004
                  PM2 logs:     pm2 logs --lines 50

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

# On 192.168.80.12 (MCP VM)
pm2 status                                  # All MCP servers
pm2 logs --lines 20                         # Recent logs
curl http://localhost:3001/health           # zeek-mcp health
curl http://localhost:3002/health           # suricata-mcp health
curl http://localhost:3003/health           # wazuh-mcp health
curl http://localhost:3004/health           # mitre-mcp health

# On 100.64.0.3 (Azure — n8n + Agent VM)
pm2 status                                  # Agent status
pm2 logs soc-agent --lines 20              # Agent logs
curl http://localhost:3000/health           # Agent health
sudo systemctl status n8n                   # n8n status
cat ~/soc-agent/logs/decisions.log | tail -20  # Decision history

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
  □ pm2 status on MCP VM shows 4 servers online
  □ pm2 status on Agent VM shows soc-agent online
  □ curl /health on agent returns {"status":"ok"}
  □ Wazuh dashboard accessible
  □ n8n workflow is active (toggle in n8n GUI)
  □ Telegram bot responding (send /start)
  □ pfSense accessible and api_soc_blocklist alias exists
  □ Zeek generating logs (check conn.log timestamp < 1 min ago)
  □ Suricata running (check eve.json timestamp < 1 min ago)

After every test session:
  □ Copy decisions.log entry to metrics spreadsheet
  □ Note attack_start, wazuh_alert, agent_decision, block_applied timestamps
  □ Record confidence, action, investigation_path
  □ Verify pfSense blocklist (remove test IPs if needed for next test)
  □ Take VM snapshot if major changes were made
```

---

*Document Version 1.0 — June 2026*  
*Generated from full discovery + design session*  
*Project: AI-Powered SOC Agent NIDS for E-Commerce Infrastructure*  
*Stack: pfSense · Zeek · Suricata · Wazuh · n8n · Claude API · MCP Servers*  
*Network: VMware Workstation + Azure + Tailscale Zero Trust Mesh*
