# 🛡️ Zeek & Suricata — Complete Installation & Configuration Guide
> **Project:** AI-Powered SOC Agent NIDS for E-Commerce  
> **VM:** `192.168.80.11` — Ubuntu 22.04 LTS — 4 CPU / 4 GB RAM / 50 GB  
> **Purpose:** Detection Layer (Layer 2) feeding Wazuh → AI Agent pipeline  

---

## ⚠️ Errors Found and Fixed in the Original Guide

The following mistakes were found in `NIDS_Full_Milestone_Guide.md` and are corrected in this document:

| # | Location | Original Error | Fix Applied |
|---|---|---|---|
| 1 | Phase 3, Section 5.4 line 993 | Sentence cut off mid-word: `"...over NFS, SSHF"` then raw bash appears outside code block | Full NFS section rewritten cleanly with proper code blocks |
| 2 | Phase 3, Section 5.4 line 1036 | `"...zeek-logsS, or another read-only sync..."` — garbled text mixing bash and prose | Cleaned and separated properly |
| 3 | Phase 3, Section 5.4 | NFS section appears **twice** (lines 995–1036 and again 1040–1062) with conflicting export rules — one allows `/24`, the other only allows `100.64.0.3` | Merged into one correct version that covers **both** local and Tailscale access |
| 4 | Phase 1, Section 3.3 line 260 | `sudo apt install -y zeek` installs a **generic/versioned package** that caused your earlier broken-dependency issue | Changed to `sudo apt install -y zeek-lts` (LTS is stable and avoids version conflicts) |
| 5 | Phase 2, Section 4.1 | Suricata rule 9000003 (DDoS SYN Flood) uses `type both` threshold — this fires once then suppresses; use `type threshold` for continuous detection in a lab | Fixed threshold type |
| 6 | Phase 1, Section 3.4 | `suricata.yaml` shows interface `eth1` hardcoded with no reminder to verify | Added `ip a` verification step with clear note |
| 7 | Phase 2, Section 4.1 | `sudo suricata --list-rules` is not a valid Suricata command | Corrected to `sudo suricata-update list-sources` and grep method |

---

## 📋 Before You Start — Checklist

```
□ Ubuntu 22.04 server installed on 192.168.80.11
□ Static IP set to 192.168.80.11/24, gateway 192.168.80.10 (pfSense)
□ SSH access working
□ pfSense SPAN mirror configured and sending traffic to this VM's second NIC
□ You know your SPAN interface name (run: ip a)
```

**Find your interface names before touching anything:**
```bash
ip a
# You should see TWO interfaces (not counting loopback):
#   Interface 1: management (e.g. ens33, eth0) — has IP 192.168.80.11
#   Interface 2: SPAN/capture (e.g. ens37, eth1) — NO IP address (that is correct)
```

> 🔑 **Write down both interface names now.** Every `eth1` reference in this guide is your SPAN interface. Replace it with your actual name.

---

## Part 1 — System Preparation

```bash
# Update system completely before installing anything
sudo apt-get update && sudo apt-get upgrade -y

# Install required dependencies
sudo apt-get install -y \
  curl wget gnupg2 software-properties-common \
  apt-transport-https ca-certificates lsb-release \
  python3 python3-pip jq net-tools htop

# Confirm Ubuntu version (must be 22.04)
lsb_release -a
```

---

## Part 2 — Install Zeek

### 2.1 Add the Official Zeek Repository

```bash
# Add the Zeek OBS repository for Ubuntu 22.04
echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list

# Add the GPG signing key
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor \
  | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Update package lists
sudo apt-get update

# Confirm the repo is reachable (should show zeek packages)
apt-cache search zeek | grep "^zeek"
```

### 2.2 Install Zeek LTS

```bash
# Install zeek-lts — the Long Term Support version
# DO NOT use plain "zeek" — it installs a versioned meta-package
# that caused your earlier broken-dependency problem
sudo apt-get install -y zeek-lts

# Verify the binary exists
/opt/zeek/bin/zeek --version

# Add Zeek to PATH for this session and permanently
export PATH=$PATH:/opt/zeek/bin
echo 'export PATH=$PATH:/opt/zeek/bin' | sudo tee /etc/profile.d/zeek.sh
source /etc/profile.d/zeek.sh

# Confirm zeek is accessible
zeek --version
zeekctl --version
```

### 2.3 Configure node.cfg (Standalone Mode)

```bash
sudo nano /opt/zeek/etc/node.cfg
```

Replace ALL content with:

```ini
# /opt/zeek/etc/node.cfg
# Standalone mode — single sensor VM

[zeek]
type=standalone
host=localhost
interface=eth1
# ⚠️ Replace eth1 with YOUR actual SPAN interface name from: ip a
```

### 2.4 Configure networks.cfg

```bash
sudo nano /opt/zeek/etc/networks.cfg
```

Add these lines (replace any defaults):

```
# /opt/zeek/etc/networks.cfg
192.168.80.0/24    Local VMware lab network
10.0.0.0/8         Azure and internal private ranges
100.64.0.0/10      Tailscale overlay network
```

### 2.5 Configure local.zeek (Enable Detection Scripts)

```bash
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

Add these lines at the **end** of the file (keep any existing content):

```zeek
# ── Tuning and base policies ──────────────────────────────────────
@load policy/tuning/defaults

# ── SSH brute force detection (feeds your MCP zeek__zeek_ssh_bruteforce) ──
@load policy/protocols/ssh/detect-bruteforcing

# ── SQL injection detection (feeds zeek__zeek_suspicious_http) ───
@load policy/protocols/http/detect-sqli

# ── DNS anomaly detection (feeds zeek__zeek_detect_beaconing) ────
@load policy/protocols/dns/detect-external-names

# ── General anomaly framework ─────────────────────────────────────
@load policy/frameworks/notice/weird
@load policy/frameworks/files/hash-all-files
@load policy/misc/detect-traceroute
```

### 2.6 Deploy and Start Zeek

```bash
# Check configuration before deploying (catches errors)
sudo zeekctl check

# If check passes, deploy
sudo zeekctl deploy

# Verify status
sudo zeekctl status
# Expected output:
# Name       Type    Host       Status    Pid    Started
# zeek       standalone localhost running   XXXX   DD MMM HH:MM:SS
```

### 2.7 Verify Zeek is Generating Logs

```bash
# Wait 30 seconds after deploy, then check
sleep 30

# Check that log files exist and have recent timestamps
ls -la /opt/zeek/logs/current/

# Watch live connection log (you should see traffic if SPAN is working)
tail -f /opt/zeek/logs/current/conn.log

# Watch HTTP log
tail -f /opt/zeek/logs/current/http.log

# Watch DNS log
tail -f /opt/zeek/logs/current/dns.log
```

> ✅ **If logs are empty:** The SPAN interface name is wrong. Run `ip a`, find your second interface, update `/opt/zeek/etc/node.cfg`, then run `sudo zeekctl deploy` again.

> ✅ **If zeekctl status shows "crashed":** Run `sudo zeekctl diag` — it shows the exact error.

### 2.8 Configure Zeek Log Rotation

```bash
sudo nano /opt/zeek/etc/zeekctl.cfg
```

Find and set these values (add if missing):

```ini
# Keep logs for 7 days to prevent disk fill
LogExpireInterval = 7

# Log rotation interval (default is 1 hour — keep it)
LogRotationInterval = 3600
```

```bash
# Apply the config
sudo zeekctl deploy
```

### 2.9 Make Zeek Start on Boot

```bash
# Create a systemd service for Zeek
sudo tee /etc/systemd/system/zeek.service << 'EOF'
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
ExecStart=/opt/zeek/bin/zeekctl start
ExecStop=/opt/zeek/bin/zeekctl stop
ExecReload=/opt/zeek/bin/zeekctl reload
PIDFile=/opt/zeek/spool/zeek/zeek.pid
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable zeek
```

---

## Part 3 — Install Suricata

### 3.1 Add the Official OISF PPA

```bash
# Add the Open Information Security Foundation stable PPA
sudo add-apt-repository ppa:oisf/suricata-stable -y

# Update package lists
sudo apt-get update

# Confirm Suricata is available
apt-cache policy suricata | head -5
```

### 3.2 Install Suricata

```bash
sudo apt-get install -y suricata

# Verify installation
suricata --version

# Check service status (it may fail to start until configured — that is OK)
sudo systemctl status suricata
```

### 3.3 Configure suricata.yaml

```bash
# Always back up the original config first
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

sudo nano /etc/suricata/suricata.yaml
```

Find and update these sections. **Do not change anything else.**

**Section 1 — HOME_NET (find `vars:` near the top):**
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.80.0/24,10.0.0.0/8,100.64.0.0/10]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,443,8080,8443"
    SSH_PORTS: "22"
    SQL_PORTS: "3306,5432"
```

**Section 2 — af-packet (find `af-packet:`):**
```yaml
af-packet:
  - interface: eth1
    # ⚠️ Replace eth1 with YOUR actual SPAN interface name from: ip a
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
```

**Section 3 — EVE JSON output (find `outputs:`):**
```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - flow
        - stats:
            interval: 60
```

**Section 4 — Rule files (find `rule-files:`):**
```yaml
rule-files:
  - suricata.rules
  - local.rules
```

### 3.4 Test Configuration Syntax

```bash
# Always test before starting — catches yaml errors
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Expected last line: "Configuration provided was successfully loaded."
# If there is an error, it will show the line number — fix it before continuing.
```

### 3.5 Download and Update Rules

```bash
# Update Emerging Threats Open rules (free, no account needed)
sudo suricata-update

# Verify rules were downloaded
ls -la /var/lib/suricata/rules/
# You should see suricata.rules with a recent timestamp

# Count rules loaded
sudo suricata-update list-sources
```

### 3.6 Enable and Start Suricata

```bash
sudo systemctl enable suricata
sudo systemctl start suricata

# Check status
sudo systemctl status suricata

# If it fails, check the error log:
sudo tail -50 /var/log/suricata/suricata.log
```

### 3.7 Verify Suricata is Working

```bash
# Watch EVE JSON output (alerts and events will appear here)
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool 2>/dev/null | head -80

# Check Suricata stats (shows if it is seeing packets)
sudo tail -f /var/log/suricata/stats.log | head -30

# Generate a test alert using the EICAR test
curl -o /dev/null http://testmynids.org/uid/index.html 2>/dev/null || true
sleep 5
grep -i "testmynids\|GPL ATTACK_RESPONSE\|ET INFO" /var/log/suricata/eve.json | tail -5
```

> ✅ **If eve.json is empty after 60 seconds:** The SPAN interface name is wrong. Check with `ip a`, update `suricata.yaml`, run `sudo suricata -T -c /etc/suricata/suricata.yaml -v` again, then `sudo systemctl restart suricata`.

### 3.8 Schedule Weekly Rule Updates

```bash
# Add a weekly cron job to keep rules current
echo "0 3 * * 1 /usr/bin/suricata-update && systemctl reload suricata" \
  | sudo tee /etc/cron.d/suricata-update
```

---

## Part 4 — Custom Detection Rules (Phase 2)

These are the 5 rules your project requires, covering all 5 attack scenarios.

### 4.1 Create the Custom Rules File

```bash
sudo nano /etc/suricata/rules/local.rules
```

Paste the full content below:

```bash
# =============================================================
# LOCAL.RULES — Custom NIDS Rules for E-Commerce SOC Project
# VM: 192.168.80.11
# =============================================================

# ── RULE 1: SSH BRUTE FORCE ──────────────────────────────────
# Detects: 5+ SSH connection attempts from same source in 60s
# MITRE:   T1110.001 — Brute Force: Password Guessing
# Wazuh:   Triggers rule 100001
# Agent:   Fast-path → auto-block (confidence ≥ 80)
# Test:    hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.80.13 -t 10
alert tcp any any -> $HOME_NET 22 (
  msg:"CUSTOM SSH BRUTE FORCE ATTEMPT";
  flow:to_server,established;
  threshold: type threshold, track by_src, count 5, seconds 60;
  classtype:attempted-admin;
  sid:9000001;
  rev:1;
  metadata:mitre_technique T1110.001, affected_product OpenSSH;
)

# ── RULE 2: SQL INJECTION ────────────────────────────────────
# Detects: UNION SELECT patterns in HTTP URI
# MITRE:   T1190 — Exploit Public-Facing Application
# Wazuh:   Triggers rule 100002
# Agent:   Fast-path → auto-block (confidence ≥ 80)
# Test:    sqlmap -u "http://192.168.80.13/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
alert http any any -> $HTTP_SERVERS any (
  msg:"CUSTOM SQL INJECTION ATTEMPT";
  flow:established,to_server;
  http.uri;
  content:"union";
  fast_pattern;
  nocase;
  http.uri;
  pcre:"/union\s+select/i";
  classtype:web-application-attack;
  sid:9000002;
  rev:1;
  metadata:mitre_technique T1190;
)

# ── RULE 3: DDoS SYN FLOOD ───────────────────────────────────
# Detects: 100+ SYN packets from same source in 10 seconds
# MITRE:   T1498 — Network Denial of Service
# Wazuh:   Triggers rule 100004
# Agent:   Fast-path → auto-block (confidence ≥ 80)
# Test:    timeout 30 sudo hping3 -S --flood -V -p 80 192.168.80.13
# FIX:     Changed "type both" → "type threshold" for continuous detection
alert tcp any any -> $HOME_NET any (
  msg:"CUSTOM DDOS SYN FLOOD DETECTED";
  flags:S;
  threshold: type threshold, track by_src, count 100, seconds 10;
  classtype:denial-of-service;
  sid:9000003;
  rev:1;
  metadata:mitre_technique T1498;
)

# ── RULE 4: C2 DNS BEACONING ─────────────────────────────────
# Detects: Long DNS query subdomains (30+ chars) — DNS tunneling/C2
# MITRE:   T1071.004 — Application Layer Protocol: DNS
# Wazuh:   Triggers rule 100003
# Agent:   Deep-path → analyst-review (confidence 40–79)
# Test:    ./c2_dns_beacon.sh (see Phase 6 attack scripts)
alert dns any any -> any any (
  msg:"CUSTOM SUSPICIOUS LONG DNS QUERY C2 BEACONING";
  dns.query;
  pcre:"/[a-z0-9\-]{30,}\./i";
  threshold: type threshold, track by_src, count 5, seconds 120;
  classtype:trojan-activity;
  sid:9000004;
  rev:1;
  metadata:mitre_technique T1071.004;
)

# ── RULE 5: INTERNAL PORT SCAN (LATERAL MOVEMENT) ────────────
# Detects: Internal host scanning 20+ ports in 5 seconds
# MITRE:   T1046 — Network Service Discovery
# Wazuh:   Triggers rule 100005
# Agent:   Deep-path or fast-path → analyst-review
# Test:    nmap -sS -T4 -p 22,80,443,3306,5432,8080 192.168.80.0/24
#          Run from Windows VM (192.168.80.14) for internal detection
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

### 4.2 Validate and Reload Rules

```bash
# Test configuration with new rules (ALWAYS do this before restart)
sudo suricata -T -c /etc/suricata/suricata.yaml -v
# Expected: "Configuration provided was successfully loaded."

# Reload rules without a full restart (preferred — no packet loss)
sudo systemctl reload suricata

# Or send the reload signal directly
sudo kill -USR2 $(pidof suricata)

# Verify your custom rules are loaded
grep "CUSTOM" /var/lib/suricata/rules/suricata.rules || \
  grep "CUSTOM" /etc/suricata/rules/local.rules && echo "Local rules file OK"

# Check Suricata loaded them (look for sid:9000001 through 9000005)
sudo tail -20 /var/log/suricata/suricata.log | grep -i "rule\|error\|warning"
```

---

## Part 5 — Wazuh Agent Enrollment

The Wazuh agent must run on this VM so Suricata and Zeek alerts reach your SIEM.

### 5.1 Install Wazuh Agent

```bash
# On 192.168.80.11 — the Zeek + Suricata VM

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
  --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update

# Install agent — point it to your Wazuh server on Azure
sudo WAZUH_MANAGER='100.64.0.2' apt-get install -y wazuh-agent

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Verify agent is running
sudo systemctl status wazuh-agent
```

### 5.2 Configure Wazuh Agent to Monitor Suricata and Zeek Logs

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add inside the `<ossec_config>` block:

```xml
<!-- Suricata EVE JSON alerts → Wazuh -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>

<!-- Zeek connection log → Wazuh -->
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/zeek/logs/current/conn.log</location>
</localfile>

<!-- Zeek HTTP log → Wazuh -->
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/zeek/logs/current/http.log</location>
</localfile>

<!-- Zeek DNS log → Wazuh -->
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/zeek/logs/current/dns.log</location>
</localfile>

<!-- Zeek notice log (brute force notices appear here) → Wazuh -->
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/zeek/logs/current/notice.log</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent

# Verify agent is communicating with Wazuh server
sudo tail -20 /var/ossec/logs/ossec.log
# Look for: "Connected to the server"
```

---

## Part 6 — NFS Log Sharing (Corrected)

This section is needed because the AI agent runs on `100.64.0.3` (Azure) but Zeek/Suricata logs are on `192.168.80.11` (local). The MCP stdio child processes read local file paths, so you must mount the logs on the agent VM.

### 6.1 On the Zeek+Suricata VM (NFS Server — 192.168.80.11)

```bash
# Install NFS server
sudo apt-get install -y nfs-kernel-server

# Ensure log directories exist
sudo mkdir -p /opt/zeek/logs
sudo mkdir -p /var/log/suricata

# Configure exports — allow BOTH the local VMware subnet AND the Tailscale agent IP
sudo nano /etc/exports
```

Add these lines:

```
# Allow local VMware network and Tailscale agent VM
/opt/zeek/logs      192.168.80.0/24(ro,sync,no_subtree_check,no_root_squash)
/opt/zeek/logs      100.64.0.3(ro,sync,no_subtree_check,no_root_squash)
/var/log/suricata   192.168.80.0/24(ro,sync,no_subtree_check,no_root_squash)
/var/log/suricata   100.64.0.3(ro,sync,no_subtree_check,no_root_squash)
```

```bash
# Apply exports
sudo exportfs -a

# Restart NFS
sudo systemctl enable nfs-kernel-server
sudo systemctl restart nfs-kernel-server

# Open firewall if UFW is active
sudo ufw allow from 192.168.80.0/24 to any port nfs
sudo ufw allow from 192.168.80.0/24 to any port 2049
sudo ufw allow from 100.64.0.0/10 to any port nfs
sudo ufw allow from 100.64.0.0/10 to any port 2049

# Verify what is being exported
sudo exportfs -v
```

### 6.2 On the Agent VM (NFS Client — 100.64.0.3)

```bash
# Install NFS client
sudo apt-get install -y nfs-common

# Create mount points
sudo mkdir -p /mnt/zeek-logs
sudo mkdir -p /mnt/suricata-logs

# Test mount manually first (before adding to fstab)
sudo mount -t nfs 192.168.80.11:/opt/zeek/logs /mnt/zeek-logs
sudo mount -t nfs 192.168.80.11:/var/log/suricata /mnt/suricata-logs

# Verify you can see logs
ls -la /mnt/zeek-logs/current/
ls -la /mnt/suricata-logs/

# If manual mount works, make it persistent across reboots
echo '192.168.80.11:/opt/zeek/logs    /mnt/zeek-logs    nfs ro,defaults,_netdev 0 0' \
  | sudo tee -a /etc/fstab
echo '192.168.80.11:/var/log/suricata /mnt/suricata-logs nfs ro,defaults,_netdev 0 0' \
  | sudo tee -a /etc/fstab

# Mount all fstab entries to confirm no errors
sudo mount -a
```

### 6.3 Update .env on the Agent VM

After NFS is mounted, set these paths in `ai-soc-agent/.env`:

```env
ZEEK_LOG_DIR=/mnt/zeek-logs/current
ZEEK_LOG_PATH=/mnt/zeek-logs/current
ZEEK_LOGS_DIR=/mnt/zeek-logs/current
SURICATA_EVE_LOG=/mnt/suricata-logs/eve.json
EVE_JSON_PATH=/mnt/suricata-logs/eve.json
```

---

## Part 7 — Verification Checklist

Run these commands on `192.168.80.11` to confirm everything is ready before moving to Phase 3.

```bash
echo "=== ZEEK STATUS ==="
sudo zeekctl status

echo ""
echo "=== ZEEK LOGS (last 3 lines of conn.log) ==="
tail -3 /opt/zeek/logs/current/conn.log 2>/dev/null || echo "conn.log not yet created"

echo ""
echo "=== SURICATA STATUS ==="
sudo systemctl status suricata --no-pager | head -10

echo ""
echo "=== SURICATA EVE.JSON (last event) ==="
tail -1 /var/log/suricata/eve.json 2>/dev/null | python3 -m json.tool 2>/dev/null \
  || echo "eve.json not yet populated"

echo ""
echo "=== CUSTOM RULES CHECK ==="
grep "sid:9000" /etc/suricata/rules/local.rules | wc -l
echo "rules found (expected: 5)"

echo ""
echo "=== CONFIG SYNTAX CHECK ==="
sudo suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | tail -3

echo ""
echo "=== WAZUH AGENT STATUS ==="
sudo systemctl status wazuh-agent --no-pager | head -10

echo ""
echo "=== WAZUH CONNECTION ==="
sudo tail -5 /var/ossec/logs/ossec.log | grep -i "connect\|error"
```

**All green means Phase 1 and Phase 2 are complete.**

---

## Part 8 — Quick Troubleshooting Reference

| Symptom | Command to Diagnose | Fix |
|---|---|---|
| Zeek shows "crashed" | `sudo zeekctl diag` | Check interface name in node.cfg |
| Zeek logs empty | `tail -f /opt/zeek/logs/current/conn.log` | Wrong SPAN interface — fix node.cfg |
| Suricata fails to start | `sudo tail -30 /var/log/suricata/suricata.log` | Run config test: `sudo suricata -T -c /etc/suricata/suricata.yaml -v` |
| eve.json empty | `sudo cat /var/log/suricata/stats.log \| grep capture` | Wrong af-packet interface in suricata.yaml |
| Custom rules not triggering | `grep "9000001" /var/log/suricata/eve.json` | Reload rules: `sudo kill -USR2 $(pidof suricata)` |
| Wazuh agent disconnected | `sudo tail -20 /var/ossec/logs/ossec.log` | Check Tailscale is up: `tailscale status` |
| NFS mount hangs | `sudo mount -v -t nfs 192.168.80.11:/opt/zeek/logs /mnt/zeek-logs` | Check NFS server is running on .11; check UFW rules |
| Both Zeek+Suricata dropping packets | `grep "drop" /var/log/suricata/stats.log` | Increase af-packet ring-size in suricata.yaml |

---

## Quick Reference — Key Paths

```
Zeek:
  Binary:           /opt/zeek/bin/zeek
  Config files:     /opt/zeek/etc/
  node.cfg:         /opt/zeek/etc/node.cfg
  networks.cfg:     /opt/zeek/etc/networks.cfg
  local.zeek:       /opt/zeek/share/zeek/site/local.zeek
  Live logs:        /opt/zeek/logs/current/    ← always use the symlink
  Archived logs:    /opt/zeek/logs/YYYY-MM-DD/

Suricata:
  Binary:           /usr/bin/suricata
  Main config:      /etc/suricata/suricata.yaml
  Custom rules:     /etc/suricata/rules/local.rules
  Downloaded rules: /var/lib/suricata/rules/suricata.rules
  Alert log:        /var/log/suricata/eve.json   ← MCP reads this
  Service log:      /var/log/suricata/suricata.log

Wazuh Agent:
  Config:           /var/ossec/etc/ossec.conf
  Logs:             /var/ossec/logs/ossec.log

NFS (on Agent VM 100.64.0.3):
  Zeek logs:        /mnt/zeek-logs/current/
  Suricata EVE:     /mnt/suricata-logs/eve.json
```

---

## Critical Commands — Daily Use

```bash
# ── On 192.168.80.11 ──────────────────────────────────────────

# Start everything
sudo zeekctl start
sudo systemctl start suricata
sudo systemctl start wazuh-agent

# Stop everything
sudo zeekctl stop
sudo systemctl stop suricata

# Reload Suricata rules (no packet loss)
sudo kill -USR2 $(pidof suricata)

# Live alert monitoring
tail -f /var/log/suricata/eve.json | python3 -m json.tool

# Check for your custom rule alerts only
grep "CUSTOM" /var/log/suricata/eve.json | tail -20 | python3 -m json.tool

# Check Zeek notices (brute force, scans)
tail -f /opt/zeek/logs/current/notice.log

# Full status check
sudo zeekctl status && sudo systemctl status suricata --no-pager | head -5
```

---

*Document Version 1.1 — June 2026*  
*Corrected from NIDS_Full_Milestone_Guide.md — fixes applied: 7 errors*  
*Project: AI-Powered SOC Agent NIDS — Mohammed ALwadiya Final Year Project*
