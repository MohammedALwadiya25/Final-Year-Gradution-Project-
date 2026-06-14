#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════
// alert-bridge.js — Suricata → n8n Alert Forwarder
// ═══════════════════════════════════════════════════════════════
// Replaces Wazuh webhook by reading Suricata EVE JSON directly
// and forwarding alerts to n8n via HTTP POST.
//
// Deployment: Run on detection VM (192.168.80.11) alongside Suricata
// Process management: pm2 start alert-bridge.js --name alert-bridge
// ═══════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const EVE_PATH = process.env.SURICATA_EVE || '/var/log/suricata/eve.json';
const N8N_WEBHOOK = process.env.N8N_WEBHOOK || 'http://100.64.0.3:5678/webhook/soc-alert';
const SEVERITY_THRESHOLD = parseInt(process.env.SEVERITY_THRESHOLD || '5');

// Track file position for tail-like behavior
let filePosition = 0;

/**
 * Map Suricata alert signature to normalized threat type
 */
function mapEventType(event) {
  const sig = event.alert?.signature?.toLowerCase() || '';
  if (sig.includes('brute') || sig.includes('bruteforce')) return 'ssh-bruteforce';
  if (sig.includes('sql') || sig.includes('sqli')) return 'sql-injection';
  if (sig.includes('ddos') || sig.includes('syn flood')) return 'ddos';
  if (sig.includes('beacon') || sig.includes('c2')) return 'c2-beaconing';
  if (sig.includes('lateral') || sig.includes('port scan')) return 'lateral-movement';
  return 'unknown';
}

/**
 * Forward a single alert to the n8n webhook
 */
async function forwardAlert(event) {
  try {
    const alertPayload = {
      alert_id: `suricata-${event.timestamp}-${event.flow_id}`,
      src_ip: event.src_ip,
      dest_ip: event.dest_ip,
      alert_type: mapEventType(event),
      rule_id: String(event.alert?.signature_id),
      severity: event.alert?.severity || 5,
      signature: event.alert?.signature,
      category: event.alert?.category,
      timestamp: event.timestamp,
      raw_alert: event
    };

    const response = await fetch(N8N_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alertPayload)
    });

    if (response.ok) {
      console.log(`[${new Date().toISOString()}] Forwarded alert ${event.alert?.signature_id} from ${event.src_ip} → n8n (${response.status})`);
    } else {
      console.error(`[${new Date().toISOString()}] n8n returned error: ${response.status} ${response.statusText}`);
    }
  } catch (err) {
    console.error(`[${new Date().toISOString()}] Failed to forward alert: ${err.message}`);
  }
}

/**
 * Process a single line from the EVE JSON file
 */
function processLine(line) {
  try {
    const event = JSON.parse(line);
    // Only process alert events above threshold
    if (event.event_type === 'alert' && (event.alert?.severity || 0) >= SEVERITY_THRESHOLD) {
      forwardAlert(event);
    }
  } catch (err) {
    // Skip malformed lines silently
  }
}

/**
 * Tail the eve.json file with rotation support
 */
async function tailEve() {
  if (!fs.existsSync(EVE_PATH)) {
    console.error(`[${new Date().toISOString()}] EVE file not found: ${EVE_PATH} — retrying in 5s`);
    setTimeout(tailEve, 5000);
    return;
  }

  try {
    const stats = fs.statSync(EVE_PATH);
    const currentSize = stats.size;

    if (currentSize < filePosition) {
      // File was rotated
      console.log(`[${new Date().toISOString()}] EVE file rotated, resetting position`);
      filePosition = 0;
    }

    if (currentSize > filePosition) {
      const stream = fs.createReadStream(EVE_PATH, { start: filePosition });
      const rl = readline.createInterface({ input: stream });

      for await (const line of rl) {
        if (line.trim()) processLine(line);
      }

      filePosition = currentSize;
    }
  } catch (err) {
    console.error(`[${new Date().toISOString()}] Error reading EVE file: ${err.message}`);
  }

  setTimeout(tailEve, 1000); // Poll every second
}

// ═══════════════════════════════════════════════════════════════
// Startup
// ═══════════════════════════════════════════════════════════════
console.log('═══════════════════════════════════════════════════════════');
console.log('  Alert Bridge — Suricata → n8n Forwarder');
console.log('  (Replaces Wazuh webhook — Direct-Sensor Architecture)');
console.log('═══════════════════════════════════════════════════════════');
console.log(`Watching:    ${EVE_PATH}`);
console.log(`Forwarding:  ${N8N_WEBHOOK}`);
console.log(`Threshold:   severity >= ${SEVERITY_THRESHOLD}`);
console.log('───────────────────────────────────────────────────────────');
console.log('');

tailEve();
