/**
 * PM2 Ecosystem Config — MCP Servers (192.168.80.12)
 *
 * Run from the repo root:
 *   pm2 start scripts/ecosystem.config.js
 *   pm2 save && pm2 startup
 *
 * Adjust *_LOG_PATH values to match your actual sensor paths.
 */
module.exports = {
  apps: [
    {
      name: 'zeek-mcp',
      cwd: './zeek-mcp',
      script: 'node',
      args: 'dist/index.js',
      env: {
        ZEEK_LOG_DIR: '/opt/zeek/logs/current',
        ZEEK_LOG_FORMAT: 'tsv',
        ZEEK_MAX_RESULTS: '1000',
      },
      watch: false,
      restart_delay: 3000,
      max_restarts: 10,
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    },
    {
      name: 'suricata-mcp',
      cwd: './suricata-mcp',
      script: 'node',
      args: 'dist/index.js',
      env: {
        SURICATA_EVE_LOG: '/var/log/suricata/eve.json',
        ZEEK_LOGS_DIR: '/opt/zeek/logs/current',
        SURICATA_MAX_RESULTS: '1000',
      },
      watch: false,
      restart_delay: 3000,
      max_restarts: 10,
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    },
    // Wazuh removed — using direct sensor architecture
    // alert-bridge.js runs on detection VM (192.168.80.11) instead
    {
      name: 'mitre-mcp',
      cwd: './mitre-mcp',
      script: 'node',
      args: 'dist/index.js',
      env: {
        MITRE_MATRICES: 'enterprise',
        MITRE_DATA_DIR: '/opt/mitre-mcp/data',
      },
      watch: false,
      restart_delay: 3000,
      max_restarts: 10,
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    },
  ],
};
