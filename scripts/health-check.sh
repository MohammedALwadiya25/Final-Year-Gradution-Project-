#!/usr/bin/env bash
# health-check.sh — Verify all MCP servers and the AI agent are reachable
# Usage: bash scripts/health-check.sh [MCP_HOST]
# MCP_HOST defaults to 192.168.80.12 (lab default)
set -euo pipefail

MCP_HOST="${1:-192.168.80.12}"
AGENT_HOST="${2:-localhost}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check() {
  local name="$1"
  local url="$2"
  if curl -sf --max-time 5 "$url" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ $name${NC}  ($url)"
  else
    echo -e "${RED}✗ $name${NC}  ($url)"
    FAILED=1
  fi
}

FAILED=0

echo "━━━ MCP Servers ($MCP_HOST) ━━━"
check "zeek-mcp      (port 3001)" "http://$MCP_HOST:3001/health"
check "suricata-mcp  (port 3002)" "http://$MCP_HOST:3002/health"
check "wazuh-mcp     (port 3003)" "http://$MCP_HOST:3003/health"
check "mitre-mcp     (port 3004)" "http://$MCP_HOST:3004/health"

echo ""
echo "━━━ AI Agent ($AGENT_HOST:3000) ━━━"
check "ai-soc-agent  (port 3000)" "http://$AGENT_HOST:3000/health"

echo ""
if [[ "$FAILED" -eq 0 ]]; then
  echo -e "${GREEN}All services healthy.${NC}"
else
  echo -e "${RED}One or more services are down. Check PM2 logs: pm2 logs --lines 50${NC}"
  exit 1
fi
