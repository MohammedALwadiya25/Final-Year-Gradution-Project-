#!/usr/bin/env bash
# setup.sh — One-shot build of all MCP servers and the AI agent
# Usage: bash scripts/setup.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PACKAGES=("zeek-mcp" "suricata-mcp" "wazuh-mcp" "mitre-mcp" "ai-soc-agent")

check_node() {
  local required=20
  local current
  current=$(node --version | sed 's/v//' | cut -d. -f1)
  if [[ "$current" -lt "$required" ]]; then
    echo -e "${RED}✗ Node.js $required+ required, found v$current${NC}"
    exit 1
  fi
  echo -e "${GREEN}✓ Node.js v$current${NC}"
}

build_package() {
  local pkg="$1"
  echo -e "\n${CYAN}→ Building $pkg...${NC}"
  cd "$pkg"
  npm install --silent
  npm run build
  echo -e "${GREEN}✓ $pkg built${NC}"
  cd ..
}

# ── Main ─────────────────────────────────────────────────────────

echo -e "${CYAN}━━━ AI SOC Agent NIDS — Setup ━━━${NC}"
echo ""

check_node

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

for pkg in "${PACKAGES[@]}"; do
  build_package "$pkg"
done

# Copy .env.example if no .env exists
if [[ ! -f "ai-soc-agent/.env" ]]; then
  cp ai-soc-agent/.env.example ai-soc-agent/.env
  echo -e "\n${YELLOW}⚠  Created ai-soc-agent/.env from .env.example${NC}"
  echo -e "${YELLOW}   Edit it and set GEMINI_API_KEY + Wazuh credentials before starting.${NC}"
fi

echo ""
echo -e "${GREEN}━━━ Setup complete ━━━${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit ai-soc-agent/.env with your API keys"
echo "  2. Start the agent:  cd ai-soc-agent && npm start"
echo "  3. Health check:     curl http://localhost:3000/health"
echo ""
