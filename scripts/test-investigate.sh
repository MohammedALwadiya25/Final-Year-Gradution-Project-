#!/usr/bin/env bash
# test-investigate.sh — Run the 3 canonical test scenarios against the agent
# Usage: bash scripts/test-investigate.sh [AGENT_HOST]
set -euo pipefail

AGENT="${1:-localhost:3000}"
BASE="http://$AGENT"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

run_test() {
  local name="$1"
  local payload="$2"
  local expected_action="$3"

  echo -e "\n${CYAN}━━━ $name ━━━${NC}"
  echo "Payload: $payload"
  echo ""

  local response
  response=$(curl -sf -X POST "$BASE/investigate" \
    -H "Content-Type: application/json" \
    -d "$payload")

  local action confidence path duration
  action=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['decision']['action'])")
  confidence=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['decision']['confidence'])")
  path=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('investigation_path', 'N/A'))")
  duration=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['duration_ms'])")

  echo "  Action:     $action"
  echo "  Confidence: $confidence%"
  echo "  Path:       $path"
  echo "  Duration:   ${duration}ms"

  if [[ "$action" == "$expected_action" ]]; then
    echo -e "  ${GREEN}✓ Expected action: $expected_action${NC}"
  else
    echo -e "  ${YELLOW}⚠ Expected '$expected_action', got '$action'${NC}"
  fi
}

echo -e "${CYAN}AI SOC Agent — Investigation Test Suite${NC}"
echo "Target: $BASE"

run_test "TEST-1: SSH Brute Force (expect auto-block)" \
  '{"alert_id":"test-001","src_ip":"203.0.113.55","alert_type":"ssh-bruteforce","rule_id":"100001","severity":10}' \
  "auto-block"

run_test "TEST-2: Suspicious Outbound (expect analyst-review or deep-path)" \
  '{"alert_id":"test-002","src_ip":"198.51.100.22","alert_type":"suspicious-outbound","rule_id":"31101","severity":6}' \
  "analyst-review"

run_test "TEST-3: Internal Web Scan (expect monitor)" \
  '{"alert_id":"test-003","src_ip":"192.168.80.50","alert_type":"web-scan","rule_id":"31151","severity":3}' \
  "monitor"

echo ""
echo -e "${GREEN}Test suite complete.${NC}"
