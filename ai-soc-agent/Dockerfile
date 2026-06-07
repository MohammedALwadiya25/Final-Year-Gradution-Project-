FROM node:20-alpine AS base
WORKDIR /app

# ── Build all MCP server packages first (agent spawns them via stdio) ────────
FROM base AS mcp-builder
COPY zeek-mcp/package*.json ./zeek-mcp/
COPY suricata-mcp/package*.json ./suricata-mcp/
COPY wazuh-mcp/package*.json ./wazuh-mcp/
COPY mitre-mcp/package*.json ./mitre-mcp/

COPY zeek-mcp/src ./zeek-mcp/src
COPY zeek-mcp/tsup.config.ts ./zeek-mcp/
COPY zeek-mcp/tsconfig.json ./zeek-mcp/
RUN cd zeek-mcp && npm ci && npx tsup

COPY suricata-mcp/src ./suricata-mcp/src
COPY suricata-mcp/tsup.config.ts ./suricata-mcp/
COPY suricata-mcp/tsconfig.json ./suricata-mcp/
RUN cd suricata-mcp && npm ci && npx tsup

COPY wazuh-mcp/src ./wazuh-mcp/src
COPY wazuh-mcp/tsup.config.ts ./wazuh-mcp/
COPY wazuh-mcp/tsconfig.json ./wazuh-mcp/
RUN cd wazuh-mcp && npm ci && npx tsup

COPY mitre-mcp/src ./mitre-mcp/src
COPY mitre-mcp/tsup.config.ts ./mitre-mcp/
COPY mitre-mcp/tsconfig.json ./mitre-mcp/
RUN cd mitre-mcp && npm ci && npx tsup

# ── Build the AI agent ────────────────────────────────────────────────────────
FROM base AS agent-builder
COPY ai-soc-agent/package*.json ./
RUN npm ci
COPY ai-soc-agent/src ./src
COPY ai-soc-agent/tsconfig.json ./
RUN npx tsc -p tsconfig.json

# ── Final runtime image ───────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
WORKDIR /app

# Copy agent runtime deps + build
COPY ai-soc-agent/package*.json ./
RUN npm ci --omit=dev
COPY --from=agent-builder /app/dist ./dist

# Copy MCP server builds alongside agent (agent spawns them via stdio)
COPY --from=mcp-builder /app/zeek-mcp/package*.json ./zeek-mcp/
COPY --from=mcp-builder /app/zeek-mcp/node_modules ./zeek-mcp/node_modules
COPY --from=mcp-builder /app/zeek-mcp/dist ./zeek-mcp/dist

COPY --from=mcp-builder /app/suricata-mcp/package*.json ./suricata-mcp/
COPY --from=mcp-builder /app/suricata-mcp/node_modules ./suricata-mcp/node_modules
COPY --from=mcp-builder /app/suricata-mcp/dist ./suricata-mcp/dist

COPY --from=mcp-builder /app/wazuh-mcp/package*.json ./wazuh-mcp/
COPY --from=mcp-builder /app/wazuh-mcp/node_modules ./wazuh-mcp/node_modules
COPY --from=mcp-builder /app/wazuh-mcp/dist ./wazuh-mcp/dist

COPY --from=mcp-builder /app/mitre-mcp/package*.json ./mitre-mcp/
COPY --from=mcp-builder /app/mitre-mcp/node_modules ./mitre-mcp/node_modules
COPY --from=mcp-builder /app/mitre-mcp/dist ./mitre-mcp/dist

ENV NODE_ENV=production \
    PORT=3000 \
    ZEEK_MCP_COMMAND=node \
    ZEEK_MCP_ARGS=./zeek-mcp/dist/index.js \
    SURICATA_MCP_COMMAND=node \
    SURICATA_MCP_ARGS=./suricata-mcp/dist/index.js \
    WAZUH_MCP_COMMAND=node \
    WAZUH_MCP_ARGS=./wazuh-mcp/dist/index.js \
    MITRE_MCP_COMMAND=node \
    MITRE_MCP_ARGS=./mitre-mcp/dist/index.js

EXPOSE 3000
USER node
CMD ["node", "dist/server.js"]
