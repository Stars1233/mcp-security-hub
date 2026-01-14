# VirusTotal MCP Server
# Wrapper for BurtTheCoder/mcp-virustotal
# Based on: https://github.com/BurtTheCoder/mcp-virustotal

FROM node:20-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="VirusTotal MCP Server - Malware and threat intelligence"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
    tini \
    git \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Clone mcp-virustotal
RUN git clone --depth 1 https://github.com/BurtTheCoder/mcp-virustotal.git /tmp/mcp-virustotal && \
    cp -r /tmp/mcp-virustotal/* /app/ && \
    rm -rf /tmp/mcp-virustotal

# Install dependencies and build
RUN npm ci && npm run build

ENV NODE_ENV=production

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
