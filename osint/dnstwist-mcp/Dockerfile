# DNStwist MCP Server
# Wrapper for BurtTheCoder/mcp-dnstwist
# Based on: https://github.com/BurtTheCoder/mcp-dnstwist

FROM node:20-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="DNStwist MCP Server - Typosquatting and phishing domain detection"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
    tini \
    git \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Install dnstwist
RUN pip3 install --break-system-packages dnstwist

WORKDIR /app

# Clone mcp-dnstwist
RUN git clone --depth 1 https://github.com/BurtTheCoder/mcp-dnstwist.git /tmp/mcp-dnstwist && \
    cp -r /tmp/mcp-dnstwist/* /app/ && \
    rm -rf /tmp/mcp-dnstwist

# Install dependencies and build
RUN npm ci && npm run build

ENV NODE_ENV=production

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
