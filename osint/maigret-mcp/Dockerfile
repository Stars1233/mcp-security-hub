# Maigret MCP Server
# Wrapper for BurtTheCoder/mcp-maigret
# Based on: https://github.com/BurtTheCoder/mcp-maigret

FROM node:20-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Maigret MCP Server - Username OSINT across platforms"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
    tini \
    git \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Install maigret
RUN pip3 install --break-system-packages maigret

WORKDIR /app

# Clone mcp-maigret
RUN git clone --depth 1 https://github.com/BurtTheCoder/mcp-maigret.git /tmp/mcp-maigret && \
    cp -r /tmp/mcp-maigret/* /app/ && \
    rm -rf /tmp/mcp-maigret

# Install dependencies and build
RUN npm ci && npm run build

# Create reports directory
RUN mkdir -p /app/reports

ENV MAIGRET_REPORTS_DIR=/app/reports
ENV NODE_ENV=production

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "build/index.js"]
