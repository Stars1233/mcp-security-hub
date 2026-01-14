# Ghidra MCP Server
# Wrapper for LaurieWired/GhidraMCP
# Based on: https://github.com/LaurieWired/GhidraMCP
#
# NOTE: This container provides the MCP bridge.
# You must have Ghidra installed with the GhidraMCP plugin running.

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Ghidra MCP Server - AI-powered reverse engineering with Ghidra"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache \
    tini \
    git \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Clone GhidraMCP
RUN git clone --depth 1 https://github.com/LaurieWired/GhidraMCP.git /tmp/ghidra-mcp && \
    cp /tmp/ghidra-mcp/bridge_mcp_ghidra.py /app/ && \
    cp /tmp/ghidra-mcp/requirements.txt /app/ 2>/dev/null || true && \
    rm -rf /tmp/ghidra-mcp

# Install MCP SDK and dependencies
RUN pip install --no-cache-dir mcp httpx requests

ENV PYTHONUNBUFFERED=1
ENV GHIDRA_SERVER_URL=http://host.docker.internal:18489

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "bridge_mcp_ghidra.py"]
