# IDA Pro MCP Server
# Wrapper for mrexodia/ida-pro-mcp
# Based on: https://github.com/mrexodia/ida-pro-mcp
#
# NOTE: Requires IDA Pro 8.3+ license installed on host.
# This container runs the headless MCP server component.

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="IDA Pro MCP Server - AI-powered reverse engineering with IDA Pro"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install ida-pro-mcp from GitHub
RUN pip install --no-cache-dir \
    https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip

ENV PYTHONUNBUFFERED=1

# Note: For SSE transport, IDA must be running with the plugin
# Default assumes SSE server at host.docker.internal:8744
ENV IDA_MCP_URL=http://host.docker.internal:8744/sse

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["ida-pro-mcp"]
