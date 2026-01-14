# Hashcat MCP Server
# Wrapper for MorDavid/hashcat-mcp
# Based on: https://github.com/MorDavid/hashcat-mcp

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="Hashcat MCP Server - Natural language hash cracking"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    git \
    hashcat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clone hashcat-mcp
RUN git clone --depth 1 https://github.com/MorDavid/hashcat-mcp.git /tmp/hashcat-mcp && \
    cp -r /tmp/hashcat-mcp/* /app/ && \
    rm -rf /tmp/hashcat-mcp

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create wordlists directory
RUN mkdir -p /app/wordlists

ENV PYTHONUNBUFFERED=1
ENV HASHCAT_WORDLISTS_DIR=/app/wordlists

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "hashcat_mcp_server.py"]
