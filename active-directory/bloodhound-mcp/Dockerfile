# BloodHound MCP Server
# Wrapper for MorDavid/BloodHound-MCP-AI
# Based on: https://github.com/MorDavid/BloodHound-MCP-AI

FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="BloodHound MCP Server - Active Directory attack path analysis"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
    tini \
    git \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Clone BloodHound-MCP-AI
RUN git clone --depth 1 https://github.com/MorDavid/BloodHound-MCP-AI.git /tmp/bloodhound-mcp && \
    cp -r /tmp/bloodhound-mcp/* /app/ && \
    rm -rf /tmp/bloodhound-mcp

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "BloodHound-MCP.py"]
