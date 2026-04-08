# Go Analyzer MCP Server
# Static analysis of Go source code for fuzz target identification + govulncheck

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/mcp-security-hub"
LABEL org.opencontainers.image.description="Go Analyzer MCP Server - Identifies fuzzable entry points, unsafe usage, and CVEs"
LABEL org.opencontainers.image.licenses="MIT"

RUN groupadd -g 1000 mcpuser && \
    useradd -u 1000 -g mcpuser -m mcpuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Go (globally accessible)
ENV GOROOT=/usr/local/go \
    GOPATH=/usr/local/gopath \
    PATH="/usr/local/go/bin:/usr/local/gopath/bin:${PATH}"
RUN curl -fsSL https://go.dev/dl/go1.22.8.linux-amd64.tar.gz | tar -C /usr/local -xz \
    && chmod -R a+rX /usr/local/go

# Install govulncheck
RUN go install golang.org/x/vuln/cmd/govulncheck@latest \
    && chmod -R a+rX /usr/local/gopath

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=mcpuser:mcpuser server.py .

RUN mkdir -p /data && chown -R mcpuser:mcpuser /data /app

USER mcpuser

ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]
