FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Go (architecture aware)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then GO_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then GO_ARCH="arm64"; else GO_ARCH="amd64"; fi && \
    curl -L https://go.dev/dl/go1.22.2.linux-$GO_ARCH.tar.gz | tar -C /usr/local -xzf -
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install Medusa
RUN CGO_ENABLED=1 go install github.com/crytic/medusa@latest

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH=$PATH:/root/.foundry/bin
RUN foundryup

# Install Slither
RUN pip install slither-analyzer

# Setup MCP Workspace
WORKDIR /mcp
COPY server.py requirements.txt README.md /mcp/
RUN pip install --no-cache-dir -r requirements.txt

# Execution workspace (where user project will be mounted)
WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PATH=$PATH:/root/go/bin:/root/.foundry/bin

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

ENTRYPOINT ["python", "/mcp/server.py"]
