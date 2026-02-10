# sol-azy MCP Server
# Solana sBPF static analysis and reverse engineering toolchain
#
# Security features:
# - Non-root user (uid 1000)
# - Multi-stage build for minimal runtime image
# - Health check included
# - tini as init for proper signal handling

# =============================================================================
# Build Stage (build sol-azy from source)
# =============================================================================
FROM rust:1.88-slim-bookworm AS builder

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="sol-azy MCP Server - Solana sBPF static analysis and reverse engineering"
LABEL org.opencontainers.image.licenses="SSPL-1.0"
LABEL org.opencontainers.image.vendor="FuzzingLabs"

ARG SOLAZY_REPO="https://github.com/FuzzingLabs/sol-azy.git"
ARG SOLAZY_REF="master"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    pkg-config \
    libssl-dev \
    clang \
    lld \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN git clone --depth 1 --branch "${SOLAZY_REF}" "${SOLAZY_REPO}" sol-azy

WORKDIR /tmp/sol-azy

RUN cargo build --release

# =============================================================================
# Production Stage (Python MCP server + sol-azy binary)
# =============================================================================
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/FuzzingLabs/offensive-security-mcps"
LABEL org.opencontainers.image.description="sol-azy MCP Server - Solana sBPF static analysis and reverse engineering"
LABEL org.opencontainers.image.licenses="SSPL-1.0"
LABEL org.opencontainers.image.vendor="FuzzingLabs"

# Security: Create non-root user
RUN groupadd -g 1000 mcpuser && \
    useradd -u 1000 -g mcpuser -m mcpuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tini \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /tmp/sol-azy/target/release/sol-azy /usr/local/bin/sol-azy

COPY --chown=mcpuser:mcpuser requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=mcpuser:mcpuser server.py ./

RUN mkdir -p /app/output /app/uploads && chown -R mcpuser:mcpuser /app

USER mcpuser

# Environment variables
ENV SOLAZY_OUTPUT_DIR=/app/output
ENV SOLAZY_UPLOAD_DIR=/app/uploads
ENV SOLAZY_TIMEOUT=300
ENV SOLAZY_MAX_CONCURRENT=2
ENV SOLAZY_MAX_FILE_SIZE=104857600
ENV SOLAZY_ALLOW_ANY_PATH=0
ENV RUST_LOG=sol_azy=error
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD pgrep -f "python.*server.py" > /dev/null || exit 1

EXPOSE 3000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "server.py"]

