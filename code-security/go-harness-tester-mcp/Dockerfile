# Go Harness Tester MCP Server
# Validates Go fuzz harness quality through compile, execute, and trial phases

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ENV GOROOT=/usr/local/go \
    GOPATH=/root/go \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
RUN curl -fsSL https://go.dev/dl/go1.22.8.linux-amd64.tar.gz | tar -C /usr/local -xz

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENTRYPOINT ["tini", "--"]
CMD ["python", "server.py"]
