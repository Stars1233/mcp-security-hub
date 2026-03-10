#!/bin/bash
# Test Docker builds for all MCP servers
# Usage: ./scripts/test_builds.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running"
    echo "Please start Docker and try again"
    exit 1
fi

MCPS=(
    # Reconnaissance
    "reconnaissance/nmap-mcp"
    "reconnaissance/shodan-mcp"
    "reconnaissance/pd-tools-mcp"
    "reconnaissance/whatweb-mcp"
    "reconnaissance/masscan-mcp"
    "reconnaissance/zoomeye-mcp"
    "reconnaissance/networksdb-mcp"
    "reconnaissance/externalattacker-mcp"
    # Web Security
    "web-security/nuclei-mcp"
    "web-security/sqlmap-mcp"
    "web-security/nikto-mcp"
    "web-security/ffuf-mcp"
    "web-security/waybackurls-mcp"
    "web-security/burp-mcp"
    # Binary Analysis
    "binary-analysis/binwalk-mcp"
    "binary-analysis/yara-mcp"
    "binary-analysis/capa-mcp"
    "binary-analysis/radare2-mcp"
    "binary-analysis/ghidra-mcp"
    "binary-analysis/ida-mcp"
    # Blockchain Security
    "blockchain/daml-viewer-mcp"
    "blockchain/medusa-mcp"
    "blockchain/solazy-mcp"
    # Cloud Security
    "cloud-security/trivy-mcp"
    "cloud-security/prowler-mcp"
    "cloud-security/roadrecon-mcp"
    # Secrets Detection
    "secrets/gitleaks-mcp"
    # Exploitation
    "exploitation/searchsploit-mcp"
    # Fuzzing
    "fuzzing/boofuzz-mcp"
    "fuzzing/dharma-mcp"
    # OSINT
    "osint/maigret-mcp"
    "osint/dnstwist-mcp"
    # Threat Intelligence
    "threat-intel/virustotal-mcp"
    "threat-intel/otx-mcp"
    # Active Directory
    "active-directory/bloodhound-mcp"
    # Password Cracking
    "password-cracking/hashcat-mcp"
    # Code Security
    "code-security/semgrep-mcp"
    # Meta
    "meta/mcp-scan"
)

PASSED=0
FAILED=0
FAILED_MCPS=()

echo "=========================================="
echo "Testing Docker builds for all MCP servers"
echo "=========================================="
echo ""

for mcp in "${MCPS[@]}"; do
    name=$(basename "$mcp")
    printf "Building %-25s ... " "$name"

    if [ ! -d "$mcp" ]; then
        echo "SKIP (not found)"
        continue
    fi

    if docker build -q -t "test-$name" "./$mcp" > /dev/null 2>&1; then
        echo "OK"
        ((PASSED++))
        # Clean up test image
        docker rmi "test-$name" > /dev/null 2>&1 || true
    else
        echo "FAILED"
        ((FAILED++))
        FAILED_MCPS+=("$name")
    fi
done

echo ""
echo "=========================================="
echo "Results: $PASSED passed, $FAILED failed"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed MCPs:"
    for mcp in "${FAILED_MCPS[@]}"; do
        echo "  - $mcp"
    done
    exit 1
fi

echo ""
echo "All builds passed!"
exit 0
