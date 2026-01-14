# VirusTotal MCP Server

A Model Context Protocol server for querying the [VirusTotal](https://www.virustotal.com/) API for malware analysis and threat intelligence.

> **Note**: This MCP server wraps [BurtTheCoder/mcp-virustotal](https://github.com/BurtTheCoder/mcp-virustotal).

## Tools

| Tool | Description |
|------|-------------|
| `scan_url` | Submit a URL for scanning |
| `scan_file` | Submit a file hash for analysis |
| `get_file_report` | Get analysis report for a file |
| `get_url_report` | Get analysis report for a URL |
| `get_domain_report` | Get report for a domain |
| `get_ip_report` | Get report for an IP address |
| `search` | Search VirusTotal for files, URLs, domains |
| `get_file_behavior` | Get behavioral analysis for a file |

## Features

- **File Analysis**: Check file hashes against 70+ antivirus engines
- **URL Scanning**: Analyze URLs for malicious content
- **Domain Intelligence**: Get domain reputation and history
- **IP Lookup**: Check IP addresses for malicious activity
- **Behavioral Analysis**: Review sandbox execution results

## Requirements

- VirusTotal API key (set as `VIRUSTOTAL_API_KEY` environment variable)

## Docker

### Build

```bash
docker build -t virustotal-mcp .
```

### Run

```bash
docker run --rm -i -e VIRUSTOTAL_API_KEY=your_api_key virustotal-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-e", "VIRUSTOTAL_API_KEY", "virustotal-mcp"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

## Security Notice

This tool is designed for authorized security research and threat intelligence. Follow VirusTotal's terms of service.

## License

MIT
