# DNStwist MCP Server

A Model Context Protocol server for [DNStwist](https://github.com/elceef/dnstwist), a DNS fuzzing tool that helps detect typosquatting, phishing, and corporate espionage.

> **Note**: This MCP server wraps [BurtTheCoder/mcp-dnstwist](https://github.com/BurtTheCoder/mcp-dnstwist).

## Tools

| Tool | Description |
|------|-------------|
| `check_domain` | Analyze a domain for potential typosquatting and phishing variants |

## Features

- **Domain Fuzzing**: Generate permutations of domain names
- **DNS Resolution**: Check which variants are registered
- **Phishing Detection**: Identify potential phishing domains
- **Corporate Espionage Detection**: Find domains impersonating your brand

## Docker

### Build

```bash
docker build -t dnstwist-mcp .
```

### Run

```bash
docker run --rm -i dnstwist-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dnstwist": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "dnstwist-mcp"]
    }
  }
}
```

## Security Notice

This tool is designed for authorized security testing and brand protection only. Always ensure you have proper authorization.

## License

MIT
