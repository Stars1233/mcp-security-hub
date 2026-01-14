# Maigret MCP Server

A Model Context Protocol server for [Maigret](https://github.com/soxoj/maigret), a powerful OSINT tool that collects user account information from various public sources.

> **Note**: This MCP server wraps [BurtTheCoder/mcp-maigret](https://github.com/BurtTheCoder/mcp-maigret).

## Tools

| Tool | Description |
|------|-------------|
| `maigret_search` | Search for username across social networks and websites |
| `maigret_url_search` | Analyze a URL to extract and search for usernames |

## Features

- **Username Search**: Find accounts across 2500+ sites
- **URL Analysis**: Extract usernames from URLs and search
- **Multiple Output Formats**: txt, html, pdf, json, csv, xmind
- **Site Filtering**: Filter by tags (social, dating, finance, etc.)

## Docker

### Build

```bash
docker build -t maigret-mcp .
```

### Run

```bash
docker run --rm -i maigret-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "maigret": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "maigret-mcp"]
    }
  }
}
```

## Security Notice

This tool is designed for authorized security testing and OSINT research only. Always ensure you have proper authorization and follow applicable laws and regulations.

## License

MIT
