# Burp Suite MCP Server

The official Model Context Protocol server for [Burp Suite](https://portswigger.net/burp), the leading web application security testing platform.

> **Note**: This MCP server wraps [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server).

## Prerequisites

**Burp Suite must be installed:**

1. Install Burp Suite Professional or Community Edition
2. Download the MCP extension from the BApp Store or build from source
3. Load the extension in Burp: Extensions → Add
4. The MCP server starts automatically on port 9876

## Tools

| Tool | Description |
|------|-------------|
| `get_sitemap` | Get the current site map |
| `send_to_repeater` | Send a request to Repeater |
| `send_to_intruder` | Send a request to Intruder |
| `get_proxy_history` | Get proxy history |
| `active_scan` | Start an active scan |
| `passive_scan` | Analyze for passive issues |
| `get_issues` | Get discovered vulnerabilities |

## Features

- **Proxy Integration**: Access intercepted traffic
- **Scanner Control**: Trigger active and passive scans
- **Repeater/Intruder**: Send requests to testing tools
- **Issue Tracking**: Retrieve discovered vulnerabilities
- **Site Map**: Browse application structure

## Docker

### Build

```bash
docker build -t burp-mcp .
```

### Run

Ensure Burp Suite is running with the MCP extension active:

```bash
docker run --rm -i \
  --add-host=host.docker.internal:host-gateway \
  -e BURP_URL=http://host.docker.internal:9876 \
  burp-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "burp": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--add-host=host.docker.internal:host-gateway",
        "burp-mcp"
      ]
    }
  }
}
```

## Alternative: Direct Extension Use

For simpler setup, use Burp's built-in MCP directly:

1. Install the MCP extension in Burp Suite
2. Configure Claude Desktop to connect to `http://127.0.0.1:9876`

## Security Notice

This tool is designed for authorized web application security testing only. Always ensure you have proper authorization.

## License

GPL-3.0
