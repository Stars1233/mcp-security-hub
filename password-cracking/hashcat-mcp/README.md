# Hashcat MCP Server

A Model Context Protocol server for [Hashcat](https://hashcat.net/hashcat/), the world's fastest password recovery tool.

> **Note**: This MCP server wraps [MorDavid/hashcat-mcp](https://github.com/MorDavid/hashcat-mcp).

## Tools

| Tool | Description |
|------|-------------|
| `crack_hash` | Crack a password hash using dictionary or brute-force attack |
| `identify_hash` | Identify the type of a hash |
| `list_hash_modes` | List supported hash types |
| `benchmark` | Run hashcat benchmark |

## Features

- **Natural Language Interface**: Describe what you want to crack in plain English
- **Multiple Attack Modes**: Dictionary, brute-force, rule-based, hybrid attacks
- **Hash Identification**: Automatic hash type detection
- **GPU Acceleration**: Leverage GPU for faster cracking

## Docker

### Build

```bash
docker build -t hashcat-mcp .
```

### Run

```bash
docker run --rm -i \
  -v /path/to/wordlists:/app/wordlists:ro \
  hashcat-mcp
```

### With GPU Support

```bash
docker run --rm -i \
  --gpus all \
  -v /path/to/wordlists:/app/wordlists:ro \
  hashcat-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hashcat": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/wordlists:/app/wordlists:ro",
        "hashcat-mcp"
      ]
    }
  }
}
```

## Security Notice

This tool is designed for authorized password security testing and recovery only. Only use on systems you own or have explicit permission to test.

## License

MIT
