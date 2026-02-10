# Medusa MCP Server

Model Context Protocol server for Medusa smart contract fuzzer.

## Tools
- `medusa_init`: Initialize Medusa in current folder.
- `medusa_fuzz`: Run the fuzzer.
- `medusa_get_config`: Get current configuration.
- `medusa_update_config`: Update configuration fields.

## Usage

### Docker

```bash
docker build -t medusa-mcp .
docker run --rm -i -v "$(pwd):/app" -w /app medusa-mcp:latest
```

### Cursor / Claude Configuration (workspace-aware volume)

Add to your `claude_desktop_config.json` (Cursor also honors this format). Uses `${workspaceFolder}` so the project root is mounted automatically:

```json
{
  "mcpServers": {
    "medusa": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v",
        "${workspaceFolder}:/app",
        "-w",
        "/app",
        "medusa-mcp:latest"
      ]
    }
  }
}
```

- `${workspaceFolder}` is substituted by Cursor/Claude with the current workspace root (folder containing `.cursor/mcp.json`).
- The container reads/writes project files from `/app`, so your repo stays in sync.
