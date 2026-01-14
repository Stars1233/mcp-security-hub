# IDA Pro MCP Server

A Model Context Protocol server for [IDA Pro](https://hex-rays.com/ida-pro/), the industry-standard disassembler and debugger.

> **Note**: This MCP server wraps [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).

## Prerequisites

**IDA Pro 8.3+ must be installed with a valid license:**

1. Install IDA Pro 8.3 or later (IDA 9+ recommended)
2. Install the MCP plugin: `pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip`
3. Run `ida-pro-mcp --install` to install the IDA plugin
4. Restart IDA Pro

## Tools

| Tool | Description |
|------|-------------|
| `decompile_function` | Decompile function to pseudocode |
| `get_function_info` | Get function details and metadata |
| `list_functions` | List all functions |
| `get_disassembly` | Get assembly at an address |
| `get_xrefs_to` | Find references to an address |
| `get_xrefs_from` | Find references from an address |
| `rename_function` | Rename a function |
| `set_function_type` | Set function prototype |
| `add_comment` | Add a comment |

## Features

- **Hex-Rays Decompiler**: Get high-quality pseudocode
- **Type Recovery**: Automatic and manual type application
- **Cross-References**: Full xref analysis
- **Batch Operations**: Process multiple functions
- **Headless Mode**: Run without GUI (with idalib)

## Docker

### Build

```bash
docker build -t ida-mcp .
```

### Run

Ensure IDA Pro is running with the MCP plugin active:

```bash
docker run --rm -i \
  --add-host=host.docker.internal:host-gateway \
  ida-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ida": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--add-host=host.docker.internal:host-gateway",
        "ida-mcp"
      ]
    }
  }
}
```

## Security Notice

This tool is designed for authorized reverse engineering and security research only.

## License

MIT
