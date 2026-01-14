# Ghidra MCP Server

A Model Context Protocol server for [Ghidra](https://ghidra-sre.org/), the NSA's open-source reverse engineering framework.

> **Note**: This MCP server wraps [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP).

## Prerequisites

**Ghidra must be installed and running with the GhidraMCP plugin:**

1. Download and install [Ghidra](https://ghidra-sre.org/)
2. Download the GhidraMCP plugin from [releases](https://github.com/LaurieWired/GhidraMCP/releases)
3. Install the plugin: File → Install Extensions → Add → select the zip
4. Restart Ghidra and open a project

## Tools

| Tool | Description |
|------|-------------|
| `decompile_function` | Decompile a function to C code |
| `get_function_info` | Get detailed function information |
| `list_functions` | List all functions in the binary |
| `get_xrefs` | Find cross-references to/from an address |
| `search_strings` | Search for strings in the binary |
| `rename_function` | Rename a function |
| `add_comment` | Add a comment at an address |

## Features

- **Decompilation**: Get C code from binary functions
- **Function Analysis**: Analyze parameters, local variables, call graphs
- **Cross-References**: Track data and code references
- **String Search**: Find embedded strings
- **Annotation**: Add comments and rename symbols

## Docker

### Build

```bash
docker build -t ghidra-mcp .
```

### Run

Ensure Ghidra is running with GhidraMCP plugin active, then:

```bash
docker run --rm -i \
  --add-host=host.docker.internal:host-gateway \
  ghidra-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--add-host=host.docker.internal:host-gateway",
        "ghidra-mcp"
      ]
    }
  }
}
```

## Security Notice

This tool is designed for authorized reverse engineering and security research only.

## License

Apache-2.0
