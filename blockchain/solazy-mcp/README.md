# sol-azy MCP Server

A Model Context Protocol server that provides Solana sBPF static analysis and reverse engineering capabilities using [sol-azy](https://github.com/FuzzingLabs/sol-azy).

Transport: stdio (no HTTP server).

## Tools

| Tool | Description |
|------|-------------|
| `solazy_reverse` | Reverse engineer a compiled `.so` (disassembly/CFG/both) |
| `solazy_sast` | Run Starlark-based SAST on an Anchor or SBF project directory |
| `solazy_recap` | Generate an audit-friendly markdown recap for an Anchor project |
| `solazy_fetcher` | Fetch a deployed program bytecode from an RPC endpoint |
| `solazy_dotting` | Reinsert selected functions into a reduced CFG `.dot` |
| `get_run_results` | Retrieve results from a previous run |
| `list_runs` | List completed runs |
| `list_active_runs` | Show currently running jobs |

## Features

- **Reverse Engineering**: Generate disassembly, immediate data tables, and control flow graphs from sBPF `.so` bytecode
- **SAST Rules Engine**: Run built-in and/or external Starlark rules against Rust ASTs (Anchor or raw SBF projects)
- **Anchor Recap**: Produce an audit-friendly `recap-solazy.md` report from Anchor IDLs and program source
- **On-chain Fetching**: Download deployed program bytecode to a local `.so` for analysis
- **CFG Editing**: Reinsert selected function clusters into reduced graphs (`dotting`)
- **Run Tracking**: Collect tool outputs and artifacts in per-run directories under `/app/output`

## Docker

### Build

```bash
docker build -t solazy-mcp .
```

Optional: pin which `sol-azy` ref to build:

```bash
docker build -t solazy-mcp --build-arg SOLAZY_REF=master .
```

### Run

```bash
docker run --rm -i solazy-mcp
```

### With volumes

Mount your inputs (program `.so`, Anchor project, SBF crate, config/dot files) under `/app/uploads` and outputs under `/app/output`:

```bash
docker run --rm -i \
  -v /path/to/inputs:/app/uploads:ro \
  -v /path/to/output:/app/output \
  solazy-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "solazy": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/inputs:/app/uploads:ro",
        "-v", "/path/to/output:/app/output",
        "solazy-mcp"
      ]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SOLAZY_OUTPUT_DIR` | `/app/output` | Directory for outputs and per-run artifacts |
| `SOLAZY_UPLOAD_DIR` | `/app/uploads` | Directory for mounted inputs |
| `SOLAZY_TIMEOUT` | `300` | Default command timeout (seconds) |
| `SOLAZY_MAX_CONCURRENT` | `2` | Maximum concurrent runs |
| `SOLAZY_MAX_FILE_SIZE` | `104857600` | Max input file size (100MB) |
| `SOLAZY_ALLOW_ANY_PATH` | `0` | If `1`, disables path restrictions (less safe) |
| `SOLAZY_BIN` | `sol-azy` | Path to the `sol-azy` executable |
| `SOLAZY_MAX_TEXT_OUTPUT` | `20000` | Max chars kept for captured stdout/stderr |
| `SOLAZY_MAX_ARTIFACT_PREVIEW` | `20000` | Max chars for artifact previews |

## Example Usage

### Reverse engineer a program `.so`

```
Reverse engineer /app/uploads/program.so and generate disassembly + CFG
```

### Run SAST on an Anchor project

```
Run SAST on /app/uploads/my-anchor-project using internal rules
```

### Generate an Anchor recap report

```
Generate a recap for /app/uploads/my-anchor-project and show me the markdown summary
```

### Fetch and analyze an on-chain program

```
Fetch program 4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg from mainnet, then reverse engineer the fetched .so
```

### Update a reduced CFG with selected functions

```
Use dotting with config /app/uploads/functions.json, reduced dot /app/uploads/reduced.dot, and full dot /app/uploads/full.dot
```

## Common Solana Program Analysis Workflow

1. **Fetch**: Download a deployed program bytecode with `solazy_fetcher` (or mount a local `.so` under `/app/uploads`)
2. **Reverse**: Run `solazy_reverse` in `both` mode to generate `disassembly.out` and `cfg.dot`
3. **SAST**: Run `solazy_sast` on the program source project (Anchor or SBF)
4. **Refine CFG**: If you used reduced CFG output, reinsert function clusters with `solazy_dotting`

## License

SSPL-1.0
