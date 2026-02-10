#!/usr/bin/env python3
import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional, List, Dict, Union

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic import BaseModel, Field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("medusa-mcp")

app = Server("medusa-mcp")
BASE_DIR = Path("/app")
if BASE_DIR.exists():
    os.chdir(BASE_DIR)
else:
    BASE_DIR = Path.cwd()

# ---------------------------------------------------------------------------
# Models for Input Validation & CLI Generation
# ---------------------------------------------------------------------------

class FuzzArguments(BaseModel):
    model_config = {"populate_by_name": True}

    workspace: Optional[str] = Field(None, description="Subdirectory to run fuzz in (optional)")
    timeout: Optional[int] = Field(None, description="Time limit in seconds")
    config: Optional[str] = Field(None, alias="config", description="Path to medusa.json config file")
    compilation_target: Optional[str] = Field(None, alias="compilation-target", description="Target contract or directory to compile")
    workers: Optional[int] = Field(None, alias="workers", description="Number of fuzzer workers")
    test_limit: Optional[int] = Field(None, alias="test-limit", description="Number of transactions to test before exiting (0 = no limit)")
    seq_len: Optional[int] = Field(None, alias="seq-len", description="Maximum transactions to run in sequence")
    target_contracts: Optional[List[str]] = Field(None, alias="target-contracts", description="List of target contracts for fuzz testing")
    corpus_dir: Optional[str] = Field(None, alias="corpus-dir", description="Directory for corpus items and coverage reports")
    senders: Optional[List[str]] = Field(None, alias="senders", description="Account addresses used to send state-changing txns")
    deployer: Optional[str] = Field(None, alias="deployer", description="Account address used to deploy contracts")
    no_color: bool = Field(False, alias="no-color", description="Disable colored terminal output")
    fail_fast: bool = Field(False, alias="fail-fast", description="Stop on first failed test")
    explore: bool = Field(False, alias="explore", description="Enable exploration mode")
    use_slither: bool = Field(False, alias="use-slither", description="Run slither and use cached results")
    use_slither_force: bool = Field(False, alias="use-slither-force", description="Run slither and overwrite cached results")
    rpc_url: Optional[str] = Field(None, alias="rpc-url", description="RPC URL to fetch contracts over")
    rpc_block: Optional[int] = Field(None, alias="rpc-block", description="Block number to use when fetching contracts over RPC")
    verbosity: Optional[int] = Field(None, description="Execution trace verbosity level (1=-v, 2=-vv, 3=-vvv)")
    log_level: Optional[str] = Field(None, alias="log-level", description="Log level: trace, debug, info, warn, error, or panic")

    def to_flags(self) -> List[str]:
        flags = []
        for field_name, value in self.dict(by_alias=True, exclude_none=True).items():
            if field_name in ["workspace", "timeout", "verbosity"]:
                continue
            if isinstance(value, bool):
                if value: flags.append(f"--{field_name}")
            elif isinstance(value, list):
                flags.extend([f"--{field_name}", ",".join(map(str, value))])
            else:
                flags.extend([f"--{field_name}", str(value)])
        
        if self.verbosity and 1 <= self.verbosity <= 3:
            flags.append("-" + "v" * self.verbosity)
        if self.timeout:
            flags.extend(["--timeout", str(self.timeout)])
        return flags

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _run_command(cmd: List[str], cwd: Path, timeout: float = 300.0) -> List[TextContent]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=cwd
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        
        def truncate(text: bytes, limit: int = 10000) -> str:
            decoded = text.decode()
            if len(decoded) <= limit: return decoded
            half = limit // 2
            return f"{decoded[:half]}\n... [truncated] ...\n{decoded[-half:]}"

        res = []
        if stdout: res.append(TextContent(type="text", text=f"STDOUT:\n{truncate(stdout)}"))
        if stderr: res.append(TextContent(type="text", text=f"STDERR:\n{truncate(stderr)}"))
        return res
    except asyncio.TimeoutError:
        return [TextContent(type="text", text="Command timed out.")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]

def _get_cwd(args: Dict) -> Path:
    ws = args.get("workspace") or args.get("path") or "."
    path = BASE_DIR / ws
    if not path.exists(): raise ValueError(f"Directory {path} does not exist")
    return path

# ---------------------------------------------------------------------------
# Tool Registration
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="medusa_init",
            description="Initialize Medusa in the current directory.",
            inputSchema={"type": "object", "properties": {"workspace": {"type": "string"}}},
        ),
        Tool(
            name="medusa_fuzz",
            description="Run the Medusa fuzzing process.",
            inputSchema=FuzzArguments.schema(),
        ),
        Tool(
            name="medusa_get_config",
            description="Read medusa.json.",
            inputSchema={"type": "object", "properties": {"workspace": {"type": "string"}}},
        ),
        Tool(
            name="medusa_update_config",
            description="Update medusa.json fields.",
            inputSchema={
                "type": "object", 
                "properties": {
                    "updates": {"type": "object"}, 
                    "workspace": {"type": "string"}
                },
                "required": ["updates"]
            },
        ),
       
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        cwd = _get_cwd(arguments)
        
        if name == "medusa_init":
            return await _run_command(["medusa", "init"], cwd)
            
        elif name == "medusa_fuzz":
            args = FuzzArguments(**arguments)
            timeout = float(args.timeout + 60) if args.timeout else 300.0
            return await _run_command(["medusa", "fuzz"] + args.to_flags(), cwd, timeout)
            
        elif name == "medusa_get_config":
            cfg = cwd / "medusa.json"
            if not cfg.exists(): return [TextContent(type="text", text="medusa.json not found. Run init first.")]
            return [TextContent(type="text", text=cfg.read_text())]
            
        elif name == "medusa_update_config":
            cfg = cwd / "medusa.json"
            if not cfg.exists(): return [TextContent(type="text", text="medusa.json not found.")]
            data = json.loads(cfg.read_text())
            def deep_update(d, u):
                for k, v in u.items():
                    if isinstance(v, dict): d[k] = deep_update(d.get(k, {}), v)
                    else: d[k] = v
                return d
            cfg.write_text(json.dumps(deep_update(data, arguments["updates"]), indent=4))
            return [TextContent(type="text", text="Updated successfully.")]
            
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.error(f"Error in {name}: {e}")
        return [TextContent(type="text", text=f"Error: {e}")]

async def main():
    logger.info("Starting Medusa MCP")
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
