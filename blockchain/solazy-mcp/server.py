#!/usr/bin/env python3
"""
sol-azy MCP Server

A Model Context Protocol server that provides Solana sBPF static analysis and reverse
engineering capabilities using the `sol-azy` CLI.

Transport:
  - stdio (no network port required)

Tools:
  - solazy_reverse: Reverse engineer a compiled `.so` (disassembly/CFG/both)
  - solazy_sast: Run Starlark-based SAST on an Anchor or SBF project directory
  - solazy_recap: Generate an audit-friendly markdown recap for an Anchor project
  - solazy_fetcher: Fetch a deployed program bytecode from an RPC endpoint
  - solazy_dotting: Reinsert selected functions into a reduced CFG `.dot`
  - get_run_results: Get results for a previous run ID
  - list_runs: List completed runs
  - list_active_runs: List currently running jobs
"""

import asyncio
import json
import logging
import os, sys
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, TextContent, Tool
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

LOG_LEVEL = os.environ.get("SOLAZY_LOG_LEVEL", "WARNING").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
    stream=sys.stderr,  # important
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("solazy-mcp")

class Settings(BaseSettings):
    """Server configuration from environment variables."""
    model_config = SettingsConfigDict(env_prefix="SOLAZY_")

    output_dir: str = Field(default="/app/output", alias="SOLAZY_OUTPUT_DIR")
    upload_dir: str = Field(default="/app/uploads", alias="SOLAZY_UPLOAD_DIR")
    default_timeout: int = Field(default=300, alias="SOLAZY_TIMEOUT")
    max_concurrent: int = Field(default=2, alias="SOLAZY_MAX_CONCURRENT")
    max_file_size: int = Field(default=104857600, alias="SOLAZY_MAX_FILE_SIZE") # 100 MB
    allow_any_path: bool = Field(default=False, alias="SOLAZY_ALLOW_ANY_PATH")
    solazy_bin: str = Field(default="sol-azy", alias="SOLAZY_BIN")
    max_text_output: int = Field(default=20000, alias="SOLAZY_MAX_TEXT_OUTPUT")
    max_artifact_preview: int = Field(default=20000, alias="SOLAZY_MAX_ARTIFACT_PREVIEW")


settings = Settings()


class Artifact(BaseModel):
    path: str
    size: int


class RunResult(BaseModel):
    run_id: str
    run_type: str
    command: list[str]
    out_dir: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"  # running|completed|failed|timeout|error
    artifacts: list[Artifact] = []
    stdout: str | None = None
    stderr: str | None = None
    error: str | None = None


run_results: dict[str, RunResult] = {}
active_runs: set[str] = set()


def _resolve(path_str: str) -> Path:
    return Path(path_str).expanduser().resolve(strict=False)


def _is_allowed_path(p: Path) -> bool:
    if settings.allow_any_path:
        return True

    upload_root = _resolve(settings.upload_dir)
    output_root = _resolve(settings.output_dir)

    try:
        p.relative_to(upload_root)
        return True
    except ValueError:
        pass

    try:
        p.relative_to(output_root)
        return True
    except ValueError:
        pass

    return False


def _validate_existing_path(path_str: str, *, expect_dir: bool | None = None) -> tuple[Path | None, str | None]:
    p = _resolve(path_str)

    if not _is_allowed_path(p):
        return None, (
            f"Path not allowed: {p}. "
            f"Allowed roots: {settings.upload_dir}, {settings.output_dir}. "
            "Set SOLAZY_ALLOW_ANY_PATH=1 to disable this restriction."
        )

    if not p.exists():
        return None, f"Path not found: {p}"

    if expect_dir is True and not p.is_dir():
        return None, f"Expected a directory, got: {p}"
    if expect_dir is False and not p.is_file():
        return None, f"Expected a file, got: {p}"

    if p.is_file():
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        if size > settings.max_file_size:
            return None, f"File too large ({size} bytes). Max: {settings.max_file_size} bytes."

    return p, None


def _collect_artifacts(root: Path) -> list[Artifact]:
    artifacts: list[Artifact] = []
    if not root.exists():
        return artifacts
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        artifacts.append(Artifact(path=str(p), size=size))
    artifacts.sort(key=lambda a: a.path)
    return artifacts


def _read_text_preview(path: Path, max_chars: int) -> str:
    try:
        data = path.read_text(errors="replace")
    except Exception as e:
        return f"(error reading {path}: {e})"
    if len(data) <= max_chars:
        return data
    return data[:max_chars] + "\n...(truncated)...\n"


async def _run_cmd(cmd: list[str], *, cwd: Path, timeout: int | None) -> tuple[int, str, str]:
    env = os.environ.copy()
    env.setdefault("RUST_LOG", "sol_azy=error")
    env.setdefault("TERM", "dumb")
    # sol-azy `recap` uses $PWD to decide where to write `recap-solazy.md`.
    env["PWD"] = str(cwd)

    logger.debug("Running command: %s (cwd=%s)", " ".join(cmd), cwd)

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd),
        env=env,
    )

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout or settings.default_timeout),
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        raise

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    return int(process.returncode or 0), stdout, stderr


def _truncate(s: str | None, max_chars: int) -> str | None:
    if s is None:
        return None
    if len(s) <= max_chars:
        return s
    return s[:max_chars] + "\n...(truncated)...\n"


def _format_run_summary(
    result: RunResult,
    *,
    include_stdout: bool = False,
    include_stderr: bool = False,
    include_artifacts: bool = True,
    include_artifact_previews: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "run_id": result.run_id,
        "run_type": result.run_type,
        "status": result.status,
        "command": result.command,
        "out_dir": result.out_dir,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "error": result.error,
    }

    if include_artifacts:
        out["artifacts"] = [a.model_dump() for a in result.artifacts]

    if include_stdout:
        out["stdout"] = result.stdout
    if include_stderr:
        out["stderr"] = result.stderr

    if include_artifact_previews:
        previews: dict[str, str] = {}
        for a in result.artifacts:
            p = Path(a.path)
            if not p.exists() or a.size > settings.max_file_size:
                continue
            if p.suffix in {".out", ".dot", ".md", ".json", ".txt"}:
                previews[str(p)] = _read_text_preview(p, settings.max_artifact_preview)
        out["artifact_previews"] = previews

    return out


def _new_run(run_type: str, command: list[str], out_dir: Path) -> RunResult:
    run_id = str(uuid.uuid4())[:8]
    result = RunResult(
        run_id=run_id,
        run_type=run_type,
        command=command,
        out_dir=str(out_dir),
        started_at=datetime.now(),
    )
    run_results[run_id] = result
    return result


async def _run_solazy_job(
    run_type: str,
    args: list[str],
    *,
    timeout: int | None,
    cwd: Path,
) -> RunResult:
    if len(active_runs) >= settings.max_concurrent:
        raise RuntimeError(f"Maximum concurrent runs ({settings.max_concurrent}) reached.")

    cmd = [settings.solazy_bin, *args]
    result = _new_run(run_type, cmd, cwd)
    active_runs.add(result.run_id)

    try:
        rc, stdout, stderr = await _run_cmd(cmd, cwd=cwd, timeout=timeout)
        result.completed_at = datetime.now()
        result.stdout = _truncate(stdout, settings.max_text_output)
        result.stderr = _truncate(stderr, settings.max_text_output)
        result.artifacts = _collect_artifacts(cwd)

        if rc == 0:
            result.status = "completed"
        else:
            result.status = "failed"
            if stderr.strip():
                result.error = stderr.strip()[:2000]
            else:
                result.error = f"Command failed with exit code {rc}"

    except asyncio.TimeoutError:
        result.completed_at = datetime.now()
        result.status = "timeout"
        result.error = f"Timed out after {timeout or settings.default_timeout} seconds"

    except Exception as e:
        result.completed_at = datetime.now()
        result.status = "error"
        result.error = str(e)

    finally:
        active_runs.discard(result.run_id)
        run_results[result.run_id] = result

    return result


# Create MCP server
app = Server("solazy-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="solazy_reverse",
            description="Reverse engineer a compiled Solana sBPF `.so` file. "
            "Generates disassembly (`disassembly.out`), immediate table (`immediate_data_table.out`), "
            "and/or CFG (`cfg.dot`) depending on mode.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {"type": "string", "description": "Path to the `.so` file to analyze"},
                    "mode": {
                        "type": "string",
                        "enum": ["disass", "cfg", "both"],
                        "default": "both",
                        "description": "Output mode",
                    },
                    "labeling": {
                        "type": "boolean",
                        "default": True,
                        "description": "Enable symbol/section labeling in analysis",
                    },
                    "reduced": {
                        "type": "boolean",
                        "default": False,
                        "description": "Generate a reduced CFG (functions after entrypoint)",
                    },
                    "only_entrypoint": {
                        "type": "boolean",
                        "default": False,
                        "description": "Generate a CFG containing only the entrypoint cluster",
                    },
                    "timeout": {
                        "type": "integer",
                        "default": 300,
                        "description": "Timeout in seconds",
                    },
                    "include_artifact_previews": {
                        "type": "boolean",
                        "default": False,
                        "description": "Include small previews of generated artifacts",
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="solazy_sast",
            description="Run SAST (Starlark rules) on an Anchor or SBF project directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_dir": {
                        "type": "string",
                        "description": "Path to the project directory (Anchor root or SBF crate root)",
                    },
                    "rules_dir": {
                        "type": "string",
                        "description": "Optional external rules directory (contains `.star` files)",
                    },
                    "syn_scan_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "Only parse Rust AST (skip rule evaluation)",
                    },
                    "use_internal_rules": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include built-in sol-azy rules",
                    },
                    "timeout": {
                        "type": "integer",
                        "default": 600,
                        "description": "Timeout in seconds",
                    },
                },
                "required": ["target_dir"],
            },
        ),
        Tool(
            name="solazy_recap",
            description="Generate an audit-friendly markdown recap for an Anchor project. "
            "Produces `recap-solazy.md` in the run output directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "anchor_dir": {"type": "string", "description": "Path to the Anchor project root"},
                    "timeout": {"type": "integer", "default": 300, "description": "Timeout in seconds"},
                    "include_markdown": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include a truncated markdown preview in the response",
                    },
                },
                "required": ["anchor_dir"],
            },
        ),
        Tool(
            name="solazy_fetcher",
            description="Fetch a deployed program bytecode (or account) from a Solana RPC endpoint. "
            "Writes `fetched_program.so` or `fetched_account.bin` to the run output directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "program_id": {"type": "string", "description": "Solana Program ID to fetch"},
                    "rpc_url": {"type": "string", "description": "Optional RPC URL"},
                    "timeout": {"type": "integer", "default": 120, "description": "Timeout in seconds"},
                },
                "required": ["program_id"],
            },
        ),
        Tool(
            name="solazy_dotting",
            description="Reinsert functions (clusters) into a reduced CFG `.dot` using a JSON config.",
            inputSchema={
                "type": "object",
                "properties": {
                    "config_path": {"type": "string", "description": "Path to JSON config: {\"functions\": [\"10\", ...]}"},
                    "reduced_dot_path": {"type": "string", "description": "Path to reduced .dot file"},
                    "full_dot_path": {"type": "string", "description": "Path to full .dot file"},
                    "timeout": {"type": "integer", "default": 120, "description": "Timeout in seconds"},
                    "include_updated_dot": {
                        "type": "boolean",
                        "default": False,
                        "description": "Include a truncated preview of the updated dot file",
                    },
                },
                "required": ["config_path", "reduced_dot_path", "full_dot_path"],
            },
        ),
        Tool(
            name="get_run_results",
            description="Retrieve results from a previous run by run ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "run_id": {"type": "string", "description": "Run ID returned by a previous tool"},
                    "include_stdout": {"type": "boolean", "default": False},
                    "include_stderr": {"type": "boolean", "default": False},
                    "include_artifacts": {"type": "boolean", "default": True},
                    "include_artifact_previews": {"type": "boolean", "default": False},
                },
                "required": ["run_id"],
            },
        ),
        Tool(
            name="list_runs",
            description="List completed runs (most recent first).",
            inputSchema={
                "type": "object",
                "properties": {
                    "run_type": {"type": "string", "description": "Filter by run type (reverse|sast|recap|fetcher|dotting)"},
                    "status": {"type": "string", "description": "Filter by status (completed|failed|timeout|error)"},
                    "limit": {"type": "integer", "default": 50, "description": "Max results"},
                },
            },
        ),
        Tool(
            name="list_active_runs",
            description="List currently running jobs.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        output_root = _resolve(settings.output_dir)
        output_root.mkdir(parents=True, exist_ok=True)

        if name == "solazy_reverse":
            filepath, err = _validate_existing_path(arguments["filepath"], expect_dir=False)
            if err:
                return [TextContent(type="text", text=err)]

            run_dir = output_root / f"reverse_{str(uuid.uuid4())[:8]}"
            run_dir.mkdir(parents=True, exist_ok=True)

            mode = arguments.get("mode", "both")
            labeling = bool(arguments.get("labeling", True))
            reduced = bool(arguments.get("reduced", False))
            only_entrypoint = bool(arguments.get("only_entrypoint", False))
            timeout = arguments.get("timeout")

            args = [
                "reverse",
                "--mode",
                mode,
                "--out-dir",
                str(run_dir),
                "--bytecodes-file",
                str(filepath),
            ]
            if labeling:
                args.append("--labeling")
            if reduced:
                args.append("--reduced")
            if only_entrypoint:
                args.append("--only-entrypoint")

            result = await _run_solazy_job("reverse", args, timeout=timeout, cwd=run_dir)
            summary = _format_run_summary(
                result,
                include_stdout=False,
                include_stderr=False,
                include_artifacts=True,
                include_artifact_previews=bool(arguments.get("include_artifact_previews", False)),
            )
            return [TextContent(type="text", text=json.dumps(summary, indent=2))]

        if name == "solazy_sast":
            target_dir, err = _validate_existing_path(arguments["target_dir"], expect_dir=True)
            if err:
                return [TextContent(type="text", text=err)]

            run_dir = output_root / f"sast_{str(uuid.uuid4())[:8]}"
            run_dir.mkdir(parents=True, exist_ok=True)

            rules_dir = arguments.get("rules_dir")
            if rules_dir:
                rules_path, err = _validate_existing_path(rules_dir, expect_dir=True)
                if err:
                    return [TextContent(type="text", text=err)]
                rules_dir = str(rules_path)

            syn_scan_only = bool(arguments.get("syn_scan_only", False))
            use_internal_rules = bool(arguments.get("use_internal_rules", True))
            timeout = arguments.get("timeout")

            args = ["sast", "-d", str(target_dir)]
            if rules_dir:
                args += ["-r", rules_dir]
            if syn_scan_only:
                args.append("--syn-scan-only")
            if not use_internal_rules:
                args.append("--no-internal-rules")

            result = await _run_solazy_job("sast", args, timeout=timeout, cwd=run_dir)
            summary = _format_run_summary(
                result,
                include_stdout=True,
                include_stderr=True,
                include_artifacts=True,
                include_artifact_previews=False,
            )
            return [TextContent(type="text", text=json.dumps(summary, indent=2))]

        if name == "solazy_recap":
            anchor_dir, err = _validate_existing_path(arguments["anchor_dir"], expect_dir=True)
            if err:
                return [TextContent(type="text", text=err)]

            run_dir = output_root / f"recap_{str(uuid.uuid4())[:8]}"
            run_dir.mkdir(parents=True, exist_ok=True)

            timeout = arguments.get("timeout")
            include_markdown = bool(arguments.get("include_markdown", True))

            args = ["recap", "-d", str(anchor_dir)]
            result = await _run_solazy_job("recap", args, timeout=timeout, cwd=run_dir)

            summary = _format_run_summary(
                result,
                include_stdout=True,
                include_stderr=True,
                include_artifacts=True,
                include_artifact_previews=False,
            )

            recap_path = run_dir / "recap-solazy.md"
            if include_markdown and recap_path.exists():
                summary["recap_markdown_preview"] = _read_text_preview(
                    recap_path, settings.max_artifact_preview
                )

            return [TextContent(type="text", text=json.dumps(summary, indent=2))]

        if name == "solazy_fetcher":
            run_dir = output_root / f"fetcher_{str(uuid.uuid4())[:8]}"
            run_dir.mkdir(parents=True, exist_ok=True)

            program_id = arguments["program_id"]
            rpc_url = arguments.get("rpc_url")
            timeout = arguments.get("timeout")

            args = ["fetcher", "-p", program_id, "-o", str(run_dir)]
            if rpc_url:
                args += ["-r", rpc_url]

            result = await _run_solazy_job("fetcher", args, timeout=timeout, cwd=run_dir)
            summary = _format_run_summary(
                result,
                include_stdout=True,
                include_stderr=True,
                include_artifacts=True,
                include_artifact_previews=False,
            )
            return [TextContent(type="text", text=json.dumps(summary, indent=2))]

        if name == "solazy_dotting":
            config_path, err = _validate_existing_path(arguments["config_path"], expect_dir=False)
            if err:
                return [TextContent(type="text", text=err)]

            reduced_dot, err = _validate_existing_path(arguments["reduced_dot_path"], expect_dir=False)
            if err:
                return [TextContent(type="text", text=err)]

            full_dot, err = _validate_existing_path(arguments["full_dot_path"], expect_dir=False)
            if err:
                return [TextContent(type="text", text=err)]

            run_dir = output_root / f"dotting_{str(uuid.uuid4())[:8]}"
            run_dir.mkdir(parents=True, exist_ok=True)

            # Work on copies so we never write into uploads/mounted dirs.
            cfg_copy = run_dir / config_path.name
            reduced_copy = run_dir / reduced_dot.name
            full_copy = run_dir / full_dot.name
            shutil.copy2(config_path, cfg_copy)
            shutil.copy2(reduced_dot, reduced_copy)
            shutil.copy2(full_dot, full_copy)

            timeout = arguments.get("timeout")
            include_updated_dot = bool(arguments.get("include_updated_dot", False))

            args = [
                "dotting",
                "-c",
                str(cfg_copy),
                "-r",
                str(reduced_copy),
                "-f",
                str(full_copy),
            ]

            result = await _run_solazy_job("dotting", args, timeout=timeout, cwd=run_dir)
            summary = _format_run_summary(
                result,
                include_stdout=True,
                include_stderr=True,
                include_artifacts=True,
                include_artifact_previews=False,
            )

            updated = run_dir / f"updated_{reduced_copy.name}"
            if include_updated_dot and updated.exists():
                summary["updated_dot_preview"] = _read_text_preview(
                    updated, settings.max_artifact_preview
                )

            return [TextContent(type="text", text=json.dumps(summary, indent=2))]

        if name == "get_run_results":
            run_id = arguments["run_id"]
            result = run_results.get(run_id)
            if not result:
                return [TextContent(type="text", text=f"Run '{run_id}' not found")]

            summary = _format_run_summary(
                result,
                include_stdout=bool(arguments.get("include_stdout", False)),
                include_stderr=bool(arguments.get("include_stderr", False)),
                include_artifacts=bool(arguments.get("include_artifacts", True)),
                include_artifact_previews=bool(arguments.get("include_artifact_previews", False)),
            )
            return [TextContent(type="text", text=json.dumps(summary, indent=2))]

        if name == "list_runs":
            limit = int(arguments.get("limit", 50))
            filt_type = arguments.get("run_type")
            filt_status = arguments.get("status")

            items = list(run_results.values())
            items.sort(key=lambda r: r.started_at, reverse=True)

            out: list[dict[str, Any]] = []
            for r in items:
                if r.status == "running":
                    continue
                if filt_type and r.run_type != filt_type:
                    continue
                if filt_status and r.status != filt_status:
                    continue
                out.append(_format_run_summary(r, include_artifacts=False))
                if len(out) >= limit:
                    break
            return [TextContent(type="text", text=json.dumps({"runs": out, "count": len(out)}, indent=2))]

        if name == "list_active_runs":
            active = []
            for run_id in sorted(active_runs):
                r = run_results.get(run_id)
                if not r:
                    continue
                active.append(
                    {
                        "run_id": r.run_id,
                        "run_type": r.run_type,
                        "started_at": r.started_at.isoformat(),
                        "command": r.command,
                    }
                )
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "active_runs": active,
                            "count": len(active),
                            "max_concurrent": settings.max_concurrent,
                        },
                        indent=2,
                    ),
                )
            ]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.exception("Error executing tool %s: %s", name, e)
        return [TextContent(type="text", text=f"Error: {e}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    resources: list[Resource] = []
    for run_id, result in run_results.items():
        if result.status == "running":
            continue
        resources.append(
            Resource(
                uri=f"solazy://runs/{run_id}",
                name=f"Run Results: {result.run_type} ({result.status})",
                description=f"Command: {' '.join(result.command)}",
                mimeType="application/json",
            )
        )
    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    if uri.startswith("solazy://runs/"):
        run_id = uri.replace("solazy://runs/", "")
        result = run_results.get(run_id)
        if result:
            return json.dumps(_format_run_summary(result, include_stdout=True, include_stderr=True), indent=2)
    return json.dumps({"error": "Resource not found"})


async def main() -> None:
    logger.info("Starting sol-azy MCP Server (stdio)")
    logger.info("Output directory: %s", settings.output_dir)
    logger.info("Upload directory: %s", settings.upload_dir)
    logger.info("Max concurrent: %s", settings.max_concurrent)
    logger.info("Path policy: %s", "allow-any" if settings.allow_any_path else "restricted")

    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
