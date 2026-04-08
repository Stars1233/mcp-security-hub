#!/usr/bin/env python3
"""Go Fuzzer MCP Server.

A Model Context Protocol server that runs Go native fuzzing (go test -fuzz)
with crash collection and session management.

Tools:
    - go_fuzz_run: Blocking fuzzing for a fixed duration
    - go_fuzz_start: Start continuous fuzzing in the background
    - go_fuzz_status: Get live status of a continuous session
    - go_fuzz_stop: Stop a continuous session and collect results
"""

import asyncio
import json
import logging
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("go-fuzzer-mcp")


# --- Models ---


class CrashInfo(BaseModel):
    file_path: str
    input_hash: str
    input_size: int


class FuzzingStats(BaseModel):
    total_executions: int = 0
    executions_per_second: float = 0.0
    new_interesting: int = 0
    corpus_size: int = 0
    error: str | None = None


class TargetResult(BaseModel):
    target: str
    crashes: list[CrashInfo] = []
    stats: FuzzingStats = FuzzingStats()
    raw_output: str = ""


class FuzzingReport(BaseModel):
    targets_fuzzed: int
    total_crashes: int
    total_executions: int
    duration_seconds: int
    results: list[TargetResult]


class ContinuousSession(BaseModel):
    session_id: str
    workspace: Path
    targets: list[str]
    current_target: str = ""
    round_number: int = 0
    total_executions: int = 0
    round_executions: int = 0
    new_interesting: int = 0
    crashes_found: int = 0
    crash_files: list[dict[str, Any]] = []
    recent_output: list[str] = []
    running: bool = True

    class Config:
        arbitrary_types_allowed = True

    def update_from_line(self, line: str) -> None:
        """Update session metrics from a fuzzer output line."""
        self.recent_output.append(line)
        if len(self.recent_output) > 50:
            self.recent_output = self.recent_output[-50:]

        exec_match = re.search(r"execs:\s*(\d+)\s*\((\d+)/sec\)", line)
        if exec_match:
            self.round_executions = int(exec_match.group(1))

        new_match = re.search(r"new interesting:\s*(\d+)", line)
        if new_match:
            self.new_interesting = max(self.new_interesting, int(new_match.group(1)))

        if "Failing input written to" in line:
            self.crashes_found += 1

    def flush_round(self) -> None:
        """Flush round executions into the cumulative total."""
        self.total_executions += self.round_executions
        self.round_executions = 0


# Active sessions
_sessions: dict[str, ContinuousSession] = {}
_session_tasks: dict[str, asyncio.Task] = {}


# --- Utility ---


def setup_workspace(project_path: Path) -> Path:
    """Copy project to a writable workspace."""
    workspace = Path("/tmp/fuzz-work") / project_path.name
    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(project_path, workspace)
    return workspace


def find_fuzz_targets(project_path: Path) -> list[tuple[str, str]]:
    """Find Fuzz* functions in test files.

    Returns list of (fuzz_name, package_dir).
    """
    targets: list[tuple[str, str]] = []

    for test_file in project_path.rglob("*_test.go"):
        rel = str(test_file.relative_to(project_path))
        if "/vendor/" in rel or "/." in rel:
            continue

        try:
            content = test_file.read_text()
            for match in re.finditer(
                r"func\s+(Fuzz\w+)\s*\(\s*\w+\s+\*testing\.F\s*\)", content
            ):
                pkg_dir = str(test_file.parent.relative_to(project_path))
                if pkg_dir == ".":
                    pkg_dir = "."
                else:
                    pkg_dir = f"./{pkg_dir}"
                targets.append((match.group(1), pkg_dir))
        except (OSError, UnicodeDecodeError):
            continue

    return targets


def parse_fuzzer_output(output: str) -> FuzzingStats:
    """Parse go test -fuzz output for stats."""
    stats = FuzzingStats()

    for line in output.split("\n"):
        exec_match = re.search(r"execs:\s*(\d+)\s*\((\d+)/sec\)", line)
        if exec_match:
            stats.total_executions = max(stats.total_executions, int(exec_match.group(1)))
            stats.executions_per_second = max(stats.executions_per_second, float(exec_match.group(2)))

        new_match = re.search(r"new interesting:\s*(\d+)", line)
        if new_match:
            stats.new_interesting = max(stats.new_interesting, int(new_match.group(1)))

    return stats


def collect_crashes(workspace: Path, target: str, output_dir: Path) -> list[CrashInfo]:
    """Collect crash inputs from testdata/fuzz/{target}/ and copy to output."""
    crashes: list[CrashInfo] = []
    seen: set[str] = set()

    # Go writes crashes to testdata/fuzz/{FuzzName}/
    search_dirs = [
        workspace / "testdata" / "fuzz" / target,
    ]

    # Also check package subdirectories
    for test_file in workspace.rglob("*_test.go"):
        pkg_dir = test_file.parent
        testdata_dir = pkg_dir / "testdata" / "fuzz" / target
        if testdata_dir.is_dir() and testdata_dir not in search_dirs:
            search_dirs.append(testdata_dir)

    for search_dir in search_dirs:
        if not search_dir.is_dir():
            continue
        for crash_file in search_dir.iterdir():
            if not crash_file.is_file():
                continue
            # Skip seed corpus files (typically have meaningful names)
            # Go crash files are named with hex hashes
            if crash_file.name in seen:
                continue
            seen.add(crash_file.name)

            dest_dir = output_dir / target
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / crash_file.name
            shutil.copy2(crash_file, dest)

            crash_data = crash_file.read_bytes()
            crashes.append(CrashInfo(
                file_path=str(dest),
                input_hash=crash_file.name,
                input_size=len(crash_data),
            ))

    return crashes


async def fuzz_target(
    project_path: Path, target: str, pkg_dir: str, duration: int,
    crashes_dir: Path, parallel: int = 1,
) -> TargetResult:
    """Fuzz a single target for the given duration."""
    logger.info(f"Fuzzing target: {target} for {duration}s")

    cmd = [
        "go", "test",
        f"-run=^{target}$",
        f"-fuzz=^{target}$",
        f"-fuzztime={duration}s",
        f"-parallel={parallel}",
        "-v",
        pkg_dir,
    ]

    env = os.environ.copy()
    env["GOTRACEBACK"] = "all"

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(project_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )

        stdout_bytes, _ = await asyncio.wait_for(
            proc.communicate(),
            timeout=float(duration + 120),
        )
        output = stdout_bytes.decode(errors="replace") if stdout_bytes else ""

        stats = parse_fuzzer_output(output)
        crashes = collect_crashes(project_path, target, crashes_dir)

        logger.info(f"Target {target}: {stats.total_executions} execs, {len(crashes)} crashes")
        return TargetResult(target=target, crashes=crashes, stats=stats, raw_output=output)

    except asyncio.TimeoutError:
        logger.warning(f"Fuzzer timeout for target {target}")
        crashes = collect_crashes(project_path, target, crashes_dir)
        stats = FuzzingStats(error="timeout")
        return TargetResult(target=target, crashes=crashes, stats=stats)

    except FileNotFoundError:
        stats = FuzzingStats(error="Go toolchain not found")
        return TargetResult(target=target, stats=stats)

    except Exception as e:
        logger.exception(f"Fuzzing error for {target}: {e}")
        stats = FuzzingStats(error=str(e))
        return TargetResult(target=target, stats=stats)


async def run_fuzzing(
    project_path_str: str,
    duration: int = 60,
    targets: list[str] | None = None,
    parallel: int = 1,
) -> dict[str, Any]:
    """Run go test -fuzz on project targets."""
    project_path = Path(project_path_str)

    if not (project_path / "go.mod").exists():
        return {"error": f"No go.mod found at {project_path}"}

    workspace = setup_workspace(project_path)

    available_targets = find_fuzz_targets(workspace)
    if not available_targets:
        return {"error": "No Fuzz* targets found in test files"}

    if targets:
        selected = [(n, p) for n, p in available_targets if n in targets]
        if not selected:
            all_names = [n for n, _ in available_targets]
            return {"error": f"None of the requested targets found. Available: {all_names}"}
        available_targets = selected

    duration_per_target = duration // max(len(available_targets), 1)
    crashes_dir = Path("/app/output/crashes") if Path("/app/output").exists() else Path("/tmp/fuzz-crashes")
    crashes_dir.mkdir(parents=True, exist_ok=True)

    results: list[TargetResult] = []
    for fuzz_name, pkg_dir in available_targets:
        result = await fuzz_target(workspace, fuzz_name, pkg_dir, duration_per_target, crashes_dir, parallel)
        results.append(result)

    total_crashes = sum(len(r.crashes) for r in results)
    total_execs = sum(r.stats.total_executions for r in results)

    report = FuzzingReport(
        targets_fuzzed=len(results),
        total_crashes=total_crashes,
        total_executions=total_execs,
        duration_seconds=duration,
        results=results,
    )

    return report.model_dump()


# --- Continuous Fuzzing Logic ---


async def _fuzz_target_continuous(
    session: ContinuousSession, target: str, pkg_dir: str,
    duration_per_round: int,
) -> None:
    """Fuzz a single target for one round, updating session metrics live."""
    session.current_target = target

    cmd = [
        "go", "test",
        f"-run=^{target}$",
        f"-fuzz=^{target}$",
        f"-fuzztime={duration_per_round}s",
        "-v",
        pkg_dir,
    ]

    env = os.environ.copy()
    env["GOTRACEBACK"] = "all"

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(session.workspace),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )

    while True:
        line_bytes = await proc.stdout.readline()
        if not line_bytes:
            break
        line = line_bytes.decode(errors="replace").rstrip()
        if line:
            session.update_from_line(line)

    await proc.wait()

    # Collect crashes produced this round
    crashes_dir = Path("/app/output/crashes") if Path("/app/output").exists() else Path("/tmp/fuzz-crashes")
    crashes_dir.mkdir(parents=True, exist_ok=True)
    new_crashes = collect_crashes(session.workspace, target, crashes_dir)
    for crash in new_crashes:
        crash_dict = crash.model_dump()
        if not any(c["input_hash"] == crash_dict["input_hash"] for c in session.crash_files):
            session.crash_files.append(crash_dict)

    session.flush_round()


async def _continuous_loop(session: ContinuousSession) -> None:
    """Run fuzzing targets in rounds until cancelled."""
    duration_per_target = 60

    # Build target → pkg_dir mapping
    target_pkgs = find_fuzz_targets(session.workspace)
    target_map = {n: p for n, p in target_pkgs}

    while session.running:
        session.round_number += 1
        for target in session.targets:
            if not session.running:
                break
            pkg_dir = target_map.get(target, ".")
            try:
                await _fuzz_target_continuous(session, target, pkg_dir, duration_per_target)
            except asyncio.CancelledError:
                session.running = False
                return
            except Exception as e:
                logger.warning(f"Round {session.round_number}, target {target} error: {e}")


async def start_continuous(
    project_path_str: str,
    targets: list[str] | None = None,
    parallel: int = 1,
) -> dict[str, Any]:
    """Start continuous fuzzing in background."""
    project_path = Path(project_path_str)

    if not (project_path / "go.mod").exists():
        return {"error": f"No go.mod found at {project_path}"}

    workspace = setup_workspace(project_path)
    available_targets = find_fuzz_targets(workspace)
    if not available_targets:
        return {"error": "No Fuzz* targets found"}

    target_names = [n for n, _ in available_targets]
    if targets:
        selected = [t for t in targets if t in target_names]
        if not selected:
            return {"error": f"Targets not found. Available: {target_names}"}
        target_names = selected

    session_id = str(uuid.uuid4())[:8]
    session = ContinuousSession(
        session_id=session_id,
        workspace=workspace,
        targets=target_names,
    )

    _sessions[session_id] = session
    task = asyncio.create_task(_continuous_loop(session))
    _session_tasks[session_id] = task

    return {
        "session_id": session_id,
        "targets": target_names,
        "status": "started",
        "message": f"Continuous fuzzing started for {len(target_names)} target(s). "
                   f"Use go_fuzz_status to monitor.",
    }


async def get_status(session_id: str) -> dict[str, Any]:
    """Get status of a continuous fuzzing session."""
    session = _sessions.get(session_id)
    if not session:
        return {"error": f"Session {session_id} not found"}

    return {
        "session_id": session_id,
        "running": session.running,
        "current_target": session.current_target,
        "round": session.round_number,
        "total_executions": session.total_executions + session.round_executions,
        "new_interesting": session.new_interesting,
        "crashes_found": session.crashes_found,
        "crash_files": len(session.crash_files),
        "recent_output": session.recent_output[-10:],
    }


async def stop_session(session_id: str) -> dict[str, Any]:
    """Stop a continuous fuzzing session."""
    session = _sessions.get(session_id)
    if not session:
        return {"error": f"Session {session_id} not found"}

    session.running = False
    task = _session_tasks.get(session_id)
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    session.flush_round()

    result = {
        "session_id": session_id,
        "status": "stopped",
        "rounds_completed": session.round_number,
        "total_executions": session.total_executions,
        "new_interesting": session.new_interesting,
        "crashes_found": session.crashes_found,
        "crash_files": session.crash_files,
    }

    _sessions.pop(session_id, None)
    _session_tasks.pop(session_id, None)

    return result


# --- MCP Server ---


app = Server("go-fuzzer-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="go_fuzz_run",
            description=(
                "Run Go native fuzzing (go test -fuzz) on fuzz targets for a fixed duration. "
                "Collects crash inputs and execution statistics. "
                "The project must have *_test.go files with Fuzz* functions. "
                "Returns crash file paths and fuzzing metrics for each target. "
                "This is a BLOCKING call — use go_fuzz_start for continuous mode."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the Go project directory containing go.mod",
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Total fuzzing duration in seconds (split across targets)",
                        "default": 60,
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: specific FuzzXxx names to fuzz (default: all)",
                    },
                    "parallel": {
                        "type": "integer",
                        "description": "Number of parallel fuzzing goroutines",
                        "default": 1,
                    },
                },
                "required": ["project_path"],
            },
        ),
        Tool(
            name="go_fuzz_start",
            description=(
                "Start continuous Go fuzzing in the background. Returns immediately "
                "with a session_id. The fuzzer runs in rounds (60s per target per round) "
                "indefinitely until stopped. Use go_fuzz_status to monitor and "
                "go_fuzz_stop to stop."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the Go project directory containing go.mod",
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: specific FuzzXxx names to fuzz (default: all)",
                    },
                    "parallel": {
                        "type": "integer",
                        "description": "Number of parallel fuzzing goroutines",
                        "default": 1,
                    },
                },
                "required": ["project_path"],
            },
        ),
        Tool(
            name="go_fuzz_status",
            description=(
                "Get live status and metrics from a running continuous fuzzing session. "
                "Returns current target, round number, execution count, new interesting "
                "inputs, crashes found, and recent output lines."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID returned by go_fuzz_start",
                    },
                },
                "required": ["session_id"],
            },
        ),
        Tool(
            name="go_fuzz_stop",
            description=(
                "Stop a running continuous fuzzing session and collect final results. "
                "Returns final metrics summary including total executions, crashes found, "
                "and crash file paths."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the session to stop",
                    },
                },
                "required": ["session_id"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "go_fuzz_run":
            result = await run_fuzzing(
                project_path_str=arguments["project_path"],
                duration=arguments.get("duration", 60),
                targets=arguments.get("targets"),
                parallel=arguments.get("parallel", 1),
            )
        elif name == "go_fuzz_start":
            result = await start_continuous(
                project_path_str=arguments["project_path"],
                targets=arguments.get("targets"),
                parallel=arguments.get("parallel", 1),
            )
        elif name == "go_fuzz_status":
            result = await get_status(arguments["session_id"])
        elif name == "go_fuzz_stop":
            result = await stop_session(arguments["session_id"])
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    except Exception as e:
        logger.exception(f"Error in {name}: {e}")
        return [TextContent(type="text", text=f"Error: {e!s}")]


async def main():
    logger.info("Starting Go Fuzzer MCP Server")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
