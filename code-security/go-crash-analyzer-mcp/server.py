#!/usr/bin/env python3
"""Go Crash Analyzer MCP Server.

A Model Context Protocol server that reproduces, classifies, and deduplicates
crash inputs from Go fuzzing campaigns.

Tool:
    - go_crash_analyze: Analyze Go fuzzing crashes from a project
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
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
logger = logging.getLogger("go-crash-analyzer-mcp")


# --- Models ---


class StackFrame(BaseModel):
    function: str
    file: str
    line: int


class CrashClassification(BaseModel):
    crash_type: str
    severity: str
    description: str


class CrashReport(BaseModel):
    crash_file: str
    target: str
    input_size: int
    reproducible: bool
    classification: CrashClassification
    stack_trace: list[StackFrame] = []
    raw_output: str = ""
    signature: str = ""


class AnalysisReport(BaseModel):
    project_path: str
    crashes_analyzed: int
    unique_crashes: int
    unreproducible: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    crashes: list[CrashReport]


# --- Classification ---

CRASH_PATTERNS: list[tuple[str, str, str, str]] = [
    # (regex, crash_type, severity, description)
    (r"runtime error: index out of range", "index-out-of-range", "high",
     "Array/slice index out of bounds"),
    (r"runtime error: slice bounds out of range", "slice-bounds-out-of-range", "high",
     "Slice bounds exceed capacity"),
    (r"runtime error: invalid memory address or nil pointer dereference",
     "nil-dereference", "critical", "Nil pointer dereference"),
    (r"runtime error: integer divide by zero", "divide-by-zero", "medium",
     "Division by zero"),
    (r"runtime error: integer overflow", "integer-overflow", "medium",
     "Integer overflow in arithmetic operation"),
    (r"runtime error: makeslice: len out of range", "allocation-overflow", "high",
     "Slice allocation with invalid length"),
    (r"runtime error: makemap: negative key count", "allocation-overflow", "high",
     "Map allocation with invalid key count"),
    (r"fatal error: stack overflow", "stack-overflow", "critical",
     "Stack overflow — unbounded recursion or very deep call chain"),
    (r"fatal error: out of memory", "out-of-memory", "critical",
     "Out of memory allocation"),
    (r"fatal error: concurrent map (read and map write|writes)", "data-race", "critical",
     "Concurrent map access without synchronization"),
    (r"DATA RACE", "data-race", "critical",
     "Data race detected by race detector"),
    (r"panic:.*runtime error", "runtime-panic", "high",
     "Runtime panic"),
    (r"panic:", "panic", "medium",
     "Explicit panic in application code"),
    (r"signal: segmentation fault", "segfault", "critical",
     "Segmentation fault — likely from cgo or unsafe code"),
    (r"signal: bus error", "bus-error", "critical",
     "Bus error — misaligned memory access"),
    (r"SIGABRT", "abort", "critical",
     "Process aborted"),
    (r"deadlock", "deadlock", "critical",
     "Goroutine deadlock detected"),
    (r"timeout", "timeout", "low",
     "Execution timed out"),
]


def classify_crash(output: str) -> CrashClassification:
    """Classify a crash based on output patterns."""
    for pattern, crash_type, severity, description in CRASH_PATTERNS:
        if re.search(pattern, output, re.IGNORECASE):
            return CrashClassification(
                crash_type=crash_type,
                severity=severity,
                description=description,
            )
    return CrashClassification(
        crash_type="unknown",
        severity="medium",
        description="Unclassified crash",
    )


def parse_stack_trace(output: str) -> list[StackFrame]:
    """Parse Go stack trace from crash output."""
    frames: list[StackFrame] = []

    # Go stack traces look like:
    #   goroutine N [running]:
    #   package.Function(args)
    #       /path/to/file.go:123 +0x1a2
    func_pattern = re.compile(r"^(\S+)\(.*\)\s*$")
    file_pattern = re.compile(r"^\s+(.+\.go):(\d+)")

    lines = output.split("\n")
    i = 0
    while i < len(lines):
        func_match = func_pattern.match(lines[i])
        if func_match and i + 1 < len(lines):
            file_match = file_pattern.match(lines[i + 1])
            if file_match:
                frames.append(StackFrame(
                    function=func_match.group(1),
                    file=file_match.group(1),
                    line=int(file_match.group(2)),
                ))
                i += 2
                continue
        i += 1

    return frames


def compute_signature(target: str, classification: CrashClassification, stack: list[StackFrame]) -> str:
    """Compute a deduplication signature from target + crash type + top stack frames."""
    parts = [target, classification.crash_type]
    for frame in stack[:3]:
        parts.append(f"{frame.function}@{frame.file}:{frame.line}")

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# --- Analysis ---


def setup_workspace(project_path: Path) -> Path:
    """Copy project to a writable workspace."""
    workspace = Path("/tmp/crash-work") / project_path.name
    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(project_path, workspace)
    return workspace


async def reproduce_crash(
    project_path: Path,
    target: str,
    crash_file: Path,
    timeout: int = 10,
) -> tuple[bool, str]:
    """Reproduce a crash by feeding the input back into the fuzz target."""
    # Try to find which package the target is in
    pkg_dir = "."
    for test_file in project_path.rglob("*_test.go"):
        try:
            content = test_file.read_text()
            if f"func {target}(" in content:
                rel = test_file.parent.relative_to(project_path)
                pkg_dir = f"./{rel}" if str(rel) != "." else "."
                break
        except (OSError, UnicodeDecodeError):
            continue

    # Go's approach: put the crash file in testdata/fuzz/{Target}/ then run the seed corpus
    # Or use -run=FuzzXxx/{filename}
    crash_name = crash_file.name

    # Copy crash file to testdata so go test can find it
    testdata_dir = project_path / "testdata" / "fuzz" / target
    testdata_dir.mkdir(parents=True, exist_ok=True)
    dest = testdata_dir / crash_name
    if not dest.exists():
        shutil.copy2(crash_file, dest)

    cmd = [
        "go", "test",
        f"-run=^{target}$",
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
            proc.communicate(), timeout=float(timeout)
        )
        output = stdout_bytes.decode(errors="replace") if stdout_bytes else ""

        # Non-zero exit with error output = crash reproduced
        reproduced = proc.returncode != 0 and (
            "panic" in output.lower()
            or "FAIL" in output
            or "runtime error" in output
            or "signal:" in output
        )

        return reproduced, output

    except asyncio.TimeoutError:
        return True, "timeout: crash reproduction exceeded time limit"
    except Exception as e:
        return False, f"reproduction error: {e!s}"


def discover_crashes(crashes_path: Path, project_path: Path) -> list[tuple[str, Path]]:
    """Discover crash files, returning (target, crash_file) pairs."""
    results: list[tuple[str, Path]] = []

    if crashes_path.is_file():
        # Single file — try to infer target from parent dir name
        target = crashes_path.parent.name
        results.append((target, crashes_path))
        return results

    if crashes_path.is_dir():
        # Check for subdirectories named after fuzz targets
        has_subdirs = any(d.is_dir() for d in crashes_path.iterdir())

        if has_subdirs:
            for subdir in crashes_path.iterdir():
                if subdir.is_dir():
                    target = subdir.name
                    for f in subdir.iterdir():
                        if f.is_file():
                            results.append((target, f))
        else:
            # Flat directory — try to infer target from filenames or dir name
            target = crashes_path.name
            for f in crashes_path.iterdir():
                if f.is_file():
                    results.append((target, f))

    # Also check testdata/fuzz/ in the project
    testdata_fuzz = project_path / "testdata" / "fuzz"
    if testdata_fuzz.is_dir():
        for target_dir in testdata_fuzz.iterdir():
            if target_dir.is_dir():
                for f in target_dir.iterdir():
                    if f.is_file():
                        pair = (target_dir.name, f)
                        if pair not in results:
                            results.append(pair)

    return results


async def analyze_crashes(
    project_path_str: str,
    crashes_path_str: str | None = None,
    reproduce: bool = True,
    reproduce_timeout: int = 10,
    max_crashes: int = 50,
) -> dict[str, Any]:
    """Analyze Go fuzzing crashes."""
    project_path = Path(project_path_str)

    if not (project_path / "go.mod").exists():
        return {"error": f"No go.mod found at {project_path}"}

    # Use writable workspace for reproduction
    workspace = setup_workspace(project_path)

    # Determine crashes path
    if crashes_path_str:
        crashes_path = Path(crashes_path_str)
    elif Path("/app/output/crashes").exists():
        crashes_path = Path("/app/output/crashes")
    else:
        crashes_path = project_path / "testdata" / "fuzz"

    if not crashes_path.exists():
        return {"error": f"Crashes path does not exist: {crashes_path}"}

    crash_pairs = discover_crashes(crashes_path, workspace)
    if not crash_pairs:
        return {"error": f"No crash files found in {crashes_path}"}

    # Respect max_crashes limit
    crash_pairs = crash_pairs[:max_crashes]
    logger.info(f"Analyzing {len(crash_pairs)} crash(es)")

    reports: list[CrashReport] = []
    signatures_seen: set[str] = set()
    unreproducible = 0

    for target, crash_file in crash_pairs:
        try:
            input_data = crash_file.read_bytes()
        except OSError:
            continue

        if reproduce:
            reproduced, output = await reproduce_crash(
                workspace, target, crash_file, reproduce_timeout
            )
        else:
            reproduced = False
            output = ""

        classification = classify_crash(output) if output else CrashClassification(
            crash_type="unknown", severity="medium", description="Not reproduced"
        )

        stack = parse_stack_trace(output) if output else []
        signature = compute_signature(target, classification, stack)

        if not reproduced and reproduce:
            unreproducible += 1

        report = CrashReport(
            crash_file=str(crash_file),
            target=target,
            input_size=len(input_data),
            reproducible=reproduced,
            classification=classification,
            stack_trace=stack,
            raw_output=output[-2000:] if len(output) > 2000 else output,
            signature=signature,
        )
        reports.append(report)
        signatures_seen.add(signature)

    # Aggregate
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in reports:
        by_type[r.classification.crash_type] = by_type.get(r.classification.crash_type, 0) + 1
        by_severity[r.classification.severity] = by_severity.get(r.classification.severity, 0) + 1

    analysis = AnalysisReport(
        project_path=project_path_str,
        crashes_analyzed=len(reports),
        unique_crashes=len(signatures_seen),
        unreproducible=unreproducible,
        by_type=by_type,
        by_severity=by_severity,
        crashes=reports,
    )

    return analysis.model_dump()


# --- MCP Server ---


app = Server("go-crash-analyzer-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="go_crash_analyze",
            description=(
                "Analyze Go fuzzing crash inputs: reproduce, classify, and deduplicate. "
                "Supports crash files from go_fuzz_run output (/app/output/crashes/) "
                "or testdata/fuzz/ directories. Classifies by type (nil-dereference, "
                "index-out-of-range, panic, data-race, etc.) and severity. "
                "Deduplicates using target + crash type + top stack frames."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the Go project directory containing go.mod",
                    },
                    "crashes_path": {
                        "type": "string",
                        "description": (
                            "Path to crash files. Can be a directory containing "
                            "subdirectories named by fuzz target, or a flat directory, "
                            "or a single file. Default: /app/output/crashes/ or testdata/fuzz/"
                        ),
                    },
                    "reproduce": {
                        "type": "boolean",
                        "description": "Whether to attempt crash reproduction (default: true)",
                        "default": True,
                    },
                    "reproduce_timeout": {
                        "type": "integer",
                        "description": "Timeout per crash reproduction in seconds (default: 10)",
                        "default": 10,
                    },
                    "max_crashes": {
                        "type": "integer",
                        "description": "Maximum number of crashes to analyze (default: 50)",
                        "default": 50,
                    },
                },
                "required": ["project_path"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "go_crash_analyze":
            result = await analyze_crashes(
                project_path_str=arguments["project_path"],
                crashes_path_str=arguments.get("crashes_path"),
                reproduce=arguments.get("reproduce", True),
                reproduce_timeout=arguments.get("reproduce_timeout", 10),
                max_crashes=arguments.get("max_crashes", 50),
            )
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    except Exception as e:
        logger.exception(f"Error in {name}: {e}")
        return [TextContent(type="text", text=f"Error: {e!s}")]


async def main():
    logger.info("Starting Go Crash Analyzer MCP Server")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
