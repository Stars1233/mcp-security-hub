#!/usr/bin/env python3
"""Go Analyzer MCP Server.

A Model Context Protocol server that analyzes Go source code to identify
fuzzable entry points, existing fuzz targets, unsafe usage, and known CVEs
via govulncheck.

Tools:
    - go_analyze: Full static analysis of a Go project
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("go-analyzer-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    default_timeout: int = Field(default=300, alias="GO_ANALYZER_TIMEOUT")

    class Config:
        env_prefix = "GO_ANALYZER_"


settings = Settings()


# --- Models ---


class EntryPoint(BaseModel):
    """A fuzzable entry point in the Go codebase."""

    function: str
    file: str
    line: int
    signature: str
    fuzzable: bool = True


class ExistingFuzzTarget(BaseModel):
    """An existing Fuzz* function found in test files."""

    function: str
    file: str
    line: int


class UnsafeUsage(BaseModel):
    """Unsafe usage detected in the codebase."""

    file: str
    line: int
    usage_type: str  # "unsafe", "cgo", "reflect-unsafe"
    context: str


class Vulnerability(BaseModel):
    """A known vulnerability from govulncheck."""

    vuln_id: str
    module: str
    version: str
    title: str
    severity: str


class AnalysisResult(BaseModel):
    """The complete analysis result."""

    module_name: str
    go_version: str
    entry_points: list[EntryPoint] = []
    existing_fuzz_targets: list[ExistingFuzzTarget] = []
    unsafe_usage: list[UnsafeUsage] = []
    vulnerabilities: list[Vulnerability] = []
    summary: dict[str, int] = {}


# --- Analysis Logic ---


def parse_go_mod(go_mod_path: Path) -> tuple[str, str]:
    """Parse go.mod to extract module name and Go version."""
    content = go_mod_path.read_text()

    module_match = re.search(r"^module\s+(\S+)", content, re.MULTILINE)
    module_name = module_match.group(1) if module_match else "unknown"

    version_match = re.search(r"^go\s+(\S+)", content, re.MULTILINE)
    go_version = version_match.group(1) if version_match else "unknown"

    return module_name, go_version


def find_entry_points(project_path: Path) -> list[EntryPoint]:
    """Find fuzzable entry points in Go source (non-test files)."""
    entry_points: list[EntryPoint] = []
    seen: set[str] = set()

    # Patterns for functions accepting fuzzable input types
    fuzzable_param_patterns = [
        r"func\s+(\w+)\s*\([^)]*\[\]byte[^)]*\)",
        r"func\s+(\w+)\s*\([^)]*\[\]uint8[^)]*\)",
        r"func\s+(\w+)\s*\([^)]*string[^)]*\)",
        r"func\s+(\w+)\s*\([^)]*io\.Reader[^)]*\)",
        r"func\s+(\w+)\s*\([^)]*io\.ReaderAt[^)]*\)",
        r"func\s+(\w+)\s*\([^)]*io\.ReadSeeker[^)]*\)",
    ]

    # Parser/decoder function name patterns
    parser_patterns = [
        r"func\s+(Parse\w*)\s*\([^)]*\)",
        r"func\s+(Decode\w*)\s*\([^)]*\)",
        r"func\s+(Unmarshal\w*)\s*\([^)]*\)",
        r"func\s+(FromBytes\w*)\s*\([^)]*\)",
        r"func\s+(Read\w*)\s*\([^)]*\)",
        r"func\s+(Deserialize\w*)\s*\([^)]*\)",
        r"func\s+(Load\w*)\s*\([^)]*\)",
    ]

    for go_file in project_path.rglob("*.go"):
        # Skip test files, vendor, and hidden directories
        rel = str(go_file.relative_to(project_path))
        if "_test.go" in rel or "/vendor/" in rel or "/." in rel:
            continue

        try:
            content = go_file.read_text()
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                for pattern in fuzzable_param_patterns:
                    match = re.search(pattern, line)
                    if match:
                        func_name = match.group(1)
                        key = f"{rel}:{func_name}"
                        if key not in seen:
                            seen.add(key)
                            entry_points.append(
                                EntryPoint(
                                    function=func_name,
                                    file=rel,
                                    line=line_num,
                                    signature=line.strip(),
                                    fuzzable=True,
                                )
                            )

                for pattern in parser_patterns:
                    match = re.search(pattern, line)
                    if match:
                        func_name = match.group(1)
                        key = f"{rel}:{func_name}"
                        if key not in seen:
                            seen.add(key)
                            entry_points.append(
                                EntryPoint(
                                    function=func_name,
                                    file=rel,
                                    line=line_num,
                                    signature=line.strip(),
                                    fuzzable=True,
                                )
                            )
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to read {go_file}: {e}")

    return entry_points


def find_existing_fuzz_targets(project_path: Path) -> list[ExistingFuzzTarget]:
    """Find existing Fuzz* functions in test files."""
    targets: list[ExistingFuzzTarget] = []

    for test_file in project_path.rglob("*_test.go"):
        rel = str(test_file.relative_to(project_path))
        if "/vendor/" in rel or "/." in rel:
            continue

        try:
            content = test_file.read_text()
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                match = re.search(
                    r"func\s+(Fuzz\w+)\s*\(\s*\w+\s+\*testing\.F\s*\)", line
                )
                if match:
                    targets.append(
                        ExistingFuzzTarget(
                            function=match.group(1),
                            file=rel,
                            line=line_num,
                        )
                    )
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to read {test_file}: {e}")

    return targets


def find_unsafe_usage(project_path: Path) -> list[UnsafeUsage]:
    """Detect unsafe, cgo, and reflection-based unsafe usage."""
    usages: list[UnsafeUsage] = []

    for go_file in project_path.rglob("*.go"):
        rel = str(go_file.relative_to(project_path))
        if "/vendor/" in rel or "/." in rel:
            continue

        try:
            content = go_file.read_text()
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()

                # import "unsafe"
                if re.search(r'"unsafe"', stripped):
                    usages.append(
                        UnsafeUsage(
                            file=rel,
                            line=line_num,
                            usage_type="unsafe",
                            context=stripped,
                        )
                    )
                # import "C" (cgo)
                elif re.search(r'"C"', stripped) and "import" in stripped:
                    usages.append(
                        UnsafeUsage(
                            file=rel,
                            line=line_num,
                            usage_type="cgo",
                            context=stripped,
                        )
                    )
                # unsafe.Pointer usage
                elif "unsafe.Pointer" in stripped:
                    usages.append(
                        UnsafeUsage(
                            file=rel,
                            line=line_num,
                            usage_type="unsafe-pointer",
                            context=stripped,
                        )
                    )
                # reflect.SliceHeader / reflect.StringHeader
                elif re.search(r"reflect\.(SliceHeader|StringHeader)", stripped):
                    usages.append(
                        UnsafeUsage(
                            file=rel,
                            line=line_num,
                            usage_type="reflect-unsafe",
                            context=stripped,
                        )
                    )
                # //go:nosplit, //go:noescape directives
                elif re.search(r"//go:(nosplit|noescape|linkname)", stripped):
                    usages.append(
                        UnsafeUsage(
                            file=rel,
                            line=line_num,
                            usage_type="compiler-directive",
                            context=stripped,
                        )
                    )
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to read {go_file}: {e}")

    return usages


async def run_govulncheck(project_path: Path, timeout: int = 120) -> list[Vulnerability]:
    """Run govulncheck to find known vulnerabilities."""
    vulnerabilities: list[Vulnerability] = []

    try:
        process = await asyncio.create_subprocess_exec(
            "govulncheck", "-json", "./...",
            cwd=str(project_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout),
        )

        if stdout:
            # govulncheck JSON output is newline-delimited JSON objects
            for line in stdout.decode(errors="replace").strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Look for vulnerability findings
                if "finding" in entry and entry["finding"]:
                    finding = entry["finding"]
                    osv = finding.get("osv", "")
                    trace = finding.get("trace", [])

                    module_name = ""
                    version = ""
                    if trace:
                        module_name = trace[0].get("module", "")
                        version = trace[0].get("version", "")

                    if osv and osv not in {v.vuln_id for v in vulnerabilities}:
                        vulnerabilities.append(
                            Vulnerability(
                                vuln_id=osv,
                                module=module_name,
                                version=version,
                                title=osv,  # govulncheck doesn't always include title inline
                                severity="unknown",
                            )
                        )
    except asyncio.TimeoutError:
        logger.warning("govulncheck timed out")
    except FileNotFoundError:
        logger.warning("govulncheck not installed")
    except Exception as e:
        logger.warning(f"govulncheck failed: {e}")

    return vulnerabilities


async def analyze_project(
    project_path_str: str,
    run_vulncheck: bool = True,
    timeout: int = 300,
) -> dict[str, Any]:
    """Analyze a Go project for fuzzable targets and vulnerabilities."""
    project_path = Path(project_path_str)

    # Find go.mod
    if project_path.name == "go.mod":
        go_mod_path = project_path
        project_path = go_mod_path.parent
    else:
        go_mod_path = project_path / "go.mod"

    if not go_mod_path.exists():
        return {"error": f"go.mod not found at {go_mod_path}"}

    # Parse go.mod
    module_name, go_version = parse_go_mod(go_mod_path)

    # Find entry points
    entry_points = find_entry_points(project_path)

    # Find existing fuzz targets
    fuzz_targets = find_existing_fuzz_targets(project_path)

    # Detect unsafe usage
    unsafe_usage = find_unsafe_usage(project_path)

    # Run govulncheck
    vulnerabilities: list[Vulnerability] = []
    if run_vulncheck:
        vulnerabilities = await run_govulncheck(project_path, timeout)

    result = AnalysisResult(
        module_name=module_name,
        go_version=go_version,
        entry_points=entry_points,
        existing_fuzz_targets=fuzz_targets,
        unsafe_usage=unsafe_usage,
        vulnerabilities=vulnerabilities,
        summary={
            "entry_points": len(entry_points),
            "existing_fuzz_targets": len(fuzz_targets),
            "unsafe_usage": len(unsafe_usage),
            "vulnerabilities": len(vulnerabilities),
        },
    )

    return result.model_dump()


# --- MCP Server ---


app = Server("go-analyzer-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="go_analyze",
            description=(
                "Analyze a Go project to identify fuzzable entry points, existing "
                "fuzz targets (Fuzz* functions), unsafe/cgo usage, and known CVEs "
                "via govulncheck. Returns structured analysis with function signatures, "
                "file locations, and vulnerability details. "
                "Use this as the first step in a Go fuzzing pipeline."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the Go project directory containing go.mod",
                    },
                    "run_vulncheck": {
                        "type": "boolean",
                        "description": "Run govulncheck for CVE detection",
                        "default": True,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Analysis timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["project_path"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "go_analyze":
            result = await analyze_project(
                project_path_str=arguments["project_path"],
                run_vulncheck=arguments.get("run_vulncheck", True),
                timeout=arguments.get("timeout", settings.default_timeout),
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.exception(f"Error in {name}: {e}")
        return [TextContent(type="text", text=f"Error: {e!s}")]


async def main():
    logger.info("Starting Go Analyzer MCP Server")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
