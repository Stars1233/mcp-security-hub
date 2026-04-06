#!/usr/bin/env python3
"""Go Harness Tester MCP Server.

A Model Context Protocol server that tests Go fuzz harness quality by
compiling, executing with seed inputs, and running short fuzzing trials.
Returns detailed quality assessments with scores 0-100.

Tools:
    - go_harness_test: Test fuzz harness quality
"""

import asyncio
import json
import logging
import re
import shutil
import time
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
logger = logging.getLogger("go-harness-tester-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    default_trial_duration: int = Field(default=30, alias="HARNESS_TRIAL_DURATION")

    class Config:
        env_prefix = "GO_HARNESS_"


settings = Settings()


# --- Models ---


class CompilationResult(BaseModel):
    success: bool
    time_ms: int = 0
    errors: list[str] = []
    warnings: list[str] = []
    stderr: str | None = None


class ExecutionResult(BaseModel):
    success: bool
    runs_completed: int | None = None
    immediate_crash: bool = False
    timeout: bool = False
    crash_details: str | None = None


class CoverageInfo(BaseModel):
    new_interesting: int = 0
    growth_rate: str = "unknown"


class PerformanceInfo(BaseModel):
    total_execs: int = 0
    execs_per_sec: float = 0.0
    performance_rating: str = "unknown"


class StabilityInfo(BaseModel):
    status: str = "unknown"
    crashes_found: int = 0
    crash_rate: float = 0.0


class FuzzingTrialResult(BaseModel):
    duration_seconds: int = 0
    coverage: CoverageInfo = CoverageInfo()
    performance: PerformanceInfo = PerformanceInfo()
    stability: StabilityInfo = StabilityInfo()
    trial_successful: bool = False


class Issue(BaseModel):
    category: str
    severity: str
    issue_type: str
    message: str
    suggestion: str


class QualityAssessment(BaseModel):
    score: int = 0
    verdict: str = "unknown"
    issues: list[Issue] = []
    strengths: list[str] = []
    recommended_actions: list[str] = []


class HarnessEvaluation(BaseModel):
    name: str
    file: str
    compilation: CompilationResult
    execution: ExecutionResult | None = None
    fuzzing_trial: FuzzingTrialResult | None = None
    quality: QualityAssessment = QualityAssessment()


class HarnessTestReport(BaseModel):
    harnesses: list[HarnessEvaluation] = []
    summary: dict[str, Any] = {}
    test_configuration: dict[str, int] = {}


# --- Logic ---


def setup_workspace(project_path: Path) -> Path:
    """Copy project to a writable workspace."""
    workspace = Path("/tmp/harness-workspace")
    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(project_path, workspace)
    return workspace


def find_fuzz_targets(project_path: Path) -> list[tuple[str, str, str]]:
    """Find all Fuzz* functions in test files.

    Returns list of (function_name, file_path, package_dir).
    """
    targets: list[tuple[str, str, str]] = []

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
                    pkg_dir = "./..."
                else:
                    pkg_dir = f"./{pkg_dir}/..."
                targets.append((match.group(1), rel, pkg_dir))
        except (OSError, UnicodeDecodeError):
            continue

    return targets


async def test_compilation(workspace: Path) -> CompilationResult:
    """Test if the project compiles."""
    start = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            "go", "test", "-c", "-o", "/dev/null", "./...",
            cwd=str(workspace),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        stderr_text = stderr_bytes.decode(errors="replace") if stderr_bytes else ""

        if proc.returncode == 0:
            return CompilationResult(success=True, time_ms=elapsed_ms)

        errors = [
            line for line in stderr_text.split("\n")
            if line.strip() and ("error" in line.lower() or "cannot" in line.lower())
        ]
        return CompilationResult(
            success=False, time_ms=elapsed_ms, errors=errors, stderr=stderr_text[:2000],
        )

    except asyncio.TimeoutError:
        return CompilationResult(success=False, errors=["Compilation timed out"])
    except FileNotFoundError:
        return CompilationResult(success=False, errors=["Go toolchain not found"])


async def test_execution(
    workspace: Path, fuzz_name: str, pkg_dir: str, timeout: int = 10,
) -> ExecutionResult:
    """Test seed execution: run the fuzz target with seed corpus only."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "go", "test", f"-run=^{fuzz_name}$", "-fuzztime=1x", "-v",
            pkg_dir,
            cwd=str(workspace),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout_bytes, _ = await asyncio.wait_for(
            proc.communicate(), timeout=float(timeout),
        )
        output = stdout_bytes.decode(errors="replace") if stdout_bytes else ""

        if proc.returncode == 0:
            return ExecutionResult(success=True, runs_completed=1)

        # Check for panic/crash
        if "panic" in output.lower() or "FAIL" in output:
            return ExecutionResult(
                success=False, immediate_crash=True,
                crash_details=output[:2000],
            )

        return ExecutionResult(success=False, crash_details=output[:2000])

    except asyncio.TimeoutError:
        return ExecutionResult(success=False, timeout=True)
    except FileNotFoundError:
        return ExecutionResult(success=False, crash_details="Go toolchain not found")


def parse_fuzz_output(output: str) -> tuple[int, float, int, int]:
    """Parse go test -fuzz output.

    Returns (total_execs, execs_per_sec, new_interesting, crashes).
    """
    total_execs = 0
    execs_per_sec = 0.0
    new_interesting = 0
    crashes = 0

    for line in output.split("\n"):
        # fuzz: elapsed: 10s, execs: 50432 (5043/sec), new interesting: 12
        exec_match = re.search(r"execs:\s*(\d+)\s*\((\d+)/sec\)", line)
        if exec_match:
            total_execs = max(total_execs, int(exec_match.group(1)))
            execs_per_sec = max(execs_per_sec, float(exec_match.group(2)))

        new_match = re.search(r"new interesting:\s*(\d+)", line)
        if new_match:
            new_interesting = max(new_interesting, int(new_match.group(1)))

        if "FAIL" in line and "crash" in line.lower():
            crashes += 1

    # Count crash files in output
    crash_matches = re.findall(r"Failing input written to (testdata/fuzz/\S+)", output)
    crashes = max(crashes, len(crash_matches))

    return total_execs, execs_per_sec, new_interesting, crashes


async def run_fuzzing_trial(
    workspace: Path, fuzz_name: str, pkg_dir: str, duration: int,
) -> FuzzingTrialResult:
    """Run a short fuzzing trial."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "go", "test", f"-fuzz=^{fuzz_name}$",
            f"-fuzztime={duration}s", "-v",
            pkg_dir,
            cwd=str(workspace),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout_bytes, _ = await asyncio.wait_for(
            proc.communicate(), timeout=float(duration + 60),
        )
        output = stdout_bytes.decode(errors="replace") if stdout_bytes else ""

        total_execs, execs_per_sec, new_interesting, crashes = parse_fuzz_output(output)

        # Coverage assessment
        if new_interesting > 20:
            growth_rate = "excellent"
        elif new_interesting > 5:
            growth_rate = "good"
        elif new_interesting > 0:
            growth_rate = "low"
        else:
            growth_rate = "none"

        coverage = CoverageInfo(new_interesting=new_interesting, growth_rate=growth_rate)

        # Performance rating
        if execs_per_sec > 5000:
            perf_rating = "excellent"
        elif execs_per_sec > 1000:
            perf_rating = "good"
        elif execs_per_sec > 100:
            perf_rating = "acceptable"
        elif execs_per_sec > 0:
            perf_rating = "poor"
        else:
            perf_rating = "unknown"

        performance = PerformanceInfo(
            total_execs=total_execs,
            execs_per_sec=execs_per_sec,
            performance_rating=perf_rating,
        )

        # Stability
        crash_rate = crashes / max(total_execs, 1) * 100.0
        stability_status = "unstable" if crashes > 0 else "stable"
        stability = StabilityInfo(
            status=stability_status,
            crashes_found=crashes,
            crash_rate=round(crash_rate, 4),
        )

        return FuzzingTrialResult(
            duration_seconds=duration,
            coverage=coverage,
            performance=performance,
            stability=stability,
            trial_successful=True,
        )

    except asyncio.TimeoutError:
        return FuzzingTrialResult(
            duration_seconds=duration,
            stability=StabilityInfo(status="timeout"),
        )
    except Exception as e:
        logger.warning(f"Fuzzing trial failed: {e}")
        return FuzzingTrialResult(duration_seconds=duration)


def compute_quality(
    compilation: CompilationResult,
    execution: ExecutionResult | None,
    trial: FuzzingTrialResult | None,
) -> QualityAssessment:
    """Compute quality score 0-100."""
    score = 0
    issues: list[Issue] = []
    strengths: list[str] = []

    # Compilation: +20
    if compilation.success:
        score += 20
        strengths.append("Compiles successfully")
    else:
        issues.append(Issue(
            category="compilation", severity="critical", issue_type="compile_error",
            message="Project fails to compile",
            suggestion="Fix compilation errors before fuzzing.",
        ))
        return QualityAssessment(
            score=score, verdict="broken", issues=issues,
            strengths=strengths, recommended_actions=["Fix compilation errors"],
        )

    # Seed execution: +15
    if execution and execution.success:
        score += 15
        strengths.append("Executes without crashing on seeds")
    elif execution and execution.immediate_crash:
        issues.append(Issue(
            category="execution", severity="critical", issue_type="panic_on_start",
            message=f"Harness crashes: {(execution.crash_details or '')[:200]}",
            suggestion="Check initialization code and input validation.",
        ))
    elif execution and execution.timeout:
        issues.append(Issue(
            category="execution", severity="warning", issue_type="execution_timeout",
            message="Seed execution timed out",
            suggestion="Check for blocking operations or infinite loops in harness.",
        ))

    # No immediate crashes: +15
    if execution and not execution.immediate_crash and not execution.timeout:
        score += 15
        strengths.append("No immediate crashes")

    # Trial results
    if trial and trial.trial_successful:
        # Coverage: +20
        if trial.coverage.growth_rate == "excellent":
            score += 20
            strengths.append(f"Excellent coverage: {trial.coverage.new_interesting} new interesting inputs")
        elif trial.coverage.growth_rate == "good":
            score += 15
            strengths.append(f"Good coverage: {trial.coverage.new_interesting} new interesting inputs")
        elif trial.coverage.growth_rate == "low":
            score += 8
            issues.append(Issue(
                category="coverage", severity="warning", issue_type="low_coverage",
                message=f"Low coverage growth: only {trial.coverage.new_interesting} new inputs",
                suggestion="Improve input generation or seed corpus.",
            ))

        # Performance: +15
        perf = trial.performance
        if perf.performance_rating in ("excellent", "good"):
            score += 15
            strengths.append(f"Good performance: {perf.execs_per_sec:.0f} exec/s")
        elif perf.performance_rating == "acceptable":
            score += 10
        elif perf.performance_rating == "poor":
            score += 5
            issues.append(Issue(
                category="performance", severity="warning", issue_type="slow",
                message=f"Slow: {perf.execs_per_sec:.0f} execs/sec",
                suggestion="Remove file I/O or expensive computations from harness.",
            ))
        elif perf.execs_per_sec == 0.0 and perf.total_execs > 0:
            score += 5  # Stats parsing issue, not tool's fault
            issues.append(Issue(
                category="performance", severity="critical", issue_type="extremely_slow",
                message=f"Extremely slow: {perf.execs_per_sec} execs/sec",
                suggestion="Remove file I/O, network ops, or expensive computations from harness loop.",
            ))

        # Stability: +15
        if trial.stability.status == "stable":
            score += 15
            strengths.append("Stable execution - no crashes or hangs")
        elif trial.stability.crashes_found > 0:
            score += 5
            strengths.append(f"Found {trial.stability.crashes_found} potential bugs during trial!")

    # Verdict
    if score >= 80:
        verdict = "production-ready"
    elif score >= 50:
        verdict = "needs-improvement"
    else:
        verdict = "broken"

    actions = []
    critical_count = sum(1 for i in issues if i.severity == "critical")
    if critical_count > 0:
        actions.append(f"Fix {critical_count} critical issue(s)")

    return QualityAssessment(
        score=score, verdict=verdict, issues=issues,
        strengths=strengths, recommended_actions=actions,
    )


async def test_harnesses(
    project_path_str: str,
    target_harness: str | None = None,
    trial_duration: int = 30,
    execution_timeout: int = 10,
) -> dict[str, Any]:
    """Test Go fuzz harness quality."""
    project_path = Path(project_path_str)

    if not (project_path / "go.mod").exists():
        return {"error": f"No go.mod found at {project_path}"}

    workspace = setup_workspace(project_path)

    # Find fuzz targets
    targets = find_fuzz_targets(workspace)
    if not targets:
        return {"error": "No Fuzz* functions found in test files"}

    # Filter if specific harness requested
    if target_harness:
        targets = [(n, f, p) for n, f, p in targets if n == target_harness]
        if not targets:
            all_names = [n for n, _, _ in find_fuzz_targets(workspace)]
            return {"error": f"Harness '{target_harness}' not found. Available: {all_names}"}

    # Test compilation first (shared across all harnesses)
    compilation = await test_compilation(workspace)

    evaluations: list[HarnessEvaluation] = []
    for fuzz_name, file_path, pkg_dir in targets:
        logger.info(f"Testing harness: {fuzz_name}")

        execution = None
        trial = None

        if compilation.success:
            execution = await test_execution(workspace, fuzz_name, pkg_dir, execution_timeout)

            if execution.success:
                trial = await run_fuzzing_trial(workspace, fuzz_name, pkg_dir, trial_duration)

        quality = compute_quality(compilation, execution, trial)

        evaluations.append(
            HarnessEvaluation(
                name=fuzz_name,
                file=file_path,
                compilation=compilation,
                execution=execution,
                fuzzing_trial=trial,
                quality=quality,
            )
        )

    # Summary
    scores = [e.quality.score for e in evaluations]
    report = HarnessTestReport(
        harnesses=evaluations,
        summary={
            "total_harnesses": len(evaluations),
            "production_ready": sum(1 for e in evaluations if e.quality.verdict == "production-ready"),
            "needs_improvement": sum(1 for e in evaluations if e.quality.verdict == "needs-improvement"),
            "broken": sum(1 for e in evaluations if e.quality.verdict == "broken"),
            "average_score": round(sum(scores) / max(len(scores), 1), 1),
            "recommended_action": (
                f"Fix {sum(1 for e in evaluations if e.quality.verdict == 'broken')} broken harness(es) before proceeding."
                if any(e.quality.verdict == "broken" for e in evaluations)
                else "All harnesses are ready for fuzzing."
            ),
        },
        test_configuration={
            "trial_duration_sec": trial_duration,
            "execution_timeout_sec": execution_timeout,
        },
    )

    return report.model_dump()


# --- MCP Server ---


app = Server("go-harness-tester-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="go_harness_test",
            description=(
                "Test Go fuzz harnesses by compiling, executing with seed inputs, "
                "and running short fuzzing trials. Returns detailed quality assessments "
                "with actionable feedback including compilation errors, coverage metrics, "
                "performance ratings, and stability analysis. "
                "Requires the project to have *_test.go files with Fuzz* functions."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the Go project directory containing go.mod",
                    },
                    "target_harness": {
                        "type": "string",
                        "description": "Optional: test only this specific harness (FuzzXxx name)",
                    },
                    "trial_duration": {
                        "type": "integer",
                        "description": "Duration for each fuzzing trial in seconds",
                        "default": 30,
                    },
                    "execution_timeout": {
                        "type": "integer",
                        "description": "Timeout for execution test in seconds",
                        "default": 10,
                    },
                },
                "required": ["project_path"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "go_harness_test":
            result = await test_harnesses(
                project_path_str=arguments["project_path"],
                target_harness=arguments.get("target_harness"),
                trial_duration=arguments.get("trial_duration", settings.default_trial_duration),
                execution_timeout=arguments.get("execution_timeout", 10),
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.exception(f"Error in {name}: {e}")
        return [TextContent(type="text", text=f"Error: {e!s}")]


async def main():
    logger.info("Starting Go Harness Tester MCP Server")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
