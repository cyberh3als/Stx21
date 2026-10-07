"""Drive the real `strix` CLI (multi-agent LLM loop) and score its findings.

Unlike the other harness modules, this needs Docker (the sandbox the agent
runs in) and an LLM API key (``STRIX_LLM`` + ``LLM_API_KEY``) — neither is
assumed to be present. ``run()`` raises :class:`AgentRunUnavailable` up front
when they are missing, rather than failing confusingly mid-scan.

Scoring here is coarser than the other benchmark modes: it checks whether a
filed finding's CWE matches a ground-truth entry for the target, not whether
the agent's specific exploit is correct. That is the right level for judging
whether the *agent* discovered the bug class on its own; the deterministic
validators (exercised directly in ``validator_bench.py``) are what already
checks the exploit evidence.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from benchmarks.harness.ground_truth import GroundTruthFinding, ProbeResult
from benchmarks.harness.scoring import Scorecard


DEFAULT_TIMEOUT_S = 3600


class AgentRunUnavailableError(RuntimeError):
    """Raised when the environment can't run a real agent scan."""


@dataclass
class AgentTarget:
    """One benchmark target for agent mode: a scan target plus its answer key."""

    name: str
    target: str  # anything `strix --target` accepts: a path, URL, or IP
    ground_truth: list[GroundTruthFinding]  # `.name` is unused; `.cwe` is matched
    scan_mode: str = "quick"
    max_budget_usd: float = 10.0
    extra_args: tuple[str, ...] = ()


def check_prerequisites() -> None:
    """Raise :class:`AgentRunUnavailable` with a concrete reason, or return."""
    missing = []
    docker_bin = shutil.which("docker")
    if docker_bin is None:
        missing.append("the `docker` CLI is not installed")
    else:
        probe = subprocess.run(  # noqa: S603  # resolved absolute path, fixed args, no shell
            [docker_bin, "info"], capture_output=True, timeout=15, check=False
        )
        if probe.returncode != 0:
            missing.append("the Docker daemon is not reachable (`docker info` failed)")
    if not os.environ.get("STRIX_LLM"):
        missing.append("STRIX_LLM is not set")
    if not (os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")):
        missing.append("LLM_API_KEY (or OPENAI_API_KEY) is not set")
    if missing:
        raise AgentRunUnavailableError(
            "Cannot run a real agent scan here: " + "; ".join(missing) + ". "
            "This mode needs a working Docker daemon and an LLM API key; set them and "
            "re-run `python -m benchmarks.run_benchmark agent`, or run the fixtures-mode "
            "benchmarks instead (no Docker/LLM required)."
        )


def _run_scan(target: AgentTarget, run_dir: Path) -> Path:
    strix_bin = shutil.which("strix") or sys.executable
    args = [strix_bin] if strix_bin != sys.executable else [strix_bin, "-m", "strix"]
    args += [
        "-n",
        "--target",
        target.target,
        "--scan-mode",
        target.scan_mode,
        "--max-budget",
        str(target.max_budget_usd),
        *target.extra_args,
    ]
    env = {**os.environ, "STRIX_RUNS_DIR": str(run_dir)}
    subprocess.run(  # noqa: S603  # args are config, not shell text
        args, cwd=run_dir, env=env, timeout=DEFAULT_TIMEOUT_S, check=False
    )
    run_dirs = sorted(run_dir.glob("*"), key=lambda p: p.stat().st_mtime)
    if not run_dirs:
        raise AgentRunUnavailableError(f"strix produced no run directory under {run_dir}")
    return run_dirs[-1]


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def score_run(run_output_dir: Path, ground_truth: list[GroundTruthFinding]) -> Scorecard:
    """Score one completed run directory's filed findings against ground truth."""
    findings = _load_json(run_output_dir / "vulnerabilities.json") or []
    found_cwes = {f.get("cwe") for f in findings if f.get("cwe")}
    results = [
        ProbeResult(
            gt,
            "verified" if gt.cwe in found_cwes else "unverified",
            f"{len(findings)} findings filed in this run",
        )
        for gt in ground_truth
    ]
    return Scorecard(f"Agent run: {run_output_dir.name}", results)


def run(target: AgentTarget) -> Scorecard:
    check_prerequisites()
    with TemporaryDirectory() as tmp:
        output_dir = _run_scan(target, Path(tmp))
        return score_run(output_dir, target.ground_truth)
