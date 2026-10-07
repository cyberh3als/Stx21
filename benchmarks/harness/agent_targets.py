"""Default agent-mode benchmark targets.

These point the agent at the same fixture app the validator benchmark probes
directly, so the two modes are comparable: the fixtures benchmark asks "is the
deterministic validation sound given correct evidence", agent mode asks "does
the autonomous agent find and prove these bugs on its own, including the
evidence". Point ``AgentTarget.target`` at a real app (a URL, IP, or local
checkout) and reuse the same ``GroundTruthFinding`` list to benchmark anything
else.
"""

from __future__ import annotations

from benchmarks.fixtures.vulnerable_app import GROUND_TRUTH as FIXTURE_GROUND_TRUTH
from benchmarks.harness.agent_runner import AgentTarget


# The agent needs a running server, not a module import — start
# ``benchmarks.fixtures.vulnerable_app.FixtureServer`` yourself and fill in
# its URL (``run_benchmark.py agent`` does this automatically).
FIXTURE_APP_TARGET_TEMPLATE = AgentTarget(
    name="fixture_app",
    target="",  # filled in with the running fixture's base_url at run time
    ground_truth=[gt for gt in FIXTURE_GROUND_TRUTH if gt.expect_vulnerable],
    scan_mode="quick",
    max_budget_usd=10.0,
)
