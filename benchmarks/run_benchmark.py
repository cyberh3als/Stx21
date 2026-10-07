#!/usr/bin/env python3
"""CLI entrypoint for the Strix benchmark harness.

    python -m benchmarks.run_benchmark fixtures   # validators + network + mobile; no Docker/LLM
    python -m benchmarks.run_benchmark agent       # the real strix CLI against the fixture app

See benchmarks/README.md for what each mode measures and its current results.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _run_fixtures() -> int:
    from benchmarks.harness import mobile_bench, network_bench, scoring, validator_bench

    sections = [("validators", validator_bench), ("network", network_bench)]
    cards = []
    for label, module in sections:
        print(f"Running {label} benchmark...", file=sys.stderr)
        cards.append(module.run())

    print("Running mobile benchmark...", file=sys.stderr)
    try:
        cards.append(mobile_bench.run())
    except Exception as exc:  # noqa: BLE001  # report it in the output, don't just crash
        print(f"mobile benchmark failed: {exc}", file=sys.stderr)

    report = scoring.render_report(cards)
    print(report)
    out_path = Path("benchmarks") / "results" / "fixtures-latest.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    print(f"\nWritten to {out_path}", file=sys.stderr)
    return 0


def _run_agent() -> int:
    from benchmarks.fixtures.vulnerable_app import FixtureServer
    from benchmarks.harness import scoring
    from benchmarks.harness.agent_runner import AgentRunUnavailableError, check_prerequisites, run
    from benchmarks.harness.agent_targets import FIXTURE_APP_TARGET_TEMPLATE

    try:
        check_prerequisites()
    except AgentRunUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    from dataclasses import replace

    with FixtureServer() as server:
        target = replace(FIXTURE_APP_TARGET_TEMPLATE, target=server.base_url)
        card = run(target)
    print(scoring.render_report([card]))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["fixtures", "agent"])
    args = parser.parse_args()
    return _run_fixtures() if args.mode == "fixtures" else _run_agent()


if __name__ == "__main__":
    raise SystemExit(main())
