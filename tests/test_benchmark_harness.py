"""Tests for the benchmark harness's own logic and (where tools are present)
a real run of each fixtures-mode benchmark.

The scoring/matching tests are pure logic and always run. The live benchmarks
spin up real servers / run real nmap / build a real APK; they are skipped only
when a required binary (nmap) is genuinely absent, never silently weakened.
"""

from __future__ import annotations

import shutil

import pytest

from benchmarks.harness.ground_truth import GroundTruthFinding, ProbeResult
from benchmarks.harness.scoring import Scorecard, render_report


def _gt(name: str, expect_vulnerable: bool) -> GroundTruthFinding:
    return GroundTruthFinding(name, None, expect_vulnerable=expect_vulnerable)


def test_scorecard_classifies_all_four_outcomes() -> None:
    results = [
        ProbeResult(_gt("tp", expect_vulnerable=True), "verified"),
        ProbeResult(_gt("fn", expect_vulnerable=True), "unverified"),
        ProbeResult(_gt("fp", expect_vulnerable=False), "verified"),
        ProbeResult(_gt("tn", expect_vulnerable=False), "unverified"),
    ]
    card = Scorecard("demo", results)
    assert (card.true_positives, card.false_negatives) == (1, 1)
    assert (card.false_positives, card.true_negatives) == (1, 1)
    assert card.recall == pytest.approx(0.5)
    assert card.false_positive_rate == pytest.approx(0.5)
    rendered = card.render()
    assert "Recall" in rendered and "TP" in rendered and "FN" in rendered


def test_scorecard_recall_and_fpr_are_none_without_applicable_probes() -> None:
    only_safe = Scorecard("demo", [ProbeResult(_gt("tn", expect_vulnerable=False), "unverified")])
    assert only_safe.recall is None
    assert only_safe.false_positive_rate == 0.0
    only_vuln = Scorecard("demo", [ProbeResult(_gt("tp", expect_vulnerable=True), "verified")])
    assert only_vuln.false_positive_rate is None


def test_render_report_aggregates_across_scorecards() -> None:
    card_a = Scorecard("A", [ProbeResult(_gt("tp", expect_vulnerable=True), "verified")])
    card_b = Scorecard("B", [ProbeResult(_gt("fp", expect_vulnerable=False), "verified")])
    report = render_report([card_a, card_b])
    assert "## Overall" in report
    assert "Recall: 1/1" in report
    assert "False positive rate: 1/1" in report
    assert "### A" in report
    assert "### B" in report


# --- live fixtures-mode runs ------------------------------------------------------------


def test_validator_bench_against_the_live_fixture_app() -> None:
    from benchmarks.harness import validator_bench  # noqa: PLC0415

    card = validator_bench.run()
    assert card.recall == 1.0
    assert card.false_positive_rate == 0.0


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed")
def test_network_bench_against_real_nmap() -> None:
    from benchmarks.harness import network_bench  # noqa: PLC0415

    card = network_bench.run()
    assert card.recall == 1.0
    assert card.false_positive_rate == 0.0


def test_mobile_bench_against_a_real_binary_apk() -> None:
    from benchmarks.harness import mobile_bench  # noqa: PLC0415

    card = mobile_bench.run()
    assert card.recall == 1.0
    assert card.false_positive_rate == 0.0


def test_agent_runner_reports_concrete_missing_prerequisites(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from benchmarks.harness.agent_runner import (  # noqa: PLC0415
        AgentRunUnavailableError,
        check_prerequisites,
    )

    monkeypatch.delenv("STRIX_LLM", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(AgentRunUnavailableError, match=r"docker.*not installed"):
        check_prerequisites()
