"""Aggregate ProbeResults into recall / false-positive-rate reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from benchmarks.harness.ground_truth import ProbeResult


@dataclass
class Scorecard:
    section: str
    results: list[ProbeResult]

    @property
    def true_positives(self) -> int:
        return sum(r.is_true_positive for r in self.results)

    @property
    def false_negatives(self) -> int:
        return sum(r.is_false_negative for r in self.results)

    @property
    def false_positives(self) -> int:
        return sum(r.is_false_positive for r in self.results)

    @property
    def true_negatives(self) -> int:
        return sum(r.is_true_negative for r in self.results)

    @property
    def recall(self) -> float | None:
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total else None

    @property
    def false_positive_rate(self) -> float | None:
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total else None

    def render(self) -> str:
        def pct(value: float | None) -> str:
            return "n/a" if value is None else f"{value * 100:.0f}%"

        lines = [
            f"### {self.section}",
            "",
            f"- Recall (planted vulns confirmed): {self.true_positives}/"
            f"{self.true_positives + self.false_negatives} ({pct(self.recall)})",
            f"- False positive rate (safe probes incorrectly confirmed): "
            f"{self.false_positives}/{self.false_positives + self.true_negatives} "
            f"({pct(self.false_positive_rate)})",
            "",
            "| Probe | Expected | Status | Outcome |",
            "|---|---|---|---|",
        ]
        for r in self.results:
            expected = "vulnerable" if r.finding.expect_vulnerable else "safe"
            outcome = (
                "TP"
                if r.is_true_positive
                else "FN"
                if r.is_false_negative
                else "FP"
                if r.is_false_positive
                else "TN"
            )
            lines.append(f"| {r.finding.name} | {expected} | {r.status} | {outcome} |")
        return "\n".join(lines)


def render_report(scorecards: list[Scorecard]) -> str:
    sections = "\n\n".join(card.render() for card in scorecards)
    total_tp = sum(c.true_positives for c in scorecards)
    total_fn = sum(c.false_negatives for c in scorecards)
    total_fp = sum(c.false_positives for c in scorecards)
    total_tn = sum(c.true_negatives for c in scorecards)
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else None
    fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) else None
    overall = (
        f"## Overall\n\n- Recall: {total_tp}/{total_tp + total_fn} "
        f"({'n/a' if recall is None else f'{recall * 100:.0f}%'})\n"
        f"- False positive rate: {total_fp}/{total_fp + total_tn} "
        f"({'n/a' if fpr is None else f'{fpr * 100:.0f}%'})\n"
    )
    return f"{overall}\n{sections}\n"
