"""Shared ground-truth and scoring types for both benchmark modes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GroundTruthFinding:
    """One known-planted vulnerability (or known-absent one) in a target."""

    name: str
    cwe: str | None
    expect_vulnerable: bool  # False = a "safe" probe that must NOT verify
    detail: str = ""


@dataclass
class ProbeResult:
    """The outcome of running the real pipeline against one ground-truth item."""

    finding: GroundTruthFinding
    status: str  # "verified" | "unverified" | "not_validated" | "error"
    evidence_summary: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_true_positive(self) -> bool:
        return self.finding.expect_vulnerable and self.status == "verified"

    @property
    def is_false_negative(self) -> bool:
        return self.finding.expect_vulnerable and self.status != "verified"

    @property
    def is_false_positive(self) -> bool:
        return not self.finding.expect_vulnerable and self.status == "verified"

    @property
    def is_true_negative(self) -> bool:
        return not self.finding.expect_vulnerable and self.status != "verified"
