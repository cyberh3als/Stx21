"""Shared shapes for mobile static-analysis results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MobileFinding:
    rule: str
    title: str
    severity: str
    cwe: str | None
    description: str
    remediation: str
    masvs: str
    location: str = ""
    evidence: str = ""
    notes: list[str] = field(default_factory=list)

    def to_candidate(self, platform: str, subject: str) -> dict[str, Any]:
        """Candidate dict with a `validation` object ready for create_vulnerability_report."""
        validation: dict[str, Any] = {
            "type": "mobile_manifest"
            if self.rule.split(":")[0] in _CONFIG_RULES
            else "mobile_secret",
            "platform": platform,
            "rule": self.rule,
            "evidence": self.evidence,
        }
        return {
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "rule": self.rule,
            "masvs": self.masvs,
            "location": self.location,
            "summary": self.description,
            "remediation": self.remediation,
            "notes": self.notes,
            "subject": subject,
            "validation": validation,
        }


# Rule ids produced by the manifest/plist analyzers (everything else is a secret rule).
_CONFIG_RULES = frozenset(
    {
        "debuggable",
        "allow_backup",
        "cleartext_traffic",
        "exported_component",
        "nsc_cleartext",
        "nsc_user_ca",
        "low_target_sdk",
        "ats_arbitrary_loads",
        "ats_exception_http",
        "file_sharing",
    }
)
