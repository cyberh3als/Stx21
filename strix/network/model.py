"""Normalized network assessment data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Service:
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    ip: str = ""
    scripts: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    @property
    def label(self) -> str:
        return " ".join(p for p in (self.name, self.product, self.version) if p)


@dataclass
class NucleiRecord:
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    ip: str = ""
    cves: list[str] = field(default_factory=list)
    cwes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class Candidate:
    """A finding candidate built from real scanner output.

    ``validation`` is ready to pass to ``create_vulnerability_report`` as-is, so
    the deterministic validator re-checks the same evidence the engine used.
    """

    title: str
    severity: str
    cwe: str | None
    host: str
    port: int | None
    summary: str
    remediation: str
    validation: dict[str, Any]
    cve: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "cve": self.cve,
            "host": self.host,
            "port": self.port,
            "summary": self.summary,
            "remediation": self.remediation,
            "notes": self.notes,
            "validation": self.validation,
        }
