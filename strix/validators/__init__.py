"""Deterministic finding validators.

``evaluate`` is the single entry point used by the reporting tool: it resolves
which validator applies to a finding (explicit ``validation.type`` first, then
the finding's CWE), runs it, and returns a JSON-serializable verification
record to store alongside the report.
"""

from __future__ import annotations

from typing import Any

from strix.validators import web  # noqa: F401  (registers validators)
from strix.validators.base import available_types, canonical_type, get_validator


_CWE_TO_TYPE = {
    "CWE-79": "xss",
    "CWE-80": "xss",
    "CWE-89": "sql_injection",
    "CWE-564": "sql_injection",
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-36": "path_traversal",
    "CWE-601": "open_redirect",
    "CWE-1336": "ssti",
    "CWE-77": "rce",
    "CWE-78": "rce",
    "CWE-918": "ssrf",
    "CWE-639": "idor",
}

NOT_VALIDATED = "not_validated"
MODES = ("off", "annotate", "enforce")


def infer_type(cwe: str | None) -> str | None:
    return _CWE_TO_TYPE.get((cwe or "").strip().upper())


def evaluate(validation: dict[str, Any] | None, cwe: str | None) -> dict[str, Any]:
    """Return the verification record for a finding.

    ``status`` is ``verified`` (a validator confirmed it), ``unverified`` (a
    validator applies but the evidence did not hold up or was missing), or
    ``not_validated`` (no validator exists for this class).
    """
    requested = None
    if isinstance(validation, dict):
        raw_type = validation.get("type")
        requested = canonical_type(raw_type if isinstance(raw_type, str) else None)
        if requested is None:
            reason = (
                f"unknown validation type {raw_type!r}"
                if raw_type
                else "validation.type is missing"
            )
            return {
                "status": "unverified",
                "validator": None,
                "checks": [],
                "reasons": [f"{reason}; available: {', '.join(available_types())}"],
            }

    expected = requested or infer_type(cwe)
    if expected is None:
        return {"status": NOT_VALIDATED, "validator": None, "checks": [], "reasons": []}

    if not isinstance(validation, dict):
        return {
            "status": "unverified",
            "validator": expected,
            "checks": [],
            "reasons": [
                f"no validation evidence supplied; a '{expected}' validator applies to this finding"
            ],
        }

    validator = get_validator(expected)
    if validator is None:  # pragma: no cover - guarded by canonical_type
        return {"status": NOT_VALIDATED, "validator": None, "checks": [], "reasons": []}
    spec = {k: v for k, v in validation.items() if k != "type"}
    return validator(spec).to_dict()
