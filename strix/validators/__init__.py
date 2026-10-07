"""Deterministic finding validators.

``evaluate`` is the single entry point used by the reporting tool: it resolves
which validator applies to a finding (explicit ``validation.type`` first, then
the finding's CWE), runs it, and returns a JSON-serializable verification
record to store alongside the report.
"""

from __future__ import annotations

from typing import Any

from strix.validators import mobile, network, web  # noqa: F401  (registers validators)
from strix.validators.base import available_types, canonical_type, get_validator
from strix.validators.browser import check_xss_execution
from strix.validators.replay import REPLAYABLE_TYPES, replay


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


def _replayable(validator: str | None, spec: dict[str, Any]) -> bool:
    if validator not in REPLAYABLE_TYPES:
        return False
    multi_request = ("injected_ms", "baseline_ms", "true_response", "false_response")
    if validator == "sql_injection" and any(k in spec for k in multi_request):
        return False
    return not (validator == "ssrf" and ("token" in spec or "callback_log" in spec))


def apply_replay(
    validation: dict[str, Any] | None,
    verification: dict[str, Any],
    *,
    scope: dict[Any, str],
    allow_unsafe_methods: bool = False,
    timeout: float = 20.0,
    gateway_host: str | None = None,
) -> dict[str, Any]:
    """Re-send the evidence request and re-validate the fresh response.

    Only a request that was actually answered and did not reproduce downgrades
    the finding; skipped or errored replays leave the status untouched.
    """
    if verification.get("status") != "verified" or not isinstance(validation, dict):
        return verification
    spec = {k: v for k, v in validation.items() if k != "type"}
    validator_name = verification.get("validator")
    if not _replayable(validator_name, spec):
        verification["replay"] = {
            "status": "skipped",
            "detail": "evidence is not a single request/response pair",
        }
        return verification

    result = replay(
        spec.get("request"),
        scope,
        allow_unsafe_methods=allow_unsafe_methods,
        timeout=timeout,
        gateway_host=gateway_host,
    )
    if result.status in ("skipped", "error"):
        verification["replay"] = {"status": result.status, "detail": result.detail}
        return verification

    validator = get_validator(str(validator_name))
    outcome = validator({**spec, "response": result.response}) if validator else None
    if outcome is not None and outcome.ok:
        verification["replay"] = {"status": "reproduced", "http_status": result.http_status}
        return verification
    verification["status"] = "unverified"
    verification["replay"] = {"status": "not_reproduced", "http_status": result.http_status}
    verification["reasons"] = [
        *verification.get("reasons", []),
        "replay did not reproduce the evidence: "
        + "; ".join(outcome.reasons if outcome else ["validator unavailable"]),
    ]
    return verification


def apply_browser_check(
    validation: dict[str, Any] | None,
    verification: dict[str, Any],
    *,
    mode: str = "auto",
) -> dict[str, Any]:
    """Require proof that an XSS payload executes in a real browser.

    ``auto`` runs the check when the finding supplies an ``execution_token`` and
    only a payload that was rendered and did not run downgrades the finding.
    ``required`` also fails XSS findings with no token or no usable browser.
    """
    if (
        mode == "off"
        or verification.get("status") != "verified"
        or verification.get("validator") != "xss"
        or not isinstance(validation, dict)
    ):
        return verification

    result = check_xss_execution({k: v for k, v in validation.items() if k != "type"})
    verification["browser"] = {"status": result.status, "detail": result.detail}
    if result.status == "executed":
        verification["checks"] = [*verification.get("checks", []), result.detail]
        return verification
    failed = result.status == "not_executed" or (
        mode == "required" and result.status in ("skipped", "unavailable")
    )
    if failed:
        verification["status"] = "unverified"
        verification["reasons"] = [
            *verification.get("reasons", []),
            f"browser execution check: {result.detail}",
        ]
    return verification
