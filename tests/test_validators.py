"""Tests for the deterministic finding validators and their reporting gate."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.report.state import ReportState, set_global_report_state
from strix.report.writer import render_vulnerability_md
from strix.tools.reporting.tool import _do_create
from strix.validators import evaluate


if TYPE_CHECKING:
    from pathlib import Path


def _resp(body: str, status: int = 200, **headers: str) -> str:
    head = "".join(f"{k.replace('_', '-')}: {v}\n" for k, v in headers.items())
    return f"HTTP/1.1 {status} OK\nContent-Type: text/html\n{head}\n{body}"


def _verdict(validation: dict[str, Any], cwe: str | None = None) -> dict[str, Any]:
    return evaluate(validation, cwe)


# --- XSS ------------------------------------------------------------------------


def test_xss_verified_when_payload_reflected_unencoded() -> None:
    payload = "<script>alert(1)</script>"
    out = _verdict(
        {"type": "xss", "payload": payload, "response": _resp(f"<h2>Results for {payload}</h2>")}
    )
    assert out["status"] == "verified", out


def test_xss_fails_when_payload_is_html_encoded() -> None:
    payload = "<script>alert(1)</script>"
    out = _verdict(
        {
            "type": "xss",
            "payload": payload,
            "response": _resp("<h2>Results for &lt;script&gt;alert(1)&lt;/script&gt;</h2>"),
        }
    )
    assert out["status"] == "unverified"


def test_xss_fails_for_json_response_and_inert_contexts() -> None:
    payload = "<script>alert(1)</script>"
    json_resp = f'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{{"q": "{payload}"}}'
    assert (
        _verdict({"type": "xss", "payload": payload, "response": json_resp})["status"]
        == "unverified"
    )
    in_textarea = _resp(f"<textarea>{payload}</textarea>")
    assert (
        _verdict({"type": "xss", "payload": payload, "response": in_textarea})["status"]
        == "unverified"
    )
    in_comment = _resp(f"<!-- {payload} -->")
    assert (
        _verdict({"type": "xss", "payload": payload, "response": in_comment})["status"]
        == "unverified"
    )


def test_xss_fails_without_executable_payload_or_under_strict_csp() -> None:
    assert (
        _verdict({"type": "xss", "payload": "hello", "response": _resp("hello")})["status"]
        == "unverified"
    )
    payload = "<img src=x onerror=alert(1)>"
    strict = _resp(payload, content_security_policy="default-src 'self'")
    assert (
        _verdict({"type": "xss", "payload": payload, "response": strict})["status"] == "unverified"
    )
    relaxed = _resp(payload, content_security_policy="script-src 'self' 'unsafe-inline'")
    assert (
        _verdict({"type": "xss", "payload": payload, "response": relaxed})["status"] == "verified"
    )


# --- SQL injection ----------------------------------------------------------------


def test_sqli_error_based() -> None:
    request = "GET /item?id=1' HTTP/1.1\nHost: shop.test\n\n"
    good = _resp("You have an error in your SQL syntax; check the manual", 500)
    assert _verdict({"type": "sqli", "request": request, "response": good})["status"] == "verified"
    # error already present in baseline -> not caused by payload
    out = _verdict(
        {"type": "sqli", "request": request, "response": good, "baseline_response": good}
    )
    assert out["status"] == "unverified"
    # no payload in request
    plain = "GET /item?id=1 HTTP/1.1\nHost: shop.test\n\n"
    assert _verdict({"type": "sqli", "request": plain, "response": good})["status"] == "unverified"


def test_sqli_time_based_requires_samples_and_clear_margin() -> None:
    ok = {
        "type": "sql_injection",
        "delay_s": 5,
        "baseline_ms": [120, 140],
        "injected_ms": [5100, 5230],
    }
    assert _verdict(ok)["status"] == "verified"
    assert _verdict({**ok, "injected_ms": [5100]})["status"] == "unverified"
    assert _verdict({**ok, "baseline_ms": [120, 3000]})["status"] == "unverified"
    assert _verdict({**ok, "injected_ms": [800, 900]})["status"] == "unverified"


def test_sqli_boolean_based() -> None:
    base = _resp("<ul>" + "<li>Widget</li>" * 20 + "</ul>")
    empty = _resp("<ul></ul><p>No results</p>")
    ok = {"type": "sqli", "baseline_response": base, "true_response": base, "false_response": empty}
    assert _verdict(ok)["status"] == "verified"
    assert _verdict({**ok, "false_response": base})["status"] == "unverified"


def test_sqli_computed_marker() -> None:
    request = "GET /i?id=-1 UNION SELECT 7*191-- HTTP/1.1\nHost: a\n\n"
    out = _verdict(
        {"type": "sqli", "request": request, "response": _resp("<b>1337</b>"), "expected": "1337"}
    )
    assert out["status"] == "verified"


# --- Path traversal -----------------------------------------------------------------


def test_path_traversal() -> None:
    request = "GET /download?f=../../../../etc/passwd HTTP/1.1\nHost: a\n\n"
    passwd = _resp(
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    )
    assert _verdict({"type": "lfi", "request": request, "response": passwd})["status"] == "verified"
    assert (
        _verdict({"type": "lfi", "request": request, "response": _resp("not found", 404)})["status"]
        == "unverified"
    )
    benign = "GET /download?f=report.pdf HTTP/1.1\nHost: a\n\n"
    assert (
        _verdict({"type": "lfi", "request": benign, "response": passwd})["status"] == "unverified"
    )


# --- Open redirect --------------------------------------------------------------------


def test_open_redirect() -> None:
    request = "GET /go?next=//evil.example HTTP/1.1\nHost: app.test\n\n"
    redirect = "HTTP/1.1 302 Found\nLocation: //evil.example/login\n\n"
    assert (
        _verdict({"type": "open_redirect", "request": request, "response": redirect})["status"]
        == "verified"
    )
    onsite = "HTTP/1.1 302 Found\nLocation: /dashboard\n\n"
    assert (
        _verdict({"type": "open_redirect", "request": request, "response": onsite})["status"]
        == "unverified"
    )
    sibling = "HTTP/1.1 302 Found\nLocation: https://www.app.test/\n\n"
    req2 = "GET /go?next=https://www.app.test/ HTTP/1.1\nHost: app.test\n\n"
    assert (
        _verdict({"type": "open_redirect", "request": req2, "response": sibling})["status"]
        == "unverified"
    )
    # redirect host not influenced by the request
    fixed = "HTTP/1.1 302 Found\nLocation: https://sso.other.example/\n\n"
    assert (
        _verdict({"type": "open_redirect", "request": request, "response": fixed})["status"]
        == "unverified"
    )


# --- SSTI / RCE ---------------------------------------------------------------------


def test_ssti_requires_computed_value_not_reflection() -> None:
    request = "GET /?name={{7*191}} HTTP/1.1\nHost: a\n\n"
    assert (
        _verdict(
            {
                "type": "ssti",
                "request": request,
                "response": _resp("Hello 1337"),
                "expected": "1337",
            }
        )["status"]
        == "verified"
    )
    # reflected literally -> expression not evaluated
    assert (
        _verdict(
            {
                "type": "ssti",
                "request": request,
                "response": _resp("Hello {{7*191}}"),
                "expected": "1337",
            }
        )["status"]
        == "unverified"
    )
    # expected value present in the request itself
    req_leak = "GET /?name=1337 HTTP/1.1\nHost: a\n\n"
    assert (
        _verdict(
            {
                "type": "ssti",
                "request": req_leak,
                "response": _resp("Hello 1337"),
                "expected": "1337",
            }
        )["status"]
        == "unverified"
    )
    # too-short marker
    assert (
        _verdict({"type": "ssti", "request": request, "response": _resp("49"), "expected": "49"})[
            "status"
        ]
        == "unverified"
    )


def test_rce_accepts_id_output() -> None:
    request = "GET /ping?host=;id HTTP/1.1\nHost: a\n\n"
    out = _verdict(
        {
            "type": "rce",
            "request": request,
            "response": _resp("uid=33(www-data) gid=33(www-data) groups=33"),
        }
    )
    assert out["status"] == "verified"
    assert (
        _verdict({"type": "rce", "request": request, "response": _resp("ok")})["status"]
        == "unverified"
    )


# --- OOB / SSRF -----------------------------------------------------------------------


def test_oob_callback() -> None:
    token = "a1b2c3d4e5f6"  # noqa: S105
    request = f"POST /fetch HTTP/1.1\nHost: a\n\nurl=http://{token}.oast.test/"
    log = f"[HTTP] GET /x from 203.0.113.9 Host: {token}.oast.test"
    spec = {
        "type": "ssrf",
        "request": request,
        "token": token,
        "callback_log": log,
        "response": _resp("queued"),
    }
    assert _verdict(spec)["status"] == "verified"
    assert (
        _verdict({**spec, "callback_log": "[HTTP] GET /x from 203.0.113.9"})["status"]
        == "unverified"
    )
    assert _verdict({**spec, "response": _resp(f"fetched {token}")})["status"] == "unverified"
    assert _verdict({**spec, "token": "abc"})["status"] == "unverified"


def test_ssrf_in_band_metadata() -> None:
    request = "GET /proxy?u=http://169.254.169.254/latest/meta-data/ HTTP/1.1\nHost: a\n\n"
    out = _verdict(
        {"type": "ssrf", "request": request, "response": _resp("ami-id\ninstance-id\nhostname")}
    )
    assert out["status"] == "verified"


# --- IDOR -------------------------------------------------------------------------------


def test_idor() -> None:
    spec = {
        "type": "idor",
        "request": "GET /api/orders/1002 HTTP/1.1\nAuthorization: Bearer userA\n\n",
        "response": _resp('{"id":1002,"email":"victim@corp.test"}'),
        "attacker_identity": "user A",
        "victim_identity": "user B",
        "victim_marker": "victim@corp.test",
    }
    assert _verdict(spec)["status"] == "verified"
    assert _verdict({**spec, "victim_identity": "User A"})["status"] == "unverified"
    assert _verdict({**spec, "response": _resp("{}", 403)})["status"] == "unverified"
    public = {**spec, "unauthenticated_response": _resp('{"email":"victim@corp.test"}')}
    assert _verdict(public)["status"] == "unverified"


# --- Resolution rules ---------------------------------------------------------------------


def test_resolution_rules() -> None:
    assert evaluate(None, "CWE-1021")["status"] == "not_validated"
    missing = evaluate(None, "CWE-79")
    assert missing["status"] == "unverified"
    assert "xss" in missing["reasons"][0]
    unknown = evaluate({"type": "magic"}, None)
    assert unknown["status"] == "unverified"
    assert "available" in unknown["reasons"][0]
    assert evaluate({"payload": "x"}, None)["status"] == "unverified"
    # explicit type beats the CWE-inferred one
    explicit = evaluate(
        {"type": "ssti", "request": "x{{7*191}}", "response": _resp("1337"), "expected": "1337"},
        "CWE-79",
    )
    assert explicit["validator"] == "ssti"


def test_garbage_evidence_fails_closed() -> None:
    for spec in (
        {"type": "xss", "payload": "<script>x</script>", "response": 12345},
        {"type": "sqli", "request": None, "response": None},
        {"type": "sql_injection", "delay_s": "abc", "injected_ms": ["x"], "baseline_ms": []},
        {"type": "open_redirect", "request": "", "response": ""},
        {"type": "idor"},
    ):
        assert evaluate(spec, None)["status"] == "unverified", spec


# --- Reporting gate ---------------------------------------------------------------------------

_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "R",
    "scope": "C",
    "confidentiality": "L",
    "integrity": "L",
    "availability": "N",
}


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="validators")
    set_global_report_state(state)

    async def _not_duplicate(*_: Any, **__: Any) -> dict[str, Any]:
        return {"is_duplicate": False}

    monkeypatch.setattr("strix.report.dedupe.check_duplicate", _not_duplicate)
    return state


def _create(validation: dict[str, Any] | None, cwe: str | None = "CWE-79") -> Any:
    return _do_create(
        title="Reflected XSS in search",
        description="q reflects input.",
        impact="Session theft.",
        target="https://app.test",
        technical_analysis="No output encoding.",
        poc_description="Open the URL.",
        poc_script_code="GET /search?q=<script>alert(1)</script>",
        remediation_steps="Encode output.",
        evidence="Response echoes payload.",
        assumptions="Victim opens link.",
        fix_effort="low",
        cvss_breakdown=_CVSS,
        endpoint="/search",
        method="GET",
        cve=None,
        cwe=cwe,
        code_locations=None,
        validation=validation,
    )


def _set_mode(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    monkeypatch.setattr("strix.tools.reporting.tool._validation_mode", lambda: mode)


_GOOD_XSS = {
    "type": "xss",
    "payload": "<script>alert(1)</script>",
    "response": _resp("<h2><script>alert(1)</script></h2>"),
}


async def test_annotate_mode_files_unverified_findings_with_status(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_mode(monkeypatch, "annotate")
    result = await _create(None)
    assert result["success"] is True
    assert result["verification"]["status"] == "unverified"
    stored = report_state.vulnerability_reports[0]
    assert stored["verification"]["status"] == "unverified"
    assert "Verification" in render_vulnerability_md(stored)


async def test_verified_finding_is_marked_verified(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_mode(monkeypatch, "annotate")
    result = await _create(_GOOD_XSS)
    assert result["success"] is True
    assert report_state.vulnerability_reports[0]["verification"]["status"] == "verified"


async def test_enforce_mode_rejects_unverified_and_accepts_verified(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_mode(monkeypatch, "enforce")
    rejected = await _create(None)
    assert rejected["success"] is False
    assert rejected["verification"]["status"] == "unverified"
    assert report_state.vulnerability_reports == []

    accepted = await _create(_GOOD_XSS)
    assert accepted["success"] is True
    assert len(report_state.vulnerability_reports) == 1


@pytest.mark.usefixtures("report_state")
async def test_enforce_mode_does_not_block_classes_without_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_mode(monkeypatch, "enforce")
    result = await _create(None, cwe="CWE-1021")
    assert result["success"] is True
    assert result["verification"]["status"] == "not_validated"


async def test_off_mode_skips_validators(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_mode(monkeypatch, "off")
    result = await _create(None)
    assert result["success"] is True
    assert "verification" not in result
    assert "verification" not in report_state.vulnerability_reports[0]
    json.dumps(result)
