"""Tests for the replay backend (against a real local HTTP server)."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import load_settings
from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _do_create
from strix.validators import apply_replay, evaluate
from strix.validators.replay import Endpoint, replay, scope_from_targets


if TYPE_CHECKING:
    from collections.abc import Iterator

PAYLOAD = "<script>alert(1)</script>"


class _Handler(BaseHTTPRequestHandler):
    mode = "vulnerable"
    seen: list[str] = []  # noqa: RUF012

    def do_GET(self) -> None:
        type(self).seen.append(self.command)
        body = (
            f"<h2>{PAYLOAD}</h2>"
            if type(self).mode == "vulnerable"
            else "<h2>&lt;script&gt;alert(1)&lt;/script&gt;</h2>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self) -> None:
        type(self).seen.append(self.command)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_: Any) -> None:
        return


@pytest.fixture
def server() -> Iterator[tuple[str, int]]:
    _Handler.mode = "vulnerable"
    _Handler.seen = []
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield "127.0.0.1", httpd.server_address[1]
    httpd.shutdown()
    thread.join(timeout=5)


def _targets(host: str, port: int) -> list[dict[str, Any]]:
    return [{"type": "web_application", "details": {"target_url": f"http://{host}:{port}/"}}]


def _xss_validation(host: str, port: int) -> dict[str, Any]:
    return {
        "type": "xss",
        "payload": PAYLOAD,
        "request": f"GET /search?q={PAYLOAD} HTTP/1.1\nHost: {host}:{port}\n\n",
        "response": f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<h2>{PAYLOAD}</h2>",
    }


def test_scope_from_targets_maps_gateway_and_bare_ips() -> None:
    scope = scope_from_targets(
        [
            {
                "type": "web_application",
                "details": {"target_url": "http://host.docker.internal:8080"},
            },
            {"type": "ip_address", "details": {"target_ip": "203.0.113.7"}},
            {"type": "repository", "details": {"target_repo": "https://github.com/a/b"}},
        ],
        gateway_host="host.docker.internal",
    )
    assert Endpoint("127.0.0.1", 8080) in scope
    assert Endpoint("203.0.113.7", 443) in scope
    assert Endpoint("203.0.113.7", 80) in scope
    assert all(e.host != "github.com" for e in scope)


def test_replay_reproduces_when_server_still_vulnerable(server: tuple[str, int]) -> None:
    host, port = server
    validation = _xss_validation(host, port)
    verification = evaluate(validation, None)
    assert verification["status"] == "verified"
    out = apply_replay(validation, verification, scope=scope_from_targets(_targets(host, port)))
    assert out["status"] == "verified"
    assert out["replay"]["status"] == "reproduced"
    assert _Handler.seen == ["GET"]


def test_replay_downgrades_when_evidence_does_not_reproduce(server: tuple[str, int]) -> None:
    host, port = server
    _Handler.mode = "fixed"
    validation = _xss_validation(host, port)
    verification = evaluate(validation, None)
    out = apply_replay(validation, verification, scope=scope_from_targets(_targets(host, port)))
    assert out["status"] == "unverified"
    assert out["replay"]["status"] == "not_reproduced"
    assert "replay did not reproduce" in out["reasons"][-1]


def test_replay_never_contacts_out_of_scope_hosts(server: tuple[str, int]) -> None:
    host, port = server
    validation = _xss_validation(host, port)
    other = {"type": "web_application", "details": {"target_url": "http://127.0.0.1:9/"}}
    out = apply_replay(validation, evaluate(validation, None), scope=scope_from_targets([other]))
    assert out["status"] == "verified"  # untouched
    assert out["replay"]["status"] == "skipped"
    assert "outside the scan scope" in out["replay"]["detail"]
    assert _Handler.seen == []


def test_replay_skips_unsafe_methods_unless_enabled(server: tuple[str, int]) -> None:
    host, port = server
    request = f"POST /x HTTP/1.1\nHost: {host}:{port}\n\nq=1"
    scope = scope_from_targets(_targets(host, port))
    assert replay(request, scope).status == "skipped"
    assert _Handler.seen == []
    assert replay(request, scope, allow_unsafe_methods=True).http_status == 200
    assert _Handler.seen == ["POST"]


def test_replay_errors_do_not_downgrade(server: tuple[str, int]) -> None:
    host, port = server
    validation = {**_xss_validation(host, port)}
    scope = scope_from_targets(_targets(host, port))
    server_port_closed = {Endpoint("127.0.0.1", 1): "http"}
    validation["request"] = "GET /x HTTP/1.1\nHost: 127.0.0.1:1\n\n"
    out = apply_replay(validation, evaluate(validation, None), scope=server_port_closed, timeout=2)
    assert out["status"] == "verified"
    assert out["replay"]["status"] == "error"
    assert scope  # silence unused


def test_multi_request_evidence_is_not_replayed(server: tuple[str, int]) -> None:
    host, port = server
    validation = {
        "type": "sql_injection",
        "delay_s": 5,
        "baseline_ms": [100, 110],
        "injected_ms": [5100, 5200],
    }
    out = apply_replay(
        validation, evaluate(validation, None), scope=scope_from_targets(_targets(host, port))
    )
    assert out["status"] == "verified"
    assert out["replay"]["status"] == "skipped"


def test_unverified_findings_are_not_replayed(server: tuple[str, int]) -> None:
    host, port = server
    bad = {"type": "xss", "payload": PAYLOAD, "response": "HTTP/1.1 200 OK\n\nnothing"}
    verification = evaluate(bad, None)
    out = apply_replay(bad, verification, scope=scope_from_targets(_targets(host, port)))
    assert "replay" not in out
    assert _Handler.seen == []


@pytest.mark.usefixtures("server")
def test_replay_does_not_follow_redirects() -> None:
    class _Redirect(_Handler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", "//evil.example/x")
            self.end_headers()

    httpd = HTTPServer(("127.0.0.1", 0), _Redirect)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        rport = httpd.server_address[1]
        validation = {
            "type": "open_redirect",
            "request": f"GET /go?next=//evil.example HTTP/1.1\nHost: 127.0.0.1:{rport}\n\n",
            "response": "HTTP/1.1 302 Found\nLocation: //evil.example/x\n\n",
        }
        scope = scope_from_targets(_targets("127.0.0.1", rport))
        out = apply_replay(validation, evaluate(validation, None), scope=scope)
        assert out["status"] == "verified"
        assert out["replay"]["status"] == "reproduced"
        assert out["replay"]["http_status"] == 302
    finally:
        httpd.shutdown()
        t.join(timeout=5)


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


async def _file(validation: dict[str, Any]) -> dict[str, Any]:
    return await _do_create(
        title="Reflected XSS",
        description="d",
        impact="i",
        target="t",
        technical_analysis="a",
        poc_description="p",
        poc_script_code="GET /",
        remediation_steps="r",
        evidence="e",
        assumptions="a",
        fix_effort="low",
        cvss_breakdown=_CVSS,
        endpoint="/search",
        method="GET",
        cve=None,
        cwe="CWE-79",
        code_locations=None,
        validation=validation,
    )


async def test_tool_enforce_with_replay_rejects_non_reproducible_finding(
    server: tuple[str, int], tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, port = server
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="replay-e2e")
    state.set_scan_config({"targets": _targets(host, port)})
    set_global_report_state(state)

    settings = load_settings()
    monkeypatch.setattr(settings.validation, "mode", "enforce")
    monkeypatch.setattr(settings.validation, "replay", True)

    async def _not_duplicate(*_: Any, **__: Any) -> dict[str, Any]:
        return {"is_duplicate": False}

    monkeypatch.setattr("strix.report.dedupe.check_duplicate", _not_duplicate)

    validation = _xss_validation(host, port)
    accepted = await _file(validation)
    assert accepted["success"] is True
    assert accepted["verification"]["replay"]["status"] == "reproduced"

    _Handler.mode = "fixed"
    rejected = await _file(validation)
    assert rejected["success"] is False
    assert rejected["verification"]["replay"]["status"] == "not_reproduced"
    assert len(state.vulnerability_reports) == 1
