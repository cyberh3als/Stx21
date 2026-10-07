"""Tests for the headless-browser XSS execution check."""

from __future__ import annotations

from typing import Any

import pytest

from strix.validators import apply_browser_check, evaluate
from strix.validators.browser import check_xss_execution


TOKEN = "STRIX-7f3a9c"  # noqa: S105
PAYLOAD = f"<img src=x onerror=alert('{TOKEN}')>"
REQUEST = "GET /search?q=x HTTP/1.1\nHost: app.test\n\n"


def _spec(body: str, **headers: str) -> dict[str, Any]:
    head = "".join(f"{k}: {v}\n" for k, v in headers.items())
    return {
        "type": "xss",
        "payload": PAYLOAD,
        "execution_token": TOKEN,
        "request": REQUEST,
        "response": f"HTTP/1.1 200 OK\nContent-Type: text/html\n{head}\n{body}",
    }


@pytest.fixture(scope="module")
def browser_ready() -> None:
    probe = check_xss_execution(_spec(f"<h2>{PAYLOAD}</h2>"))
    if probe.status == "unavailable":
        pytest.skip(f"headless Chromium unavailable: {probe.detail}")


def test_skipped_without_valid_token() -> None:
    spec = _spec(PAYLOAD)
    assert check_xss_execution({**spec, "execution_token": ""}).status == "skipped"
    assert check_xss_execution({**spec, "execution_token": "short"}).status == "skipped"
    other = {**spec, "execution_token": "STRIX-not-in-payload"}
    result = check_xss_execution(other)
    assert result.status == "skipped"
    assert "inside the payload" in result.detail


@pytest.mark.usefixtures("browser_ready")
def test_payload_that_executes_is_confirmed() -> None:
    result = check_xss_execution(_spec(f"<h2>{PAYLOAD}</h2>"))
    assert result.status == "executed"
    assert any(TOKEN in line for line in result.observed)


@pytest.mark.usefixtures("browser_ready")
def test_csp_blocked_payload_does_not_execute() -> None:
    spec = _spec(f"<h2>{PAYLOAD}</h2>", **{"Content-Security-Policy": "default-src 'self'"})
    assert check_xss_execution(spec).status == "not_executed"


@pytest.mark.usefixtures("browser_ready")
def test_encoded_reflection_does_not_execute() -> None:
    assert check_xss_execution(_spec("<h2>&lt;img src=x&gt;</h2>")).status == "not_executed"


@pytest.mark.usefixtures("browser_ready")
def test_token_in_a_failed_resource_url_is_not_mistaken_for_execution() -> None:
    # The browser's own "Failed to load resource" error would echo this URL.
    payload = f"<img src='http://{TOKEN}.invalid/x.png'>"
    spec = {**_spec(f"<h2>{payload}</h2>"), "payload": payload}
    assert check_xss_execution(spec).status == "not_executed"


@pytest.mark.usefixtures("browser_ready")
def test_page_cannot_reach_the_network() -> None:
    body = f"<script>fetch('http://127.0.0.1:9/').then(()=>console.log('{TOKEN}-net')).catch(()=>{{}})</script>"
    spec = {**_spec(body), "payload": f"<script>x('{TOKEN}')</script>"}
    assert check_xss_execution(spec).status == "not_executed"


@pytest.mark.usefixtures("browser_ready")
def test_apply_browser_check_modes() -> None:
    good = _spec(f"<h2>{PAYLOAD}</h2>")
    verified = apply_browser_check(good, evaluate(good, None), mode="auto")
    assert verified["status"] == "verified"
    assert verified["browser"]["status"] == "executed"

    # static evidence says reflected, but the rendered page never runs it
    inert = {**good, "response": good["response"].replace(PAYLOAD, "<b>hi</b>")}
    out = apply_browser_check(inert, evaluate(good, None), mode="auto")
    assert out["status"] == "unverified"
    assert out["browser"]["status"] == "not_executed"


def test_auto_ignores_missing_token_but_required_does_not() -> None:
    spec = _spec(f"<h2>{PAYLOAD}</h2>")
    spec.pop("execution_token")
    auto = apply_browser_check(spec, evaluate(spec, None), mode="auto")
    assert auto["status"] == "verified"
    assert auto["browser"]["status"] == "skipped"
    required = apply_browser_check(spec, evaluate(spec, None), mode="required")
    assert required["status"] == "unverified"
    assert "execution_token" in required["reasons"][-1]
    off = apply_browser_check(spec, evaluate(spec, None), mode="off")
    assert "browser" not in off


def test_non_xss_findings_are_untouched() -> None:
    spec = {
        "type": "ssti",
        "request": REQUEST,
        "response": "HTTP/1.1 200 OK\n\n1337",
        "expected": "1337",
    }
    verification = evaluate(spec, None)
    assert apply_browser_check(spec, verification, mode="required") == verification
