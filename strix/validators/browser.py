"""Headless-browser proof that an XSS payload actually executes.

The static XSS validator shows the payload is reflected unencoded; this check
shows a real browser *runs* it. The captured HTTP response (status, headers and
body) is served to Chromium for the request URL, so the page is rendered with
its real Content-Security-Policy and content type, while every other request is
aborted: the check never contacts the target and the page cannot reach out.

The agent proves execution by making the payload surface a unique token, e.g.
``<img src=x onerror=alert('STRIX-7f3a9c')>``. The token must appear in an
``alert``/``confirm``/``prompt`` dialog or a ``console.log/info/debug`` message. Payloads that
need user interaction (mouseover, click) do not auto-fire and are not verified.

Playwright is an optional dependency (``pip install strix-agent[browser]``);
when it or Chromium is unavailable the result is ``unavailable``, never a pass.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from strix.validators.http import Message, parse


MIN_TOKEN_LEN = 6
SETTLE_MS = 1500
_PAGE_LOG_TYPES = frozenset({"log", "info", "debug"})
_STRIP_RESPONSE_HEADERS = frozenset(
    {"content-length", "content-encoding", "transfer-encoding", "connection"}
)


@dataclass
class BrowserResult:
    status: str  # "executed" | "not_executed" | "unavailable" | "skipped"
    detail: str = ""
    observed: list[str] = field(default_factory=list)


def _page_url(request: Message) -> str | None:
    target = request.target or "/"
    if "://" in target:
        return target
    host = request.headers.get("host")
    if not host:
        return None
    scheme = (
        "http" if host.endswith(":80") or (":" in host and not host.endswith(":443")) else "https"
    )
    return f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"


def _normalize(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}?{parts.query}"


def _launch_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {"headless": True}
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        kwargs["args"] = ["--no-sandbox"]
    return kwargs


def _fallback_executable() -> str | None:
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or "", "/opt/pw-browsers"]
    for root in filter(None, roots):
        for pattern in ("chromium-*/chrome-linux*/chrome", "chromium/chrome-linux*/chrome"):
            matches = sorted(Path(root).glob(pattern))
            if matches:
                return str(matches[-1])
    return None


def check_xss_execution(  # noqa: PLR0911
    spec: dict[str, Any], *, timeout_ms: int = 15000
) -> BrowserResult:
    """Render the captured response in Chromium and look for the execution token."""
    token = str(spec.get("execution_token") or "").strip()
    payload = str(spec.get("payload") or "")
    if len(token) < MIN_TOKEN_LEN:
        return BrowserResult(
            "skipped", f"'execution_token' (>= {MIN_TOKEN_LEN} chars, unique) not supplied"
        )
    if token not in payload:
        return BrowserResult("skipped", "'execution_token' must appear inside the payload")

    request, response = parse(spec.get("request")), parse(spec.get("response"))
    url = _page_url(request)
    if url is None or response.status is None:
        return BrowserResult("skipped", "needs a raw request (with Host) and raw response")

    try:
        # Optional dependency: imported lazily so strix works without the extra.
        from playwright.sync_api import Error as PlaywrightError  # noqa: PLC0415
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except ImportError:
        return BrowserResult("unavailable", "playwright is not installed (strix-agent[browser])")

    observed: list[str] = []
    main_url = _normalize(url)
    headers = {k: v for k, v in response.headers.items() if k not in _STRIP_RESPONSE_HEADERS}
    headers.setdefault("content-type", "text/html; charset=utf-8")

    def handle_route(route: Any) -> None:
        if _normalize(route.request.url) == main_url and route.request.is_navigation_request():
            route.fulfill(status=response.status, headers=headers, body=response.body)
        else:
            route.abort()

    def on_dialog(dialog: Any) -> None:
        observed.append(dialog.message)
        dialog.dismiss()

    try:
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(**_launch_kwargs())
            except PlaywrightError:
                executable = _fallback_executable()
                if not executable:
                    return BrowserResult("unavailable", "Chromium is not installed")
                browser = playwright.chromium.launch(executable_path=executable, **_launch_kwargs())
            try:
                context = browser.new_context(java_script_enabled=True, accept_downloads=False)
                context.route("**/*", handle_route)
                page = context.new_page()
                page.on("dialog", on_dialog)
                # Only page-authored log output counts: browser-generated errors
                # (failed loads, CSP refusals) can echo the payload without it running.
                page.on(
                    "console",
                    lambda m: observed.append(m.text) if m.type in _PAGE_LOG_TYPES else None,
                )
                page.goto(url, wait_until="load", timeout=timeout_ms)
                page.wait_for_timeout(SETTLE_MS)
            finally:
                browser.close()
    except PlaywrightError as exc:
        return BrowserResult("unavailable", f"browser error: {type(exc).__name__}")

    if any(token in text for text in observed):
        return BrowserResult("executed", "payload ran in Chromium", observed[:5])
    return BrowserResult(
        "not_executed",
        "payload did not execute in Chromium (blocked by CSP, encoded, or needs interaction)",
        observed[:5],
    )
