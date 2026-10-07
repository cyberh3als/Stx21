"""Replay backend: re-send a finding's request and re-validate the fresh response.

The base validators trust the transcript an agent submits. Replay removes that
trust for single-request evidence: the exact request is re-sent by host-side
code and the *new* response must satisfy the same oracle.

Safety rules (this sends attacker-shaped traffic, so it is conservative):

* Only hosts that belong to the scan's declared targets are ever contacted.
* Only safe methods (GET/HEAD/OPTIONS) unless unsafe methods are enabled, since
  re-sending a POST can create records or trigger actions twice.
* Redirects are never followed (open-redirect evidence is the redirect itself).
* Response bodies are size-capped and timeouts are short.

Replay is best-effort: single-use CSRF tokens, expiring sessions and targets
that are only reachable from inside the sandbox make it fail with an *error*,
which never downgrades a finding. Only a request that was sent, answered, and
did not reproduce the evidence counts as "not reproduced".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import requests

from strix.validators.http import Message, parse


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_BODY_BYTES = 2 * 1024 * 1024
# Evidence types whose proof is a single request/response pair.
REPLAYABLE_TYPES = frozenset(
    {"xss", "path_traversal", "open_redirect", "ssti", "rce", "idor", "ssrf", "sql_injection"}
)
_DROP_HEADERS = frozenset({"content-length", "connection", "transfer-encoding", "accept-encoding"})
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int


@dataclass
class ReplayResult:
    status: str  # "reproduced" | "not_reproduced" | "skipped" | "error"
    detail: str = ""
    http_status: int | None = None
    response: str = ""


def _endpoint_from_url(url: str) -> Endpoint | None:
    parts = urlsplit(url if "://" in url or url.startswith("//") else f"//{url}")
    if not parts.hostname:
        return None
    scheme = parts.scheme or "https"
    return Endpoint(parts.hostname.lower(), parts.port or _DEFAULT_PORTS.get(scheme, 443))


def scope_from_targets(
    targets_info: list[dict[str, Any]], gateway_host: str | None = None
) -> dict[Endpoint, str]:
    """Map each in-scope endpoint to its URL scheme.

    A localhost target is rewritten to the docker gateway name for the sandbox;
    host-side replay maps it back to loopback. Bare IPs/hosts (no scheme) allow
    both default ports.
    """
    scope: dict[Endpoint, str] = {}
    for target in targets_info or []:
        details = target.get("details") or {}
        urls: list[str] = []
        if target.get("type") == "web_application" and details.get("target_url"):
            urls.append(str(details["target_url"]))
        elif target.get("type") == "ip_address" and details.get("target_ip"):
            urls.append(f"//{details['target_ip']}")
        urls.extend(str(base) for base in details.get("base_urls") or [])
        for url in urls:
            endpoint = _endpoint_from_url(url)
            if endpoint is None:
                continue
            scheme = urlsplit(url).scheme or "https"
            if gateway_host and endpoint.host == gateway_host.lower():
                endpoint = Endpoint("127.0.0.1", endpoint.port)
            scope[endpoint] = scheme
            if "://" not in url:
                scope[Endpoint(endpoint.host, 80)] = "http"
                scope[Endpoint(endpoint.host, 443)] = "https"
    return scope


def _resolve_url(
    request: Message, scope: dict[Endpoint, str], gateway_host: str | None
) -> tuple[str | None, str]:
    """Return ``(url, error)``; the Host header / absolute target picks the endpoint."""
    target = request.target or "/"
    if "://" in target:
        raw_url = target
    else:
        host_header = request.headers.get("host", "")
        if not host_header:
            return None, "request has no Host header or absolute URL"
        raw_url = f"//{host_header}{target if target.startswith('/') else '/' + target}"
    parts = urlsplit(raw_url)
    host = (parts.hostname or "").lower()
    if not host:
        return None, "cannot determine request host"
    if gateway_host and host == gateway_host.lower():
        host = "127.0.0.1"
    if parts.port:
        ports = [parts.port]
    elif parts.scheme:
        ports = [_DEFAULT_PORTS.get(parts.scheme, 443)]
    else:
        ports = [443, 80]
    for port in ports:
        endpoint = Endpoint(host, port)
        if endpoint in scope:
            scheme = parts.scheme or scope[endpoint]
            path = parts.path or "/"
            query = f"?{parts.query}" if parts.query else ""
            return f"{scheme}://{host}:{port}{path}{query}", ""
    return None, f"{host} is outside the scan scope"


def _render(response: requests.Response, body: bytes) -> str:
    reason = response.reason or ""
    head = f"HTTP/1.1 {response.status_code} {reason}".rstrip()
    headers = "".join(f"{k}: {v}\n" for k, v in response.headers.items())
    return f"{head}\n{headers}\n{body.decode('utf-8', errors='replace')}"


def replay(
    raw_request: object,
    scope: dict[Endpoint, str],
    *,
    allow_unsafe_methods: bool = False,
    timeout: float = 20.0,
    verify_tls: bool = False,
    gateway_host: str | None = None,
) -> ReplayResult:
    """Re-send ``raw_request`` if it targets an in-scope host with an allowed method."""
    request = parse(raw_request)
    if not request.method:
        return ReplayResult("skipped", "evidence request is not a raw HTTP request")
    if request.method not in SAFE_METHODS and not allow_unsafe_methods:
        return ReplayResult(
            "skipped", f"{request.method} is not replayed (unsafe method; enable explicitly)"
        )
    if not scope:
        return ReplayResult("skipped", "no scan targets known; cannot establish replay scope")
    url, error = _resolve_url(request, scope, gateway_host)
    if url is None:
        return ReplayResult("skipped" if "scope" in error else "error", error)

    headers = {k: v for k, v in request.headers.items() if k not in _DROP_HEADERS}
    try:
        with requests.Session() as session:
            response = session.request(
                request.method,
                url,
                headers=headers,
                data=request.body.encode() if request.body else None,
                allow_redirects=False,
                timeout=timeout,
                stream=True,
                verify=verify_tls,
            )
            body = response.raw.read(MAX_BODY_BYTES, decode_content=True)
            rendered = _render(response, body)
            return ReplayResult(
                "reproduced",  # provisional: caller re-validates the fresh response
                http_status=response.status_code,
                response=rendered,
            )
    except requests.RequestException as exc:
        return ReplayResult("error", f"replay request failed: {type(exc).__name__}")
