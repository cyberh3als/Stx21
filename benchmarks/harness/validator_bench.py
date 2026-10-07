"""Probe the live fixture app for real and score the validators against it.

Every HTTP exchange here is a genuine request/response captured from a running
server — nothing is hand-typed as validator input. This is the detection
layer's own "does validation hold up against a real target" check.
"""

from __future__ import annotations

import http.client
import urllib.error
import urllib.request as urlrequest
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from benchmarks.fixtures.vulnerable_app import API_KEYS, GROUND_TRUTH, VICTIM_EMAIL, FixtureServer
from benchmarks.harness.ground_truth import ProbeResult
from benchmarks.harness.scoring import Scorecard
from strix.validators import apply_replay, evaluate
from strix.validators.replay import Endpoint


if TYPE_CHECKING:
    from benchmarks.harness.ground_truth import GroundTruthFinding


def _fetch(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    req = urlrequest.Request(url, headers=headers or {})  # noqa: S310  # loopback fixture only
    try:
        with urlrequest.urlopen(req) as resp:  # noqa: S310
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def _fetch_no_redirect(
    host: str, port: int, path: str, headers: dict[str, str] | None = None
) -> tuple[int, dict[str, str], bytes]:
    """Like ``_fetch`` but never follows a redirect — needed to see the 3xx itself."""
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()


def _raw_request(method: str, path: str, host: str, extra_headers: str = "") -> str:
    return f"{method} {path} HTTP/1.1\nHost: {host}\n{extra_headers}\n"


def _raw_response(status: int, headers: dict[str, str], body: bytes) -> str:
    head = "".join(f"{k}: {v}\n" for k, v in headers.items())
    return f"HTTP/1.1 {status} OK\n{head}\n{body.decode('utf-8', errors='replace')}"


def _probe(
    name_to_handler: dict[str, Any], gt: GroundTruthFinding, server: FixtureServer
) -> ProbeResult:
    handler = name_to_handler.get(gt.name)
    if handler is None:
        return ProbeResult(gt, "error", f"no probe defined for {gt.name}")
    try:
        validation, replay_ok = handler(server)
    except Exception as exc:  # noqa: BLE001  # a probe bug must score as an error, not crash the run
        return ProbeResult(gt, "error", f"probe raised {type(exc).__name__}: {exc}")
    verdict = evaluate(validation, gt.cwe)
    if replay_ok and verdict["status"] == "verified":
        scope = {Endpoint(server.host, server.port): "http"}
        verdict = apply_replay(validation, verdict, scope=scope, gateway_host=None)
    replay_status = verdict.get("replay", {}).get("status", "n/a")
    summary = f"validator={verdict.get('validator')} replay={replay_status}"
    return ProbeResult(gt, verdict["status"], summary, verdict)


def _xss(path: str) -> Any:
    def run(server: FixtureServer) -> tuple[dict[str, Any], bool]:
        payload = "<img src=x onerror=alert(1)>"
        status, headers, body = _fetch(f"{server.base_url}{path}?q={quote(payload)}")
        return {
            "type": "xss",
            "payload": payload,
            "request": _raw_request(
                "GET", f"{path}?q={quote(payload)}", f"{server.host}:{server.port}"
            ),
            "response": _raw_response(status, headers, body),
        }, True

    return run


def _redirect(path: str) -> Any:
    def run(server: FixtureServer) -> tuple[dict[str, Any], bool]:
        target = "//evil.example"
        request_path = f"{path}?next={quote(target, safe='')}"
        status, headers, body = _fetch_no_redirect(server.host, server.port, request_path)
        return {
            "type": "open_redirect",
            "request": _raw_request("GET", request_path, f"{server.host}:{server.port}"),
            "response": _raw_response(status, headers, body),
        }, True  # redirects are never replayed by design; apply_replay no-ops safely

    return run


def _traversal(path: str, filename: str) -> Any:
    def run(server: FixtureServer) -> tuple[dict[str, Any], bool]:
        status, headers, body = _fetch(f"{server.base_url}{path}?file={quote(filename)}")
        return {
            "type": "path_traversal",
            "request": _raw_request(
                "GET", f"{path}?file={quote(filename)}", f"{server.host}:{server.port}"
            ),
            "response": _raw_response(status, headers, body),
        }, True

    return run


def _calc(path: str) -> Any:
    def run(server: FixtureServer) -> tuple[dict[str, Any], bool]:
        a, b = 83, 47
        expr = f"{a}*{b}"
        status, headers, body = _fetch(f"{server.base_url}{path}?expr={quote(expr)}")
        return {
            "type": "ssti",
            "request": _raw_request(
                "GET", f"{path}?expr={quote(expr)}", f"{server.host}:{server.port}"
            ),
            "response": _raw_response(status, headers, body),
            "expected": str(a * b),
        }, True

    return run


def _profile(path_fmt: str) -> Any:
    def run(server: FixtureServer) -> tuple[dict[str, Any], bool]:
        attacker_key = next(k for k, v in API_KEYS.items() if v == 101)
        victim_id = next(v for v in API_KEYS.values() if v == 202)
        headers = {"Authorization": f"Bearer {attacker_key}"}
        status, resp_headers, body = _fetch(f"{server.base_url}{path_fmt % victim_id}", headers)
        return {
            "type": "idor",
            "attacker_identity": "attacker (id 101)",
            "victim_identity": "victim (id 202)",
            # The known-correct victim data — not whatever this response happens to
            # contain. Using the live body here would make the probe tautological:
            # a "safe" endpoint that returns the attacker's OWN data would still
            # "verify" because the marker was copied from that same response.
            "victim_marker": VICTIM_EMAIL,
            "request": _raw_request(
                "GET",
                path_fmt % victim_id,
                f"{server.host}:{server.port}",
                f"Authorization: Bearer {attacker_key}\n",
            ),
            "response": _raw_response(status, resp_headers, body),
        }, True

    return run


# Maps each GROUND_TRUTH.name to a probe that returns (validation, replayable).
PROBES: dict[str, Any] = {
    "reflected_xss": _xss("/search"),
    "safe_search_escaped": _xss("/safe/search"),
    "open_redirect": _redirect("/go"),
    "safe_redirect_allowlisted": _redirect("/safe/go"),
    "path_traversal": _traversal("/download", "../../secret"),
    "safe_download_allowlisted": _traversal("/safe/download", "../../secret"),
    "expression_injection": _calc("/calc"),
    "safe_calc_fixed": _calc("/safe/calc"),
    "idor_profile": _profile("/profile/%d"),
    "safe_profile_own_only": _profile("/safe/profile/%d"),
}


def run() -> Scorecard:
    with FixtureServer() as server:
        results = [_probe(PROBES, gt, server) for gt in GROUND_TRUTH]
    return Scorecard("Validators + replay (live fixture app)", results)
