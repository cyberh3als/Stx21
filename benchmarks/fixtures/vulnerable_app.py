"""A small, real HTTP server with hand-labeled planted vulnerabilities.

Pure stdlib, loopback-only. This is a benchmark fixture, not a real
application: every endpoint's vulnerability status is deliberate and
documented in ``GROUND_TRUTH`` below so the harness can score the detection
layer against a known-correct answer key. ``API_KEYS`` simulates two user
accounts for the IDOR probe.
"""

from __future__ import annotations

import ast
import html
import json
import operator
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Self
from urllib.parse import parse_qs, urlsplit


if TYPE_CHECKING:
    from collections.abc import Callable

from benchmarks.harness.ground_truth import GroundTruthFinding


API_KEYS = {"attacker-key-1": 101, "victim-key-2": 202}
_PROFILES = {
    101: {"id": 101, "name": "Attacker", "email": "attacker@example.test"},
    202: {"id": 202, "name": "Victim", "email": "victim@example.test"},
}
_FILES: dict[str, str] = {"report.txt": "Quarterly report: all green."}
VICTIM_EMAIL = _PROFILES[202]["email"]  # the known-correct ground truth for the IDOR probe
_SECRET_FILE_CONTENT = "root:x:0:0:root:/root:/bin/bash\n"  # noqa: S105  # stand-in for /etc/passwd, not a password


_ARITHMETIC_OPS: dict[type, Callable[[int, int], int]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
}


def _eval_arithmetic(expr: str) -> str:
    """A deliberately naive expression evaluator — this IS the planted bug."""

    def ev(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _ARITHMETIC_OPS:
            return _ARITHMETIC_OPS[type(node.op)](ev(node.left), ev(node.right))
        raise ValueError("unsupported expression")

    return str(ev(ast.parse(expr, mode="eval")))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        """Silence the default per-request stderr logging."""
        return

    def _send(self, status: int, body: bytes, content_type: str = "text/html") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: PLR0912, PLR0915
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        path = parts.path

        if path == "/search":
            # PLANTED: reflected XSS — unencoded reflection of `q`.
            q = query.get("q", "")
            self._send(200, f"<h2>Results for {q}</h2>".encode())
        elif path == "/safe/search":
            # SAFE: same feature, correctly HTML-escaped.
            q = query.get("q", "")
            self._send(200, f"<h2>Results for {html.escape(q)}</h2>".encode())
        elif path == "/go":
            # PLANTED: open redirect — `next` is trusted verbatim.
            self.send_response(302)
            self.send_header("Location", query.get("next", "/"))
            self.end_headers()
        elif path == "/safe/go":
            # SAFE: only relative, same-site paths are allowed.
            next_url = query.get("next", "/")
            target = next_url if next_url.startswith("/") and not next_url.startswith("//") else "/"
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
        elif path == "/download":
            # PLANTED: path traversal — naive string join, no containment check.
            name = query.get("file", "")
            if name == "../../secret":
                self._send(200, _SECRET_FILE_CONTENT.encode(), "text/plain")
            elif name in _FILES:
                self._send(200, _FILES[name].encode(), "text/plain")
            else:
                self._send(404, b"not found", "text/plain")
        elif path == "/safe/download":
            # SAFE: only an allowlisted set of names is ever served.
            name = query.get("file", "")
            if name in _FILES:
                self._send(200, _FILES[name].encode(), "text/plain")
            else:
                self._send(404, b"not found", "text/plain")
        elif path == "/calc":
            # PLANTED: expression "injection" (stand-in for SSTI) — the whole
            # expression is attacker-controlled and evaluated.
            try:
                self._send(200, _eval_arithmetic(query.get("expr", "0")).encode(), "text/plain")
            except (ValueError, SyntaxError, ZeroDivisionError):
                self._send(400, b"bad expression", "text/plain")
        elif path == "/safe/calc":
            # SAFE: fixed server-side computation; input never reaches an evaluator.
            self._send(200, b"42", "text/plain")
        elif path.startswith("/profile/"):
            # PLANTED: IDOR — any authenticated key can read any profile id.
            auth = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if auth not in API_KEYS:
                self._send(401, b"{}", "application/json")
                return
            try:
                requested_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._send(400, b"{}", "application/json")
                return
            profile = _PROFILES.get(requested_id)
            self._send(
                200 if profile else 404,
                json.dumps(profile or {}).encode(),
                "application/json",
            )
        elif path.startswith("/safe/profile/"):
            # SAFE: the server only ever returns the caller's own profile.
            auth = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            own_id = API_KEYS.get(auth)
            profile = _PROFILES.get(own_id, {}) if own_id is not None else {}
            self._send(
                200 if own_id is not None else 401,
                json.dumps(profile).encode(),
                "application/json",
            )
        else:
            self._send(404, b"not found", "text/plain")


class FixtureServer:
    """Context-managed loopback server wrapping :class:`Handler`."""

    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._httpd.shutdown()
        self._thread.join(timeout=5)


# Ground truth: what the harness must find, and what it must NOT flag.
GROUND_TRUTH: list[GroundTruthFinding] = [
    GroundTruthFinding(
        "reflected_xss", "CWE-79", expect_vulnerable=True, detail="/search?q= is unencoded"
    ),
    GroundTruthFinding(
        "safe_search_escaped", "CWE-79", expect_vulnerable=False, detail="/safe/search HTML-escapes"
    ),
    GroundTruthFinding(
        "open_redirect", "CWE-601", expect_vulnerable=True, detail="/go?next= trusts any host"
    ),
    GroundTruthFinding(
        "safe_redirect_allowlisted",
        "CWE-601",
        expect_vulnerable=False,
        detail="/safe/go only same-site",
    ),
    GroundTruthFinding(
        "path_traversal", "CWE-22", expect_vulnerable=True, detail="/download?file=../../secret"
    ),
    GroundTruthFinding(
        "safe_download_allowlisted",
        "CWE-22",
        expect_vulnerable=False,
        detail="/safe/download allowlist",
    ),
    GroundTruthFinding(
        "expression_injection",
        None,
        expect_vulnerable=True,
        detail="/calc?expr= evaluates attacker input",
    ),
    GroundTruthFinding(
        "safe_calc_fixed", None, expect_vulnerable=False, detail="/safe/calc ignores input"
    ),
    GroundTruthFinding(
        "idor_profile", "CWE-639", expect_vulnerable=True, detail="/profile/<id> ignores ownership"
    ),
    GroundTruthFinding(
        "safe_profile_own_only",
        "CWE-639",
        expect_vulnerable=False,
        detail="/safe/profile/<id> own id only",
    ),
]
