"""Deterministic validators for common web vulnerability classes.

Each validator takes the structured ``validation`` evidence an agent submits
with a finding and checks it against a class-specific oracle that a model
cannot satisfy by merely asserting success: a payload reflected unencoded in an
HTML response, a computed value that only appears if an expression was
evaluated, a callback that only a server-side fetch could produce, and so on.

Honest limits: the evidence is agent-supplied, so these checks catch
hallucinated, misread and weak proof (the main source of false positives); they
do not defend against deliberately forged transcripts. Replaying the request
against the target is a separate, stronger backend.
"""

from __future__ import annotations

import difflib
import re
from urllib.parse import unquote, unquote_plus, urlsplit

from strix.validators.base import Check, Outcome, Spec, register
from strix.validators.http import Message, parse, request_host


_MIN_MARKER_LEN = 4
_MIN_TOKEN_LEN = 8
_BOOLEAN_SIMILAR = 0.98
_BOOLEAN_DIFFERENT = 0.95
_MAX_DIFF_CHARS = 5000


def _text(spec: Spec, key: str) -> str:
    value = spec.get(key)
    return value.strip() if isinstance(value, str) else ""


def _number_list(spec: Spec, key: str) -> list[float] | None:
    value = spec.get(key)
    if not isinstance(value, list) or not value:
        return None
    try:
        return [float(v) for v in value]
    except (TypeError, ValueError):
        return None


def _decoded(text: str) -> str:
    return unquote(unquote_plus(text))


def _messages(spec: Spec) -> tuple[Message, Message, Message]:
    return (
        parse(spec.get("request")),
        parse(spec.get("response")),
        parse(spec.get("baseline_response")),
    )


def _computed_marker(
    check: Check, spec: Spec, request: Message, response: Message, baseline: Message
) -> bool:
    """A value the server can only produce by evaluating the injected expression.

    The agent sends e.g. ``{{7*191}}`` and expects ``1337``; the result must not
    appear in the request (mere reflection) or the baseline response (coincidence).
    """
    expected = _text(spec, "expected")
    if len(expected) < _MIN_MARKER_LEN:
        check.failed(
            f"'expected' must be a computed value of at least {_MIN_MARKER_LEN} characters "
            "(e.g. payload 7*191 -> expected 1337)"
        )
        return False
    ok = True
    ok &= check.require(
        expected in response.body,
        f"computed value {expected!r} present in response",
        f"computed value {expected!r} not found in response body",
    )
    ok &= check.require(
        expected not in _decoded(request.raw),
        "computed value is absent from the request (not mere reflection)",
        "computed value also appears in the request; this is reflection, not evaluation",
    )
    if baseline.raw:
        ok &= check.require(
            expected not in baseline.body,
            "computed value absent from baseline response",
            "computed value already present in baseline response (coincidence)",
        )
    return ok


# --- XSS -----------------------------------------------------------------------

_ACTIVE_PAYLOAD = re.compile(
    r"<\s*script|<[^>]*\bon\w+\s*=|\bon(?:error|load|focus|click|mouse\w+|toggle|start)\s*=|javascript:",
    re.IGNORECASE,
)
_INERT_TAGS = ("textarea", "title", "noscript", "xmp", "template")
_NON_HTML = ("json", "text/plain", "javascript", "text/css", "octet-stream", "image/")
_INLINE_PAYLOAD = re.compile(r"<\s*script(?![^>]*\bsrc=)|\bon\w+\s*=|javascript:", re.IGNORECASE)


def _strip_inert(body: str) -> str:
    body = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
    for tag in _INERT_TAGS:
        body = re.sub(rf"<{tag}\b[^>]*>.*?</{tag}\s*>", "", body, flags=re.DOTALL | re.IGNORECASE)
    return body


def _csp_blocks_inline(csp: str) -> bool:
    directives = {}
    for part in csp.split(";"):
        name, _, value = part.strip().partition(" ")
        if name:
            directives[name.lower()] = value.lower()
    policy = directives.get("script-src", directives.get("default-src"))
    return policy is not None and "'unsafe-inline'" not in policy


@register("xss", aliases=("reflected_xss", "stored_xss", "dom_xss", "cross_site_scripting"))
def validate_xss(spec: Spec) -> Outcome:
    check = Check("xss")
    _, response, _ = _messages(spec)
    payload = _text(spec, "payload")

    if not check.require(bool(payload), "payload supplied", "'payload' is required"):
        return check.result()
    check.require(
        bool(_ACTIVE_PAYLOAD.search(payload)),
        "payload contains an executable construct",
        "payload has no executable construct (script tag, event handler or javascript: URL)",
    )
    if not check.require(
        response.status is not None, "response parsed", "'response' must be a raw HTTP response"
    ):
        return check.result()

    content_type = response.content_type
    check.require(
        not any(t in content_type for t in _NON_HTML),
        "response content type can render HTML",
        f"content type {content_type!r} does not render HTML; payload cannot execute",
    )
    check.require(
        payload in _strip_inert(response.body),
        "payload reflected verbatim (unencoded) in an executable position",
        "payload not found verbatim outside comments/inert elements (encoded or not reflected)",
    )
    csp = response.headers.get("content-security-policy", "")
    if csp and _INLINE_PAYLOAD.search(payload):
        check.require(
            not _csp_blocks_inline(csp),
            "CSP permits inline script",
            "CSP blocks inline script/handlers; demonstrate a CSP bypass",
        )
    return check.result()


# --- SQL injection ---------------------------------------------------------------

_SQL_ERRORS = re.compile(
    r"you have an error in your sql syntax|warning: mysqli?_|mysql_fetch|sqlstate\[\w+\]|"
    r"ora-\d{5}|pg_query\(\)|postgresql.{0,40}error|syntax error at or near|"
    r"unclosed quotation mark|sqlite3?::|sqlite_error|microsoft ole db provider for sql server|"
    r"odbc sql server driver|org\.hibernate\.|psycopg2\.errors|java\.sql\.sqlexception",
    re.IGNORECASE,
)
_SQL_INJECTION_HINT = re.compile(
    r"['\"`;]|--|/\*|\b(?:union|select|sleep|waitfor|benchmark|pg_sleep|extractvalue|updatexml|or|and)\b",
    re.IGNORECASE,
)


def _normalize(body: str) -> str:
    return re.sub(r"\s+", " ", body).strip()[:_MAX_DIFF_CHARS]


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, _normalize(a), _normalize(b)).ratio()


def _sqli_time(check: Check, spec: Spec) -> None:
    baseline = _number_list(spec, "baseline_ms")
    injected = _number_list(spec, "injected_ms")
    try:
        delay_ms = float(spec.get("delay_s", 0)) * 1000
    except (TypeError, ValueError):
        delay_ms = 0.0
    if not (baseline and injected and delay_ms > 0 and len(baseline) >= 2 and len(injected) >= 2):
        check.failed(
            "time-based proof needs 'delay_s' plus >= 2 samples each in "
            "'baseline_ms' and 'injected_ms'"
        )
        return
    check.require(
        min(injected) >= delay_ms * 0.9,
        f"every injected request took >= {delay_ms * 0.9:.0f} ms",
        f"fastest injected request ({min(injected):.0f} ms) is below the delay ({delay_ms:.0f} ms)",
    )
    check.require(
        max(baseline) < delay_ms * 0.5,
        "baseline requests are well below the delay",
        f"slowest baseline request ({max(baseline):.0f} ms) is too close to the "
        "delay; network noise",
    )


def _sqli_boolean(check: Check, spec: Spec) -> None:
    true_r, false_r, base_r = (
        parse(spec.get(k)).body for k in ("true_response", "false_response", "baseline_response")
    )
    if not (true_r and false_r and base_r):
        check.failed(
            "boolean proof needs 'true_response', 'false_response' and 'baseline_response'"
        )
        return
    check.require(
        _similarity(true_r, base_r) >= _BOOLEAN_SIMILAR,
        "TRUE condition response matches the baseline",
        "TRUE condition response differs from baseline "
        "(dynamic content, or condition not evaluated)",
    )
    check.require(
        _similarity(false_r, base_r) <= _BOOLEAN_DIFFERENT
        and _similarity(false_r, true_r) <= _BOOLEAN_DIFFERENT,
        "FALSE condition response differs from baseline and TRUE",
        "FALSE condition response is not distinguishable from TRUE/baseline",
    )


def _sqli_error(check: Check, request: Message, response: Message, baseline: Message) -> None:
    match = _SQL_ERRORS.search(response.body)
    if not check.require(
        match is not None,
        "database error signature present in response",
        "no database error signature in response",
    ):
        return
    signature = match.group(0) if match else ""
    check.require(
        signature.lower() not in _decoded(request.raw).lower(),
        "error text does not originate from the request",
        "error text appears in the request itself",
    )
    check.require(
        bool(_SQL_INJECTION_HINT.search(_decoded(request.raw))),
        "request contains SQL metacharacters/keywords",
        "request contains no SQL injection payload",
    )
    if baseline.raw:
        check.require(
            not _SQL_ERRORS.search(baseline.body),
            "baseline response has no database error",
            "baseline response already contains a database error (not caused by the payload)",
        )


@register("sql_injection", aliases=("sqli", "sql", "blind_sqli"))
def validate_sqli(spec: Spec) -> Outcome:
    check = Check("sql_injection")
    request, response, baseline = _messages(spec)
    if "injected_ms" in spec or "baseline_ms" in spec:
        check.passed("mode: time-based")
        _sqli_time(check, spec)
    elif "true_response" in spec or "false_response" in spec:
        check.passed("mode: boolean-based")
        _sqli_boolean(check, spec)
    elif "expected" in spec:
        check.passed("mode: computed-value (UNION/stacked)")
        _computed_marker(check, spec, request, response, baseline)
    else:
        check.passed("mode: error-based")
        _sqli_error(check, request, response, baseline)
    return check.result()


# --- Path traversal / LFI ---------------------------------------------------------

_FILE_SIGNATURES = (
    ("/etc/passwd", re.compile(r"(?m)^root:[^:\n]*:0:0:")),
    (
        "win.ini",
        re.compile(r"(?is)\[(?:fonts|extensions|mci extensions|files)\].*|for 16-bit app support"),
    ),
    ("boot.ini", re.compile(r"(?i)\[boot loader\]")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
)
_TRAVERSAL_HINT = re.compile(r"\.\.|/etc/|/proc/|[a-z]:\\|\\windows|file:", re.IGNORECASE)


@register(
    "path_traversal",
    aliases=("lfi", "local_file_inclusion", "directory_traversal", "arbitrary_file_read"),
)
def validate_path_traversal(spec: Spec) -> Outcome:
    check = Check("path_traversal")
    request, response, baseline = _messages(spec)
    check.require(
        bool(_TRAVERSAL_HINT.search(_decoded(request.raw))),
        "request targets a path outside the intended directory",
        "request has no path traversal/absolute path indicator",
    )
    hit = next(
        ((name, m) for name, rx in _FILE_SIGNATURES if (m := rx.search(response.body)) is not None),
        None,
    )
    if (
        not check.require(
            hit is not None,
            "response contains a known system-file signature",
            "no known system-file signature (/etc/passwd, win.ini, boot.ini, "
            "private key) in response",
        )
        or hit is None
    ):
        return check.result()
    name, match = hit
    check.require(
        match.group(0) not in request.raw,
        f"{name} content does not originate from the request",
        f"{name} signature appears in the request",
    )
    if baseline.raw:
        check.require(
            not any(rx.search(baseline.body) for n, rx in _FILE_SIGNATURES if n == name),
            "baseline response lacks the file content",
            "baseline response already contains the file content",
        )
    return check.result()


# --- Open redirect ---------------------------------------------------------------

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@register("open_redirect", aliases=("unvalidated_redirect",))
def validate_open_redirect(spec: Spec) -> Outcome:
    check = Check("open_redirect")
    request, response, _ = _messages(spec)
    if not check.require(
        response.status in _REDIRECT_STATUSES,
        f"response is a redirect ({response.status})",
        "response is not a 301/302/303/307/308 redirect",
    ):
        return check.result()
    location = response.headers.get("location", "").replace("\\", "/")
    host = (urlsplit(location).hostname or "").lower()
    target_host = _text(spec, "target_host").lower() or request_host(request) or ""
    if not check.require(
        bool(host),
        "Location has an absolute/scheme-relative host",
        "Location is relative; stays on site",
    ):
        return check.result()
    if not check.require(
        bool(target_host),
        "target host known",
        "cannot determine target host (add a Host header or 'target_host')",
    ):
        return check.result()
    check.require(
        host != target_host and not host.endswith("." + target_host),
        f"redirects off-site to {host}",
        f"redirect stays within {target_host}",
    )
    check.require(
        host in _decoded(request.raw).lower(),
        "redirect host is attacker-controlled (present in request)",
        "redirect host does not come from the request",
    )
    return check.result()


# --- Template / command / code injection -----------------------------------------


@register(
    "ssti", aliases=("template_injection", "server_side_template_injection", "expression_injection")
)
def validate_ssti(spec: Spec) -> Outcome:
    check = Check("ssti")
    request, response, baseline = _messages(spec)
    _computed_marker(check, spec, request, response, baseline)
    return check.result()


_ID_OUTPUT = re.compile(r"uid=\d+\([^)]*\)\s+gid=\d+")


@register("rce", aliases=("command_injection", "os_command_injection", "code_injection"))
def validate_rce(spec: Spec) -> Outcome:
    check = Check("rce")
    request, response, baseline = _messages(spec)
    if "expected" in spec:
        _computed_marker(check, spec, request, response, baseline)
        return check.result()
    match = _ID_OUTPUT.search(response.body)
    if (
        check.require(
            match is not None,
            "response contains `id` command output",
            "need a computed 'expected' value (e.g. echo $((7*191)) -> 1337) "
            "or `id` output in the response",
        )
        and match
    ):
        check.require(
            match.group(0) not in request.raw and not _ID_OUTPUT.search(baseline.body),
            "command output is not from the request or baseline",
            "command output appears in the request/baseline",
        )
    return check.result()


# --- Out-of-band (blind SSRF/XXE/RCE) ---------------------------------------------

_CALLBACK_HINT = re.compile(
    r"\b(dns|http|https|smtp|ldap|get|post|head|put|interaction)\b", re.IGNORECASE
)
_METADATA_SIGNATURE = re.compile(
    r"\bami-id\b|\binstance-id\b|\"accesskeyid\"|computemetadata|\"instancemetadata\"|metadata/v1",
    re.IGNORECASE,
)


def _oob(check: Check, spec: Spec, request: Message, response: Message) -> bool:
    token = _text(spec, "token")
    log = _text(spec, "callback_log")
    if len(token) < _MIN_TOKEN_LEN:
        check.failed(
            f"'token' must be a unique, unguessable value of >= {_MIN_TOKEN_LEN} characters"
        )
        return False
    ok = check.require(
        token in _decoded(request.raw),
        "token was sent in the request",
        "token not present in the request; callback cannot be attributed to it",
    )
    ok &= check.require(
        token in log and bool(_CALLBACK_HINT.search(log)),
        "callback log shows an inbound interaction carrying the token",
        "callback log has no interaction containing the token",
    )
    ok &= check.require(
        token not in response.body,
        "token not echoed in the response (not reflection)",
        "token is reflected in the response; that proves reflection, not a server-side fetch",
    )
    return ok


@register("oob", aliases=("blind_xxe", "blind_ssrf", "out_of_band", "interactsh", "collaborator"))
def validate_oob(spec: Spec) -> Outcome:
    check = Check("oob")
    request, response, _ = _messages(spec)
    _oob(check, spec, request, response)
    return check.result()


@register("ssrf", aliases=("server_side_request_forgery",))
def validate_ssrf(spec: Spec) -> Outcome:
    check = Check("ssrf")
    request, response, baseline = _messages(spec)
    if "token" in spec or "callback_log" in spec:
        check.passed("mode: out-of-band callback")
        _oob(check, spec, request, response)
        return check.result()
    check.passed("mode: in-band internal data")
    match = _METADATA_SIGNATURE.search(response.body)
    if (
        check.require(
            match is not None,
            "response contains cloud-metadata / internal-service content",
            "no out-of-band token supplied and no internal-service content in response",
        )
        and match
    ):
        check.require(
            match.group(0).lower() not in _decoded(request.raw).lower()
            and not _METADATA_SIGNATURE.search(baseline.body),
            "internal content is not from the request or baseline",
            "signature appears in the request or baseline",
        )
    return check.result()


# --- IDOR / BOLA ----------------------------------------------------------------


@register(
    "idor",
    aliases=("bola", "broken_object_level_authorization", "insecure_direct_object_reference"),
)
def validate_idor(spec: Spec) -> Outcome:
    check = Check("idor")
    request, response, _ = _messages(spec)
    attacker = _text(spec, "attacker_identity").lower()
    victim = _text(spec, "victim_identity").lower()
    marker = _text(spec, "victim_marker")

    check.require(
        bool(attacker) and bool(victim) and attacker != victim,
        "attacker and victim are distinct identities",
        "'attacker_identity' and 'victim_identity' are required and must differ",
    )
    check.require(
        response.status is not None and 200 <= response.status < 300,
        f"attacker's request succeeded ({response.status})",
        "attacker's request did not return 2xx",
    )
    if not check.require(
        len(marker) >= _MIN_MARKER_LEN,
        "victim-only marker supplied",
        f"'victim_marker' (data only the victim owns, >= {_MIN_MARKER_LEN} chars) is required",
    ):
        return check.result()
    check.require(
        marker in response.body,
        "victim's data present in attacker's response",
        "victim's marker not found in the attacker's response",
    )
    check.require(
        marker not in _decoded(request.raw),
        "marker is not supplied by the attacker",
        "marker appears in the attacker's own request",
    )
    unauth = parse(spec.get("unauthenticated_response"))
    if unauth.raw:
        check.require(
            not (
                unauth.status is not None and 200 <= unauth.status < 300 and marker in unauth.body
            ),
            "resource is not publicly readable",
            "resource is readable without authentication; report it as missing "
            "authentication, not IDOR",
        )
    return check.result()
