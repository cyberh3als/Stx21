"""Hard-coded secret detection for mobile app contents.

High-confidence, provider-specific patterns only: generic "looks random" matching
produces the false positives this project is trying to remove. Placeholder and
documentation values are filtered, and reports carry a masked value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from strix.mobile.findings import MobileFinding


if TYPE_CHECKING:
    from strix.mobile.archive import AppArchive


@dataclass(frozen=True)
class SecretRule:
    rule: str
    title: str
    severity: str
    cwe: str
    pattern: re.Pattern[bytes]
    note: str = ""


# No leading \b on the prefix-anchored patterns: in a DEX string table a string is preceded
# by its length byte, which can itself be a word character and would hide the match.
_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "secret_aws_access_key_id",
        "Hard-coded AWS access key ID",
        "high",
        "CWE-798",
        re.compile(rb"(AKIA[0-9A-Z]{16})(?![0-9A-Z])"),
    ),
    SecretRule(
        "secret_private_key",
        "Embedded private key",
        "high",
        "CWE-321",
        re.compile(rb"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----)"),
    ),
    SecretRule(
        "secret_slack_token",
        "Hard-coded Slack token",
        "high",
        "CWE-798",
        re.compile(rb"(xox[baprs]-[0-9A-Za-z-]{10,})"),
    ),
    SecretRule(
        "secret_github_token",
        "Hard-coded GitHub token",
        "high",
        "CWE-798",
        re.compile(rb"(gh[pousr]_[A-Za-z0-9]{36,})"),
    ),
    SecretRule(
        "secret_stripe_live_key",
        "Hard-coded Stripe live secret key",
        "high",
        "CWE-798",
        re.compile(rb"(sk_live_[0-9A-Za-z]{24,})"),
    ),
    SecretRule(
        "secret_google_api_key",
        "Hard-coded Google API key",
        "low",
        "CWE-798",
        re.compile(rb"(AIza[0-9A-Za-z_\-]{35})"),
        "Google API keys are often meant to ship in apps; severity depends on the "
        "restrictions (package/SHA-1, API scope) set on the key.",
    ),
    SecretRule(
        "secret_firebase_url",
        "Firebase Realtime Database URL embedded",
        "info",
        "CWE-200",
        re.compile(rb"(https://[a-z0-9-]+(?:-default-rtdb)?\.firebaseio\.com)"),
        "The URL alone is not a vulnerability; test whether the database rules allow "
        "unauthenticated access (read-only, within scope).",
    ),
)
_BY_NAME = {r.rule: r for r in _RULES}
_PLACEHOLDER = re.compile(
    r"EXAMPLE|XXXX|YOUR[_-]|PLACEHOLDER|DUMMY|CHANGEME|0000000|1234567|TEST|SAMPLE", re.IGNORECASE
)
SCAN_SUFFIXES = (
    ".dex",
    ".so",
    ".json",
    ".xml",
    ".txt",
    ".properties",
    ".js",
    ".html",
    ".plist",
    ".yml",
    ".yaml",
    ".cfg",
    ".conf",
    ".pem",
    ".arsc",
    ".bundle",
)
_MAX_SCAN_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class SecretHit:
    rule: str
    value: str
    context: str


def mask(value: str) -> str:
    if value.startswith("-----BEGIN"):
        return value
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)" if len(value) > 8 else "****"


def scan_bytes(data: bytes) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for rule in _RULES:
        for match in rule.pattern.finditer(data):
            value = match.group(1).decode("ascii", errors="replace")
            if _PLACEHOLDER.search(value):
                continue
            lo, hi = max(0, match.start() - 40), min(len(data), match.end() + 40)
            context = re.sub(r"[^\x20-\x7e]", ".", data[lo:hi].decode("latin-1"))
            hits.append(SecretHit(rule.rule, value, context))
    return hits


def rules_in_secret_evidence(evidence: str) -> set[str]:
    return {h.rule for h in scan_bytes(evidence.encode("latin-1", errors="replace"))}


def scan_archive(archive: AppArchive) -> list[MobileFinding]:
    findings: list[MobileFinding] = []
    seen: set[tuple[str, str]] = set()
    budget = _MAX_SCAN_BYTES
    for name, data in archive.iter_matching(SCAN_SUFFIXES):
        budget -= len(data)
        if budget < 0:
            break
        for hit in scan_bytes(data):
            key = (hit.rule, hit.value)
            if key in seen:
                continue
            seen.add(key)
            rule = _BY_NAME[hit.rule]
            findings.append(
                MobileFinding(
                    rule=hit.rule,
                    title=f"{rule.title} ({mask(hit.value)})",
                    severity=rule.severity,
                    cwe=rule.cwe,
                    description=f"{rule.title} found in {name}. Secrets shipped in an app can be "
                    "extracted by anyone who downloads it.",
                    remediation="Revoke and rotate the credential, remove it from the app, and "
                    "fetch short-lived credentials from a backend after user authentication.",
                    masvs="MASVS-STORAGE-1" if "key" in hit.rule else "MASVS-CRYPTO-2",
                    location=name,
                    evidence=hit.context,
                    notes=[n for n in (rule.note, "Report only the masked value.") if n],
                )
            )
    return findings
