"""Validators for network findings: the evidence must be real scanner output.

Each check re-parses the raw tool output attached to the finding and confirms
it says what the finding claims, so a hallucinated open port, protocol or CVE
match cannot be filed. They never touch the network.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from strix.network.parsers import (
    cert_not_after,
    parse_naabu,
    parse_nmap_xml,
    parse_nuclei,
    tls_ciphers,
    tls_protocols,
)
from strix.network.rules import weak_ciphers
from strix.validators.base import Check, Outcome, Spec, register


_TEXT_PORT = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\b", re.IGNORECASE | re.MULTILINE)
_KNOWN_WEAKNESSES = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "weak_cipher", "cert_expired")


def _text(spec: Spec, key: str) -> str:
    value = spec.get(key)
    return value.strip() if isinstance(value, str) else ""


def _port(spec: Spec) -> int | None:
    try:
        return int(spec.get("port"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _hosts_match(claimed: str, *observed: str) -> bool:
    return bool(claimed) and claimed.lower() in {o.lower() for o in observed if o}


def _open_ports(evidence: str) -> list[tuple[str, str, int]]:
    """(host, ip, port) triples from nmap XML, naabu JSONL, or nmap text output."""
    found = [(s.host, s.ip, s.port) for s in parse_nmap_xml(evidence)]
    found += [(s.host, s.ip, s.port) for s in parse_naabu(evidence)]
    # Fragments of nmap XML (a single <host> element) are valid for our purposes.
    return found


@register("exposed_service", aliases=("open_port", "service_exposure"))
def validate_exposed_service(spec: Spec) -> Outcome:
    check = Check("exposed_service")
    host, port, evidence = _text(spec, "host"), _port(spec), _text(spec, "evidence")
    if not (host and port and evidence):
        check.failed(
            "'host', 'port' and raw scanner 'evidence' (nmap XML / naabu JSON) are required"
        )
        return check.result()
    observed = _open_ports(evidence)
    matched = any(p == port and _hosts_match(host, h, ip) for h, ip, p in observed)
    if not matched and not observed:
        # nmap normal-format text has no host column; accept only when the host is named.
        matched = (
            any(int(m.group(1)) == port for m in _TEXT_PORT.finditer(evidence))
            and host.lower() in evidence.lower()
        )
    check.require(
        matched,
        f"scanner output shows {host}:{port} open",
        f"scanner output does not show {host}:{port} as open",
    )
    return check.result()


@register("tls_weakness", aliases=("weak_tls", "tls", "ssl"))
def validate_tls_weakness(spec: Spec) -> Outcome:
    check = Check("tls_weakness")
    weakness, evidence = _text(spec, "weakness"), _text(spec, "evidence")
    if weakness not in _KNOWN_WEAKNESSES:
        check.failed(f"'weakness' must be one of {', '.join(_KNOWN_WEAKNESSES)}")
        return check.result()
    if not evidence:
        check.failed("raw nmap ssl-enum-ciphers / ssl-cert output is required in 'evidence'")
        return check.result()
    if weakness == "cert_expired":
        expiry = cert_not_after(evidence)
        if not check.require(
            expiry is not None,
            "certificate expiry date present in evidence",
            "no 'Not valid after' date in evidence",
        ):
            return check.result()
        expired = datetime.fromisoformat(expiry or "").replace(tzinfo=UTC) < datetime.now(UTC)
        check.require(
            expired, f"certificate expired on {expiry}", f"certificate is valid until {expiry}"
        )
    elif weakness == "weak_cipher":
        weak = weak_ciphers(tls_ciphers(evidence))
        check.require(
            bool(weak),
            f"weak suites offered: {', '.join(weak[:5])}",
            "no weak cipher suites in the evidence",
        )
    else:
        check.require(
            weakness in tls_protocols(evidence),
            f"{weakness} is enabled per scanner output",
            f"{weakness} does not appear as an enabled protocol in the evidence",
        )
    return check.result()


@register("nuclei_match", aliases=("nuclei", "template_match", "known_cve"))
def validate_nuclei_match(spec: Spec) -> Outcome:
    check = Check("nuclei_match")
    template_id, host, evidence = (_text(spec, k) for k in ("template_id", "host", "evidence"))
    if not (template_id and host and evidence):
        check.failed(
            "'template_id', 'host' and the raw nuclei JSON record in 'evidence' are required"
        )
        return check.result()
    records = parse_nuclei(evidence)
    if not check.require(
        bool(records),
        "evidence parses as a nuclei JSON record",
        "evidence is not nuclei JSON output (use `nuclei -jsonl`)",
    ):
        return check.result()
    by_template = [r for r in records if r.template_id == template_id]
    check.require(
        bool(by_template),
        f"template {template_id} matched",
        f"template {template_id} is not among the matched templates",
    )
    check.require(
        any(_hosts_match(host, r.host) for r in by_template),
        f"match is on {host}",
        f"template {template_id} did not match on {host}",
    )
    return check.result()
