"""External network assessment engine (assessment-only; no exploitation)."""

from __future__ import annotations

from typing import Any

from strix.network.model import Candidate, NucleiRecord, Service
from strix.network.parsers import parse_naabu, parse_nmap_xml, parse_nuclei
from strix.network.rules import assess
from strix.network.scope import NetworkScope


__all__ = [
    "Candidate",
    "NetworkScope",
    "NucleiRecord",
    "Service",
    "analyze",
    "assess",
]


def analyze(
    scope: NetworkScope,
    *,
    nmap_xml: str = "",
    naabu_jsonl: str = "",
    nuclei_jsonl: str = "",
) -> dict[str, Any]:
    """Parse raw scanner output and return scoped finding candidates.

    nmap data wins over naabu for the same host:port (it carries service and TLS
    detail); naabu only fills in ports nmap did not report.
    """
    nmap_services = parse_nmap_xml(nmap_xml)
    seen = {(s.host, s.port) for s in nmap_services} | {(s.ip, s.port) for s in nmap_services}
    extra = [
        s
        for s in parse_naabu(naabu_jsonl)
        if (s.host, s.port) not in seen and (s.ip, s.port) not in seen
    ]
    services = nmap_services + extra
    records = parse_nuclei(nuclei_jsonl)
    candidates, dropped = assess(services, records, scope)
    return {
        "services_in_scope": sum(1 for s in services if scope.contains(s.host, s.ip)),
        "candidates": [c.to_dict() for c in candidates],
        "out_of_scope_hosts_ignored": dropped,
    }
