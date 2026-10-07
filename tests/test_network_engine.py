"""Tests for the external network assessment engine."""
# ruff: noqa: E501

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from strix.agents import factory
from strix.core.inputs import build_root_task, build_scope_context
from strix.interface.utils import infer_target_type
from strix.network import NetworkScope, analyze
from strix.network.parsers import (
    cert_not_after,
    parse_naabu,
    parse_nmap_xml,
    parse_nuclei,
    tls_ciphers,
    tls_protocols,
)
from strix.validators import evaluate


_ENUM = """TLSv1.0:
  ciphers:
    TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
    TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
TLSv1.2:
  ciphers:
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
"""
_CERT = "Subject: commonName=old.example\nNot valid before: 2019-01-01T00:00:00\nNot valid after:  2020-01-01T00:00:00\n"

NMAP_XML = f"""<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
<host><status state="up"/>
<address addr="203.0.113.10" addrtype="ipv4"/>
<hostnames><hostname name="app.example.test" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.18"/>
<script id="ssl-enum-ciphers" output="{_ENUM.replace(chr(10), "&#10;")}"/>
<script id="ssl-cert" output="{_CERT.replace(chr(10), "&#10;")}"/>
</port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis key-value store"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="8080"><state state="closed"/></port>
</ports></host>
<host><status state="up"/>
<address addr="198.51.100.99" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port></ports>
</host>
</nmaprun>"""

NAABU = (
    '{"host":"app.example.test","ip":"203.0.113.10","port":6379}\n'
    '{"host":"app.example.test","ip":"203.0.113.10","port":9200}\n'
    "not json\n"
)

NUCLEI = (
    json.dumps(
        {
            "template-id": "CVE-2021-41773",
            "info": {
                "name": "Apache 2.4.49 Path Traversal",
                "severity": "critical",
                "tags": ["cve", "apache"],
                "classification": {"cve-id": ["cve-2021-41773"], "cwe-id": ["cwe-22"]},
            },
            "host": "https://app.example.test",
            "ip": "203.0.113.10",
            "matched-at": "https://app.example.test/cgi-bin/.%2e/etc/passwd",
        }
    )
    + "\n"
    + json.dumps(
        {
            "template-id": "tech-detect",
            "info": {"name": "Tech", "severity": "info"},
            "host": "https://app.example.test",
        }
    )
    + "\n"
    + json.dumps(
        {
            "template-id": "CVE-2020-0001",
            "info": {"name": "Other host", "severity": "high"},
            "host": "https://stranger.test",
        }
    )
)

SCOPE_TARGETS = [{"type": "ip_address", "details": {"target_ip": "203.0.113.10"}}]


def _titles(result: dict) -> list[str]:
    return [c["title"] for c in result["candidates"]]


# --- scope ---------------------------------------------------------------------------


def test_scope_from_ip_range_url_and_hostname() -> None:
    scope = NetworkScope.from_targets(
        [
            {"type": "ip_range", "details": {"target_cidr": "192.0.2.0/28"}},
            {"type": "web_application", "details": {"target_url": "https://App.Example.test/x"}},
            {"type": "repository", "details": {"target_repo": "https://github.com/a/b"}},
        ]
    )
    assert scope.contains("192.0.2.7")
    assert not scope.contains("192.0.2.200")
    assert scope.contains("app.example.test")
    assert scope.contains("unknown.host", ip="192.0.2.3")
    assert not scope.contains("github.com")
    assert not NetworkScope.from_targets([])


def test_scope_rejects_oversized_ranges() -> None:
    with pytest.raises(ValueError, match="limit"):
        NetworkScope.from_targets([{"type": "ip_range", "details": {"target_cidr": "10.0.0.0/16"}}])


# --- parsers -------------------------------------------------------------------------


def test_parse_nmap_xml_keeps_only_open_ports_with_raw_evidence() -> None:
    services = parse_nmap_xml(NMAP_XML)
    assert {(s.host, s.port) for s in services} == {
        ("app.example.test", 443),
        ("app.example.test", 6379),
        ("app.example.test", 22),
        ("198.51.100.99", 3306),
    }
    https = next(s for s in services if s.port == 443)
    assert https.ip == "203.0.113.10"
    assert tls_protocols(https.scripts["ssl-enum-ciphers"]) == ["TLSv1.0", "TLSv1.2"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in tls_ciphers(https.scripts["ssl-enum-ciphers"])
    assert cert_not_after(https.scripts["ssl-cert"]) == "2020-01-01"
    assert '<port protocol="tcp" portid="443">' in https.raw


def test_nmap_xml_with_dtd_or_garbage_is_rejected() -> None:
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><nmaprun>&e;</nmaprun>'
    assert parse_nmap_xml(evil) == []
    assert parse_nmap_xml("not xml") == []
    assert parse_nmap_xml("") == []


def test_nmap_bare_doctype_is_allowed_but_subsets_and_external_refs_are_not() -> None:
    # nmap's own -oX output always opens with exactly this: no internal
    # subset, no SYSTEM/PUBLIC reference. Rejecting it discards every real
    # scan, which is what benchmarks/harness/network_bench.py caught.
    bare = '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun><host></host></nmaprun>'
    assert parse_nmap_xml(bare) == []  # well-formed but no <host>/<ports> content to extract
    assert "ParseError" not in repr(parse_nmap_xml)  # sanity: doesn't raise

    with_subset = '<?xml version="1.0"?>\n<!DOCTYPE nmaprun [<!ENTITY x "y">]>\n<nmaprun/>'
    assert parse_nmap_xml(with_subset) == []

    external_ref = (
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun SYSTEM "http://evil.example/x.dtd">\n<nmaprun/>'
    )
    assert parse_nmap_xml(external_ref) == []

    bare_with_open_port = (
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun><host>'
        '<address addr="10.0.0.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="6379"><state state="open"/></port></ports>'
        "</host></nmaprun>"
    )
    parsed = parse_nmap_xml(bare_with_open_port)
    assert [(s.host, s.port) for s in parsed] == [("10.0.0.5", 6379)]


def test_parse_naabu_and_nuclei_skip_bad_lines() -> None:
    assert [(s.host, s.port) for s in parse_naabu(NAABU)] == [
        ("app.example.test", 6379),
        ("app.example.test", 9200),
    ]
    records = parse_nuclei(NUCLEI)
    assert [r.template_id for r in records] == ["CVE-2021-41773", "tech-detect", "CVE-2020-0001"]
    assert records[0].host == "app.example.test"
    assert records[0].cves == ["CVE-2021-41773"]
    assert records[0].cwes == ["CWE-22"]


# --- assessment ------------------------------------------------------------------------


def test_analyze_produces_scoped_candidates_and_drops_out_of_scope() -> None:
    scope = NetworkScope.from_targets(SCOPE_TARGETS)
    result = analyze(scope, nmap_xml=NMAP_XML, naabu_jsonl=NAABU, nuclei_jsonl=NUCLEI)
    titles = _titles(result)
    assert any(t.startswith("Redis exposed") for t in titles)
    assert any("Elasticsearch" in t for t in titles)  # from naabu only
    assert any("Deprecated protocol TLSv1.0" in t for t in titles)
    assert any("Weak TLS cipher suites" in t for t in titles)
    assert any("Expired TLS certificate" in t for t in titles)
    assert any("CVE-2021-41773" in t for t in titles)
    assert not any("tech-detect" in t for t in titles)  # info, no CVE
    assert not any("MySQL" in t for t in titles)  # 198.51.100.99 is out of scope
    assert not any("CVE-2020-0001" in t for t in titles)
    assert not any("SSH" in t for t in titles)
    assert set(result["out_of_scope_hosts_ignored"]) == {"198.51.100.99", "stranger.test"}
    severities = [c["severity"] for c in result["candidates"]]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    assert severities == sorted(severities, key=order.__getitem__)


def test_nmap_data_takes_precedence_over_naabu_for_same_port() -> None:
    scope = NetworkScope.from_targets(SCOPE_TARGETS)
    result = analyze(scope, nmap_xml=NMAP_XML, naabu_jsonl=NAABU)
    assert sum(1 for t in _titles(result) if t.startswith("Redis exposed")) == 1


def test_candidate_validations_pass_their_validators() -> None:
    scope = NetworkScope.from_targets(SCOPE_TARGETS)
    result = analyze(scope, nmap_xml=NMAP_XML, naabu_jsonl=NAABU, nuclei_jsonl=NUCLEI)
    assert result["candidates"]
    for candidate in result["candidates"]:
        verdict = evaluate(candidate["validation"], candidate["cwe"])
        assert verdict["status"] == "verified", (candidate["title"], verdict)


def test_validators_reject_hallucinated_evidence() -> None:
    scope = NetworkScope.from_targets(SCOPE_TARGETS)
    candidates = analyze(scope, nmap_xml=NMAP_XML, nuclei_jsonl=NUCLEI)["candidates"]
    redis = next(c for c in candidates if c["port"] == 6379)["validation"]
    assert evaluate({**redis, "port": 27017}, None)["status"] == "unverified"
    assert evaluate({**redis, "host": "203.0.113.77"}, None)["status"] == "unverified"
    assert evaluate({**redis, "evidence": ""}, None)["status"] == "unverified"

    tls = next(c for c in candidates if "TLSv1.0" in c["title"])["validation"]
    assert evaluate({**tls, "weakness": "SSLv3"}, None)["status"] == "unverified"
    assert evaluate({**tls, "weakness": "TLSv9"}, None)["status"] == "unverified"

    nuclei = next(c for c in candidates if "CVE-2021-41773" in c["title"])["validation"]
    assert evaluate({**nuclei, "template_id": "CVE-2099-0001"}, None)["status"] == "unverified"
    assert evaluate({**nuclei, "host": "other.example"}, None)["status"] == "unverified"
    assert evaluate({**nuclei, "evidence": "just trust me"}, None)["status"] == "unverified"


def test_unexpired_certificate_is_not_reported() -> None:
    xml = NMAP_XML.replace("2020-01-01T00:00:00", "2099-01-01T00:00:00")
    scope = NetworkScope.from_targets(SCOPE_TARGETS)
    assert not any("Expired" in t for t in _titles(analyze(scope, nmap_xml=xml)))
    verdict = evaluate(
        {
            "type": "tls_weakness",
            "weakness": "cert_expired",
            "evidence": "Not valid after:  2099-01-01",
        },
        None,
    )
    assert verdict["status"] == "unverified"
    assert datetime.now(UTC).year < 2099


# --- target + tool wiring ------------------------------------------------------------------


def test_cidr_targets_are_inferred_and_capped() -> None:
    assert infer_target_type("203.0.113.0/24") == ("ip_range", {"target_cidr": "203.0.113.0/24"})
    assert infer_target_type("198.51.100.7")[0] == "ip_address"
    with pytest.raises(ValueError, match="limit"):
        infer_target_type("10.0.0.0/8")


def test_ip_range_is_rendered_and_authorized() -> None:
    config = {
        "targets": [
            {
                "type": "ip_range",
                "details": {"target_cidr": "203.0.113.0/28"},
                "original": "203.0.113.0/28",
            }
        ]
    }
    assert "203.0.113.0/28" in build_root_task(config)
    authorized = build_scope_context(config)
    assert "203.0.113.0/28" in json.dumps(authorized)


def test_network_tool_is_registered_for_scan_agents() -> None:
    assert "analyze_network_scan" in [t.name for t in factory._BASE_TOOLS]
