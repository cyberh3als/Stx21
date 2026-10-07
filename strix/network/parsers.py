"""Parsers for scanner output (nmap XML, naabu JSONL, nuclei JSONL).

All parsers are tolerant: malformed lines are skipped, never guessed at. nmap
XML comes from a tool that echoes banners from the scanned (untrusted) host, so
a DTD that declares entities (billion-laughs expansion, external SYSTEM/PUBLIC
references) is rejected before parsing. nmap's own ``-oX`` output always opens
with a bare ``<!DOCTYPE nmaprun>`` and nothing else, so that exact harmless form
is allowed through — rejecting it outright silently discarded every real scan.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET  # unsafe DTDs rejected up front
from typing import Any

from strix.network.model import NucleiRecord, Service


# A DOCTYPE with no internal subset and no external SYSTEM/PUBLIC identifier —
# just a bare root-element name — can declare no entities and is what nmap
# itself emits. Anything else matching ``<!DOCTYPE`` (a subset in ``[...]``,
# a SYSTEM/PUBLIC reference) is rejected, as is any standalone ``<!ENTITY``.
_BARE_DOCTYPE = re.compile(r"<!\s*DOCTYPE\s+[A-Za-z_][\w:.-]*\s*>", re.IGNORECASE)
_DOCTYPE_TOKEN = re.compile(r"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _has_unsafe_dtd(text: str) -> bool:
    return bool(_DOCTYPE_TOKEN.search(_BARE_DOCTYPE.sub("", text)))


def parse_nmap_xml(text: str) -> list[Service]:
    """Return open services from an nmap ``-oX`` document."""
    if not text or not text.strip() or _has_unsafe_dtd(text):
        return []
    try:
        root = ET.fromstring(text.strip())  # noqa: S314  # DTD/entities rejected above
    except ET.ParseError:
        return []
    services: list[Service] = []
    for host_el in root.iter("host"):
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        names = [h.get("name", "") for h in host_el.findall("./hostnames/hostname")]
        host = names[0] if names and names[0] else ip
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
            svc_el = port_el.find("service")
            scripts = {
                s.get("id", ""): s.get("output", "")
                for s in port_el.findall("script")
                if s.get("id")
            }
            try:
                port = int(port_el.get("portid", ""))
            except ValueError:
                continue
            services.append(
                Service(
                    host=host,
                    ip=ip,
                    port=port,
                    protocol=port_el.get("protocol", "tcp"),
                    state=state,
                    name=svc_el.get("name", "") if svc_el is not None else "",
                    product=svc_el.get("product", "") if svc_el is not None else "",
                    version=svc_el.get("version", "") if svc_el is not None else "",
                    scripts=scripts,
                    raw=_port_evidence(host_el, port_el),
                )
            )
    return services


def _port_evidence(host_el: ET.Element, port_el: ET.Element) -> str:
    """Raw nmap XML for just this host/port, so evidence stays tool output."""
    wrapper = ET.Element("host")
    wrapper.extend(host_el.findall("address"))
    hostnames = host_el.find("hostnames")
    if hostnames is not None:
        wrapper.append(hostnames)
    ports = ET.SubElement(wrapper, "ports")
    ports.append(port_el)
    return ET.tostring(wrapper, encoding="unicode")


def _jsonl(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def parse_naabu(text: str) -> list[Service]:
    """Return open ports from naabu ``-json`` output."""
    services: list[Service] = []
    for record in _jsonl(text):
        port = record.get("port")
        host = record.get("host") or record.get("ip")
        if isinstance(port, int) and host:
            services.append(
                Service(
                    host=str(host),
                    ip=str(record.get("ip") or ""),
                    port=port,
                    raw=json.dumps(record, sort_keys=True),
                )
            )
    return services


def _host_of(value: str) -> str:
    value = re.sub(r"^[a-z]+://", "", value or "")
    return re.split(r"[/:?#]", value, maxsplit=1)[0]


def parse_nuclei(text: str) -> list[NucleiRecord]:
    """Return matches from nuclei ``-jsonl`` output."""
    records: list[NucleiRecord] = []
    for raw in _jsonl(text):
        info = raw.get("info") or {}
        template_id = raw.get("template-id") or raw.get("templateID")
        if not template_id:
            continue
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        cwes = classification.get("cwe-id") or []
        matched = str(raw.get("matched-at") or raw.get("host") or "")
        records.append(
            NucleiRecord(
                template_id=str(template_id),
                name=str(info.get("name") or template_id),
                severity=str(info.get("severity") or "info").lower(),
                host=_host_of(str(raw.get("host") or matched)),
                matched_at=matched,
                ip=str(raw.get("ip") or ""),
                cves=[str(c).upper() for c in ([cves] if isinstance(cves, str) else cves)],
                cwes=[str(c).upper() for c in ([cwes] if isinstance(cwes, str) else cwes)],
                tags=[str(t) for t in (info.get("tags") or [])],
                raw=json.dumps(raw, sort_keys=True),
            )
        )
    return records


# --- nmap script output (ssl-enum-ciphers / ssl-cert) --------------------------------

_PROTOCOL_LINE = re.compile(r"^\s*(SSLv2|SSLv3|TLSv1\.[0-3]):\s*$", re.MULTILINE)
_CIPHER_LINE = re.compile(r"^\s*(TLS_[A-Z0-9_]+|SSL_[A-Z0-9_]+)\b", re.MULTILINE)
_NOT_AFTER = re.compile(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})")


def tls_protocols(script_output: str) -> list[str]:
    return _PROTOCOL_LINE.findall(script_output or "")


def tls_ciphers(script_output: str) -> list[str]:
    return _CIPHER_LINE.findall(script_output or "")


def cert_not_after(script_output: str) -> str | None:
    match = _NOT_AFTER.search(script_output or "")
    return match.group(1) if match else None
