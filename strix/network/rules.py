"""Exposure and TLS rules: turn parsed scanner output into finding candidates.

This engine is assessment-only. It classifies what scanners already observed
(reachable services, TLS configuration, template matches); it does not probe,
guess credentials, or exploit anything. Severities are deliberately
conservative: a reachable port proves exposure, not an authentication failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from strix.network.model import Candidate, NucleiRecord, Service
from strix.network.parsers import cert_not_after, tls_ciphers, tls_protocols


if TYPE_CHECKING:
    from strix.network.scope import NetworkScope


@dataclass(frozen=True)
class ExposureRule:
    title: str
    severity: str
    cwe: str
    why: str
    fix: str


# Services that should not be reachable from untrusted networks. Matching is by
# port (IANA/de-facto defaults) and confirmed against the detected service name
# where nmap provided one.
EXPOSURE_RULES: dict[int, ExposureRule] = {
    21: ExposureRule(
        "FTP service exposed (cleartext)",
        "medium",
        "CWE-319",
        "FTP transmits credentials and data unencrypted.",
        "Disable FTP or replace it with SFTP/FTPS and restrict by source IP.",
    ),
    23: ExposureRule(
        "Telnet service exposed (cleartext)",
        "high",
        "CWE-319",
        "Telnet transmits credentials and sessions unencrypted.",
        "Disable Telnet; use SSH restricted to trusted sources.",
    ),
    111: ExposureRule(
        "RPC portmapper exposed",
        "medium",
        "CWE-668",
        "The portmapper discloses registered RPC services.",
        "Block port 111 at the perimeter.",
    ),
    135: ExposureRule(
        "Microsoft RPC endpoint mapper exposed",
        "medium",
        "CWE-668",
        "MS-RPC should not be reachable from untrusted networks.",
        "Block TCP/135 at the perimeter.",
    ),
    139: ExposureRule(
        "NetBIOS session service exposed",
        "medium",
        "CWE-668",
        "NetBIOS exposes host and share information.",
        "Block NetBIOS ports at the perimeter.",
    ),
    445: ExposureRule(
        "SMB service exposed",
        "high",
        "CWE-668",
        "SMB exposed to untrusted networks is a primary lateral-movement and "
        "ransomware entry point.",
        "Block TCP/445 at the perimeter; restrict to internal segments.",
    ),
    1433: ExposureRule(
        "Microsoft SQL Server exposed",
        "medium",
        "CWE-668",
        "Database listeners should not be reachable from untrusted networks.",
        "Restrict to application subnets or require a private network/VPN.",
    ),
    1521: ExposureRule(
        "Oracle database listener exposed",
        "medium",
        "CWE-668",
        "Database listeners should not be reachable from untrusted networks.",
        "Restrict to application subnets or require a private network/VPN.",
    ),
    2049: ExposureRule(
        "NFS service exposed",
        "high",
        "CWE-668",
        "NFS exports may be mountable by untrusted hosts.",
        "Block NFS at the perimeter and restrict exports by host.",
    ),
    2375: ExposureRule(
        "Docker Engine API exposed (unencrypted)",
        "high",
        "CWE-668",
        "The Docker API on 2375 is unencrypted and is typically unauthenticated, "
        "which allows host takeover. Authentication was not verified.",
        "Do not expose the Docker API; use a TLS-authenticated socket on a private network.",
    ),
    2379: ExposureRule(
        "etcd client API exposed",
        "high",
        "CWE-668",
        "etcd stores cluster secrets and configuration. Authentication was not verified.",
        "Restrict etcd to the control plane and require client certificates.",
    ),
    3306: ExposureRule(
        "MySQL/MariaDB exposed",
        "medium",
        "CWE-668",
        "Database listeners should not be reachable from untrusted networks.",
        "Restrict to application subnets or require a private network/VPN.",
    ),
    3389: ExposureRule(
        "Remote Desktop (RDP) exposed",
        "high",
        "CWE-668",
        "RDP on the internet is a common brute-force and exploit target.",
        "Place RDP behind a VPN or gateway with MFA and network-level auth.",
    ),
    5432: ExposureRule(
        "PostgreSQL exposed",
        "medium",
        "CWE-668",
        "Database listeners should not be reachable from untrusted networks.",
        "Restrict to application subnets or require a private network/VPN.",
    ),
    5900: ExposureRule(
        "VNC exposed",
        "high",
        "CWE-668",
        "VNC often has weak or no authentication and weak encryption.",
        "Place VNC behind a VPN; require strong authentication.",
    ),
    5985: ExposureRule(
        "WinRM (HTTP) exposed",
        "medium",
        "CWE-319",
        "WinRM over HTTP exposes a remote management interface.",
        "Restrict WinRM to management networks; prefer HTTPS.",
    ),
    6379: ExposureRule(
        "Redis exposed",
        "high",
        "CWE-668",
        "Redis defaults to no authentication; exposure commonly leads to data "
        "loss and code execution. Authentication was not verified.",
        "Bind to localhost/private network, enable ACLs/auth and TLS.",
    ),
    9200: ExposureRule(
        "Elasticsearch HTTP API exposed",
        "high",
        "CWE-668",
        "Elasticsearch clusters exposed publicly frequently leak data. "
        "Authentication was not verified.",
        "Restrict to private networks and enable security/authentication.",
    ),
    10250: ExposureRule(
        "Kubelet API exposed",
        "high",
        "CWE-668",
        "An exposed kubelet can allow pod exec and node access if anonymous "
        "auth is enabled. Authentication was not verified.",
        "Restrict to the control plane and disable anonymous auth.",
    ),
    11211: ExposureRule(
        "Memcached exposed",
        "high",
        "CWE-668",
        "Memcached has no authentication by default and is abused for amplification.",
        "Bind to localhost/private network and disable UDP.",
    ),
    27017: ExposureRule(
        "MongoDB exposed",
        "high",
        "CWE-668",
        "MongoDB exposed publicly is frequently unauthenticated. Authentication was not verified.",
        "Restrict to private networks and enable authentication.",
    ),
}

_WEAK_PROTOCOLS = {
    "SSLv2": ("high", "CWE-326"),
    "SSLv3": ("high", "CWE-326"),
    "TLSv1.0": ("medium", "CWE-326"),
    "TLSv1.1": ("medium", "CWE-326"),
}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "_DES_", "NULL", "EXPORT", "ANON", "_MD5", "RC2", "IDEA")
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_REPORTABLE_NUCLEI = {"critical", "high", "medium"}


def weak_ciphers(ciphers: list[str]) -> list[str]:
    return sorted({c for c in ciphers if any(m in c for m in WEAK_CIPHER_MARKERS)})


def _exposure_candidates(services: list[Service]) -> list[Candidate]:
    out: list[Candidate] = []
    for svc in services:
        rule = EXPOSURE_RULES.get(svc.port)
        if rule is None or svc.protocol != "tcp":
            continue
        out.append(
            Candidate(
                title=f"{rule.title} on {svc.host}:{svc.port}",
                severity=rule.severity,
                cwe=rule.cwe,
                host=svc.host,
                port=svc.port,
                summary=(
                    f"{svc.host}:{svc.port}/tcp is open ({svc.label or 'unidentified'}). {rule.why}"
                ),
                remediation=rule.fix,
                validation={
                    "type": "exposed_service",
                    "host": svc.host,
                    "port": svc.port,
                    "evidence": svc.raw,
                },
            )
        )
    return out


def _tls_candidates(services: list[Service], now: datetime) -> list[Candidate]:
    out: list[Candidate] = []
    for svc in services:
        enum = svc.scripts.get("ssl-enum-ciphers", "")
        cert = svc.scripts.get("ssl-cert", "")
        for proto in tls_protocols(enum):
            if proto not in _WEAK_PROTOCOLS:
                continue
            severity, cwe = _WEAK_PROTOCOLS[proto]
            out.append(
                Candidate(
                    title=f"Deprecated protocol {proto} enabled on {svc.host}:{svc.port}",
                    severity=severity,
                    cwe=cwe,
                    host=svc.host,
                    port=svc.port,
                    summary=f"{svc.host}:{svc.port} accepts {proto}, which is deprecated and "
                    "fails PCI DSS and modern baseline requirements.",
                    remediation="Disable SSLv2/SSLv3/TLS 1.0/TLS 1.1 and allow TLS 1.2+ only.",
                    validation={
                        "type": "tls_weakness",
                        "host": svc.host,
                        "port": svc.port,
                        "weakness": proto,
                        "evidence": enum,
                    },
                )
            )
        weak = weak_ciphers(tls_ciphers(enum))
        if weak:
            out.append(
                Candidate(
                    title=f"Weak TLS cipher suites enabled on {svc.host}:{svc.port}",
                    severity="medium",
                    cwe="CWE-327",
                    host=svc.host,
                    port=svc.port,
                    summary=(
                        f"{svc.host}:{svc.port} offers weak cipher suites: {', '.join(weak[:5])}."
                    ),
                    remediation=(
                        "Remove RC4, 3DES, DES, NULL, EXPORT, anonymous and MD5-based suites."
                    ),
                    validation={
                        "type": "tls_weakness",
                        "host": svc.host,
                        "port": svc.port,
                        "weakness": "weak_cipher",
                        "evidence": enum,
                    },
                )
            )
        expiry = cert_not_after(cert)
        if expiry and datetime.fromisoformat(expiry).replace(tzinfo=UTC) < now:
            out.append(
                Candidate(
                    title=f"Expired TLS certificate on {svc.host}:{svc.port}",
                    severity="medium",
                    cwe="CWE-298",
                    host=svc.host,
                    port=svc.port,
                    summary=(
                        f"The certificate presented by {svc.host}:{svc.port} expired on {expiry}."
                    ),
                    remediation="Renew the certificate and automate renewal and expiry monitoring.",
                    validation={
                        "type": "tls_weakness",
                        "host": svc.host,
                        "port": svc.port,
                        "weakness": "cert_expired",
                        "evidence": cert,
                    },
                )
            )
    return out


def _nuclei_candidates(records: list[NucleiRecord]) -> list[Candidate]:
    out: list[Candidate] = []
    for rec in records:
        if rec.severity not in _REPORTABLE_NUCLEI and not rec.cves:
            continue
        out.append(
            Candidate(
                title=f"{rec.name} ({rec.template_id}) on {rec.host}",
                severity=rec.severity if rec.severity in _SEVERITY_ORDER else "info",
                cwe=rec.cwes[0] if rec.cwes else None,
                cve=rec.cves[0] if rec.cves else None,
                host=rec.host,
                port=None,
                summary=f"nuclei template {rec.template_id} matched at {rec.matched_at}.",
                remediation=(
                    "Apply the vendor patch or mitigation for the matched issue and re-scan."
                ),
                notes=[
                    "Template matches can be false positives: confirm with the matched evidence "
                    "before reporting."
                ],
                validation={
                    "type": "nuclei_match",
                    "template_id": rec.template_id,
                    "host": rec.host,
                    "evidence": rec.raw,
                },
            )
        )
    return out


def assess(
    services: list[Service],
    nuclei: list[NucleiRecord],
    scope: NetworkScope,
    *,
    now: datetime | None = None,
) -> tuple[list[Candidate], list[str]]:
    """Return ``(candidates, out_of_scope_hosts)``; out-of-scope data is dropped."""
    now = now or datetime.now(UTC)
    # A hostname resolved to an in-scope IP anywhere in the output counts as in scope.
    known_ips = {s.host: s.ip for s in services if s.ip} | {r.host: r.ip for r in nuclei if r.ip}

    def in_scope(host: str, ip: str) -> bool:
        return scope.contains(host, ip or known_ips.get(host, ""))

    in_scope_services = [s for s in services if in_scope(s.host, s.ip)]
    in_scope_nuclei = [r for r in nuclei if in_scope(r.host, r.ip)]
    dropped = sorted(
        {s.host for s in services if not in_scope(s.host, s.ip)}
        | {r.host for r in nuclei if not in_scope(r.host, r.ip)}
    )
    candidates = (
        _exposure_candidates(in_scope_services)
        + _tls_candidates(in_scope_services, now)
        + _nuclei_candidates(in_scope_nuclei)
    )
    candidates.sort(key=lambda c: (_SEVERITY_ORDER.get(c.severity, 5), c.host, c.port or 0))
    return candidates, dropped
