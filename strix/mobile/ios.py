"""iOS static analysis: Info.plist rules (App Transport Security etc.)."""

from __future__ import annotations

import plistlib
import re
from typing import TYPE_CHECKING, Any

from strix.mobile.findings import MobileFinding


if TYPE_CHECKING:
    from strix.mobile.archive import AppArchive


_INFO_PLIST = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")


def parse_plist(data: bytes | str) -> dict[str, Any] | None:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    try:
        value = plistlib.loads(raw)
    except Exception:  # noqa: BLE001  # plistlib raises several parser-specific types
        return None
    return value if isinstance(value, dict) else None


def analyze_plist(plist: dict[str, Any], evidence: str) -> list[MobileFinding]:
    findings: list[MobileFinding] = []
    ats = plist.get("NSAppTransportSecurity")
    ats = ats if isinstance(ats, dict) else {}
    if ats.get("NSAllowsArbitraryLoads") is True:
        findings.append(
            MobileFinding(
                rule="ats_arbitrary_loads",
                title="App Transport Security disabled (NSAllowsArbitraryLoads)",
                severity="medium",
                cwe="CWE-319",
                description="NSAllowsArbitraryLoads=true turns off ATS app-wide, allowing "
                "cleartext HTTP and weak TLS.",
                remediation="Remove NSAllowsArbitraryLoads; add narrowly scoped exceptions per "
                "domain only where unavoidable.",
                masvs="MASVS-NETWORK-1",
                location="Info.plist NSAppTransportSecurity",
                evidence=evidence,
            )
        )
    domains = ats.get("NSExceptionDomains")
    for domain, settings in domains.items() if isinstance(domains, dict) else []:
        if (
            isinstance(settings, dict)
            and settings.get("NSExceptionAllowsInsecureHTTPLoads") is True
        ):
            findings.append(
                MobileFinding(
                    rule=f"ats_exception_http:{domain}",
                    title=f"ATS exception allows insecure HTTP for {domain}",
                    severity="low",
                    cwe="CWE-319",
                    description=f"{domain} is exempt from ATS and may be accessed over cleartext "
                    "HTTP.",
                    remediation="Serve the domain over HTTPS and remove the exception.",
                    masvs="MASVS-NETWORK-1",
                    location=f"Info.plist NSExceptionDomains/{domain}",
                    evidence=evidence,
                )
            )
    if plist.get("UIFileSharingEnabled") is True:
        findings.append(
            MobileFinding(
                rule="file_sharing",
                title="iTunes/Files file sharing enabled (UIFileSharingEnabled)",
                severity="low",
                cwe="CWE-538",
                description="The app's Documents directory is exposed through file sharing, so "
                "sensitive files stored there can be read from a connected computer.",
                remediation="Disable UIFileSharingEnabled or keep sensitive data out of Documents.",
                masvs="MASVS-STORAGE-2",
                location="Info.plist UIFileSharingEnabled",
                evidence=evidence,
            )
        )
    return findings


def plist_to_xml(plist: dict[str, Any]) -> str:
    return plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=True).decode("utf-8")


def rules_in_plist_evidence(evidence: str) -> set[str]:
    plist = parse_plist(evidence)
    return {f.rule for f in analyze_plist(plist, evidence)} if plist else set()


def analyze_ipa(archive: AppArchive) -> tuple[dict[str, Any], list[MobileFinding]]:
    name = next((n for n in archive.names() if _INFO_PLIST.match(n)), None)
    raw = archive.read(name) if name else None
    plist = parse_plist(raw) if raw else None
    if plist is None:
        raise ValueError("Payload/*.app/Info.plist missing or unreadable")
    info = {
        "platform": "ios",
        "package": str(plist.get("CFBundleIdentifier", "")),
        "target_sdk": None,
        "permissions": sorted(
            k for k in plist if k.startswith("NS") and k.endswith("UsageDescription")
        ),
    }
    return info, analyze_plist(plist, plist_to_xml(plist))
