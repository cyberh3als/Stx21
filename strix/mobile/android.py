"""Android static analysis: manifest and network-security-config rules.

Works on what an APK actually ships (binary manifest decoded in-process). It is
purely static: it reports configuration that is risky by the Android security
model, mapped to OWASP MASVS, and never executes the app.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from strix.mobile.axml import AxmlError, Node, decode, to_xml
from strix.mobile.findings import MobileFinding


if TYPE_CHECKING:
    from strix.mobile.archive import AppArchive


_LAUNCHER = ("android.intent.action.MAIN", "android.intent.category.LAUNCHER")
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
_DOCTYPE = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
LOW_TARGET_SDK = 28


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def _intent_filters(component: Node) -> list[Node]:
    return component.find_all("intent-filter")


def _is_launcher(component: Node) -> bool:
    for flt in _intent_filters(component):
        actions = {a.get("name") for a in flt.find_all("action")}
        categories = {c.get("name") for c in flt.find_all("category")}
        if _LAUNCHER[0] in actions and _LAUNCHER[1] in categories:
            return True
    return False


def _target_sdk(root: Node) -> int | None:
    for node in root.find_all("uses-sdk"):
        value = node.get("targetSdkVersion")
        if value and value.isdigit():
            return int(value)
    return None


def _component_exported(component: Node, target_sdk: int | None) -> bool:
    explicit = component.get("exported")
    if explicit is not None:
        return _truthy(explicit)
    # Before Android 12 (API 31) a component with an intent filter was exported by default.
    return bool(_intent_filters(component)) and (target_sdk is None or target_sdk < 31)


def analyze_manifest(root: Node) -> list[MobileFinding]:
    findings: list[MobileFinding] = []
    evidence = to_xml(root)
    apps = root.find_all("application")
    app = apps[0] if apps else Node("application")
    target_sdk = _target_sdk(root)

    if _truthy(app.get("debuggable")):
        findings.append(
            MobileFinding(
                rule="debuggable",
                title="Application is debuggable (android:debuggable=true)",
                severity="medium",
                cwe="CWE-489",
                description="The release manifest sets android:debuggable=true, letting anyone "
                "with device access attach a debugger, read app memory and run code in the "
                "app's context.",
                remediation="Remove android:debuggable or set it to false for release builds.",
                masvs="MASVS-RESILIENCE-4",
                location="AndroidManifest.xml <application>",
                evidence=evidence,
            )
        )
    allow_backup = app.get("allowBackup")
    if allow_backup is None or _truthy(allow_backup):
        findings.append(
            MobileFinding(
                rule="allow_backup",
                title="Application data can be backed up (android:allowBackup)",
                severity="low",
                cwe="CWE-530",
                description="allowBackup is enabled (explicitly, or by default because the "
                "attribute is absent), so app data can be extracted with `adb backup` or "
                "cloud backup.",
                remediation="Set android:allowBackup=false, or define backup rules that exclude "
                "sensitive data.",
                masvs="MASVS-STORAGE-2",
                location="AndroidManifest.xml <application>",
                evidence=evidence,
                notes=["Requires ADB/device access or the user's cloud backup."],
            )
        )
    if _truthy(app.get("usesCleartextTraffic")):
        findings.append(
            MobileFinding(
                rule="cleartext_traffic",
                title="Cleartext HTTP traffic permitted (usesCleartextTraffic=true)",
                severity="medium",
                cwe="CWE-319",
                description="The app opts in to cleartext network traffic, exposing data to "
                "interception on untrusted networks.",
                remediation="Set usesCleartextTraffic=false and use HTTPS for all endpoints.",
                masvs="MASVS-NETWORK-1",
                location="AndroidManifest.xml <application>",
                evidence=evidence,
            )
        )
    if target_sdk is not None and target_sdk < LOW_TARGET_SDK:
        findings.append(
            MobileFinding(
                rule="low_target_sdk",
                title=f"Outdated targetSdkVersion ({target_sdk})",
                severity="low",
                cwe=None,
                description=f"targetSdkVersion {target_sdk} opts the app out of platform security "
                f"behaviour introduced in API {LOW_TARGET_SDK}+ (e.g. cleartext and "
                "component-export defaults).",
                remediation="Raise targetSdkVersion to a current API level and re-test.",
                masvs="MASVS-PLATFORM-1",
                location="AndroidManifest.xml <uses-sdk>",
                evidence=evidence,
            )
        )

    for tag in _COMPONENT_TAGS:
        for component in root.find_all(tag):
            name = component.get("name") or "(unnamed)"
            if _is_launcher(component) or not _component_exported(component, target_sdk):
                continue
            if component.get("permission") or (
                tag == "provider" and component.get("readPermission")
            ):
                continue
            findings.append(
                MobileFinding(
                    rule=f"exported_component:{name}",
                    title=f"Exported {tag} without permission: {name}",
                    severity="medium",
                    cwe="CWE-926",
                    description=f"The {tag} {name} is exported and not protected by a "
                    "permission, so other apps on the device can invoke it.",
                    remediation="Set android:exported=false, or protect it with a signature-level "
                    "permission, and validate all incoming Intent data.",
                    masvs="MASVS-PLATFORM-1",
                    location=f"AndroidManifest.xml <{tag} {name}>",
                    evidence=evidence,
                    notes=[
                        "Exported does not prove exploitability: review what the component "
                        "does with caller-supplied data."
                    ],
                )
            )
    return findings


def analyze_network_security_config(xml_text: str) -> list[MobileFinding]:
    """Rules for a (decoded, plain-XML) res/xml network_security_config."""
    if not xml_text or _DOCTYPE.search(xml_text):
        return []
    import xml.etree.ElementTree as ET  # noqa: PLC0415  # DTDs rejected above

    try:
        root = ET.fromstring(xml_text)  # noqa: S314
    except ET.ParseError:
        return []
    findings: list[MobileFinding] = []
    base = root.find("base-config")
    if base is not None and (base.get("cleartextTrafficPermitted") or "").lower() == "true":
        findings.append(
            MobileFinding(
                rule="nsc_cleartext",
                title="Network security config permits cleartext traffic by default",
                severity="medium",
                cwe="CWE-319",
                description="base-config sets cleartextTrafficPermitted=true, so the whole app "
                "may use unencrypted HTTP.",
                remediation="Set cleartextTrafficPermitted=false in base-config and scope any "
                "exceptions to specific domains.",
                masvs="MASVS-NETWORK-1",
                location="res/xml/network_security_config.xml <base-config>",
                evidence=xml_text,
            )
        )
    anchors = [c for c in root.iter("certificates") if c.get("src") == "user"]
    in_debug = {id(c) for d in root.iter("debug-overrides") for c in d.iter("certificates")}
    if any(id(c) not in in_debug for c in anchors):
        findings.append(
            MobileFinding(
                rule="nsc_user_ca",
                title="Network security config trusts user-installed CAs",
                severity="medium",
                cwe="CWE-295",
                description="The app trusts user-added certificate authorities in release "
                "builds, making TLS interception by a user-installed CA possible.",
                remediation='Remove <certificates src="user"/> outside debug-overrides and '
                "consider certificate pinning.",
                masvs="MASVS-NETWORK-2",
                location="res/xml/network_security_config.xml <trust-anchors>",
                evidence=xml_text,
            )
        )
    return findings


def rules_in_manifest_evidence(evidence: str) -> set[str]:
    """Re-run the analyzers over decoded-XML evidence; used by the validator."""
    import xml.etree.ElementTree as ET  # noqa: PLC0415  # DTDs rejected below

    if not evidence or _DOCTYPE.search(evidence):
        return set()
    try:
        element = ET.fromstring(evidence)  # noqa: S314
    except ET.ParseError:
        return set()
    if element.tag == "network-security-config":
        return {f.rule for f in analyze_network_security_config(evidence)}
    return {f.rule for f in analyze_manifest(_from_element(element))}


def _from_element(element: Any) -> Node:
    node = Node(tag=element.tag)
    for key, value in element.attrib.items():
        node.attrs[key.replace("{http://schemas.android.com/apk/res/android}", "android:")] = value
    node.children = [_from_element(child) for child in element]
    return node


def analyze_apk(archive: AppArchive) -> tuple[dict[str, Any], list[MobileFinding]]:
    """Return ``(app_info, findings)`` for an APK."""
    raw = archive.read("AndroidManifest.xml")
    if raw is None:
        raise AxmlError("AndroidManifest.xml missing or too large")
    root = decode(raw)
    findings = analyze_manifest(root)
    permissions = sorted({p.get("name") or "" for p in root.find_all("uses-permission")} - {""})
    info = {
        "platform": "android",
        "package": root.attrs.get("package", ""),
        "target_sdk": _target_sdk(root),
        "permissions": permissions,
    }
    for name in archive.names():
        if name.startswith("res/xml/") and name.endswith(".xml"):
            data = archive.read(name, limit=1024 * 1024)
            if not data:
                continue
            try:
                nsc = decode(data)
            except AxmlError:
                continue
            if nsc.tag == "network-security-config":
                findings.extend(analyze_network_security_config(to_xml(nsc)))
    return info, findings
