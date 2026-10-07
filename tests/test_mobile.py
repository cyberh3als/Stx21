"""Tests for static mobile app assessment (APK/IPA)."""

from __future__ import annotations

import contextlib
import json
import plistlib
import random
import zipfile
from typing import TYPE_CHECKING, Any

import pytest

from strix.core.inputs import build_root_task, build_scope_context
from strix.interface.utils import infer_target_type, stage_mobile_apps
from strix.mobile import analyze_app, platform_for
from strix.mobile import archive as archive_mod
from strix.mobile.android import analyze_manifest, analyze_network_security_config
from strix.mobile.archive import AppArchive, ArchiveError
from strix.mobile.axml import AxmlError, decode, to_xml
from strix.mobile.ios import analyze_plist, parse_plist
from strix.mobile.secrets import mask, scan_bytes
from strix.report.state import ReportState, set_global_report_state
from strix.tools.mobile.tool import _resolve, run_analysis
from strix.validators import evaluate

from .axml_builder import build


if TYPE_CHECKING:
    from pathlib import Path

FAKE_AWS = "AKIAJ4Q7LMNB2XRT5WPD"  # made-up, not a real credential
FAKE_SLACK = "xoxb-518273649051-kqzwvfjdhrnx"


def _manifest(
    app_attrs: dict[str, Any] | None = None,
    components: list[Any] | None = None,
    target_sdk: int = 33,
) -> tuple[Any, ...]:
    return (
        "manifest",
        {"package": "com.example.demo"},
        [
            ("uses-sdk", {"android:minSdkVersion": 21, "android:targetSdkVersion": target_sdk}, []),
            ("uses-permission", {"android:name": "android.permission.INTERNET"}, []),
            ("application", dict(app_attrs or {}), list(components or [])),
        ],
    )


def _rules(tree: tuple[Any, ...]) -> set[str]:
    return {f.rule for f in analyze_manifest(decode(build(tree)))}


# --- AXML decoder --------------------------------------------------------------------


@pytest.mark.parametrize("utf8", [False, True])
def test_axml_roundtrip_both_string_encodings(utf8: bool) -> None:
    tree = _manifest({"android:debuggable": True, "android:label": "Démo ✓"})
    root = decode(build(tree, utf8=utf8))
    assert root.tag == "manifest"
    assert root.attrs["package"] == "com.example.demo"
    app = root.find_all("application")[0]
    assert app.get("debuggable") == "true"
    assert app.get("label") == "Démo ✓"
    assert root.find_all("uses-sdk")[0].get("targetSdkVersion") == "33"
    assert "xmlns:android" in to_xml(root)


def test_axml_resolves_attribute_names_from_resource_ids() -> None:
    tree = _manifest({"android:debuggable": True})
    root = decode(build(tree, strip_names=True))
    assert root.find_all("application")[0].get("debuggable") == "true"


def test_axml_rejects_malformed_input() -> None:
    good = build(_manifest())
    for bad in (b"", b"\x00" * 7, b"PK\x03\x04" + b"\x00" * 40, good[:30], good[: len(good) // 2]):
        with pytest.raises(AxmlError):
            decode(bad)
    rng = random.Random(1234)  # noqa: S311  # deterministic fuzz, not cryptography
    for _ in range(300):  # corrupt random bytes: must raise AxmlError or decode, never crash
        data = bytearray(good)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        with contextlib.suppress(AxmlError):
            decode(bytes(data))


# --- Android rules ---------------------------------------------------------------------


def test_manifest_flags_debuggable_backup_and_cleartext() -> None:
    rules = _rules(_manifest({"android:debuggable": True, "android:usesCleartextTraffic": True}))
    assert {"debuggable", "allow_backup", "cleartext_traffic"} <= rules
    safe = _rules(_manifest({"android:allowBackup": False, "android:debuggable": False}))
    assert not safe & {"debuggable", "allow_backup", "cleartext_traffic"}


def test_exported_components_logic() -> None:
    components = [
        (
            "activity",
            {"android:name": ".Main", "android:exported": True},
            [
                (
                    "intent-filter",
                    {},
                    [
                        ("action", {"android:name": "android.intent.action.MAIN"}, []),
                        ("category", {"android:name": "android.intent.category.LAUNCHER"}, []),
                    ],
                )
            ],
        ),
        ("service", {"android:name": ".Open", "android:exported": True}, []),
        (
            "receiver",
            {
                "android:name": ".Guarded",
                "android:exported": True,
                "android:permission": "com.example.SIGNATURE",
            },
            [],
        ),
        ("activity", {"android:name": ".Private", "android:exported": False}, []),
        ("provider", {"android:name": ".Files", "android:exported": True}, []),
    ]
    rules = _rules(_manifest({}, components))
    assert "exported_component:.Open" in rules
    assert "exported_component:.Files" in rules
    assert "exported_component:.Main" not in rules  # launcher
    assert "exported_component:.Guarded" not in rules  # permission-protected
    assert "exported_component:.Private" not in rules


def test_implicit_export_depends_on_target_sdk() -> None:
    receiver = (
        "receiver",
        {"android:name": ".Implicit"},
        [("intent-filter", {}, [("action", {"android:name": "x.ACTION"}, [])])],
    )
    assert "exported_component:.Implicit" in _rules(_manifest({}, [receiver], target_sdk=30))
    assert "exported_component:.Implicit" not in _rules(_manifest({}, [receiver], target_sdk=33))
    assert "low_target_sdk" in _rules(_manifest({}, [], target_sdk=26))


def test_network_security_config_rules() -> None:
    risky = """<network-security-config>
      <base-config cleartextTrafficPermitted="true">
        <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
      </base-config></network-security-config>"""
    assert {f.rule for f in analyze_network_security_config(risky)} == {
        "nsc_cleartext",
        "nsc_user_ca",
    }
    debug_only = """<network-security-config><base-config cleartextTrafficPermitted="false"/>
      <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
      </network-security-config>"""
    assert analyze_network_security_config(debug_only) == []
    assert analyze_network_security_config('<!DOCTYPE x [<!ENTITY e "y">]><a/>') == []
    assert analyze_network_security_config("not xml") == []


# --- iOS ----------------------------------------------------------------------------------


def test_ios_plist_rules_for_xml_and_binary_plists() -> None:
    data = {
        "CFBundleIdentifier": "com.example.demo",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {"legacy.example": {"NSExceptionAllowsInsecureHTTPLoads": True}},
        },
        "UIFileSharingEnabled": True,
    }
    for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
        parsed = parse_plist(plistlib.dumps(data, fmt=fmt))
        assert parsed is not None
        rules = {f.rule for f in analyze_plist(parsed, "x")}
        assert rules == {"ats_arbitrary_loads", "ats_exception_http:legacy.example", "file_sharing"}
    assert parse_plist(b"garbage") is None


# --- secrets --------------------------------------------------------------------------------


def test_secret_detection_filters_placeholders_and_masks() -> None:
    blob = (
        f"api_key={FAKE_AWS};".encode()
        + b" AKIAIOSFODNN7EXAMPLE "
        + f' "{FAKE_SLACK}" '.encode()
        + b"-----BEGIN RSA PRIVATE KEY----- "
        + b"sk_live_YOUR_KEY_HERE_xxxxxxxxxxxxxxxxxxxx"
    )
    hits = {h.rule: h for h in scan_bytes(blob)}
    assert set(hits) == {"secret_aws_access_key_id", "secret_slack_token", "secret_private_key"}
    assert mask(FAKE_AWS).startswith("AKIA") and FAKE_AWS not in mask(FAKE_AWS)
    assert FAKE_AWS in hits["secret_aws_access_key_id"].context


# --- archives ---------------------------------------------------------------------------------


def _write_apk(
    path: Path, manifest: tuple[Any, ...], extra: dict[str, bytes] | None = None
) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", build(manifest))
        for name, data in (extra or {}).items():
            z.writestr(name, data)


def test_archive_rejects_non_zip_and_enforces_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bogus = tmp_path / "x.apk"
    bogus.write_bytes(b"not a zip")
    with pytest.raises(ArchiveError):
        AppArchive(bogus)
    with pytest.raises(ArchiveError):
        AppArchive(tmp_path / "missing.apk")

    apk = tmp_path / "a.apk"
    _write_apk(apk, _manifest(), {"big.bin": b"x" * 5000})
    with AppArchive(apk) as archive:
        assert archive.read("big.bin", limit=100) is None
        assert archive.read("big.bin") is not None
        assert archive.read("nope") is None
    monkeypatch.setattr(archive_mod, "MAX_MEMBERS", 1)
    with pytest.raises(ArchiveError):
        AppArchive(apk)


def test_zip_slip_names_are_never_extracted(tmp_path: Path) -> None:
    apk = tmp_path / "evil.apk"
    _write_apk(apk, _manifest(), {"../../escape.txt": b"boom"})
    analyze_app(str(apk))
    assert not (tmp_path.parent / "escape.txt").exists()


def test_analyze_apk_end_to_end_with_validated_candidates(tmp_path: Path) -> None:
    nsc = build(
        ("network-security-config", {}, [("base-config", {"cleartextTrafficPermitted": True}, [])])
    )
    apk = tmp_path / "demo.apk"
    _write_apk(
        apk,
        _manifest({"android:debuggable": True}),
        {"res/xml/network_security_config.xml": nsc, "classes.dex": f"x{FAKE_AWS}y".encode()},
    )
    result = analyze_app(str(apk))
    assert result["app"]["package"] == "com.example.demo"
    assert result["app"]["permissions"] == ["android.permission.INTERNET"]
    rules = {c["rule"] for c in result["candidates"]}
    assert {"debuggable", "allow_backup", "nsc_cleartext", "secret_aws_access_key_id"} <= rules
    for candidate in result["candidates"]:
        verdict = evaluate(candidate["validation"], candidate["cwe"])
        assert verdict["status"] == "verified", (candidate["rule"], verdict)
    secret = next(c for c in result["candidates"] if c["rule"].startswith("secret_"))
    assert FAKE_AWS not in secret["title"]  # masked in anything that reaches the report title


def test_analyze_ipa_end_to_end(tmp_path: Path) -> None:
    ipa = tmp_path / "demo.ipa"
    plist = {
        "CFBundleIdentifier": "com.example.ios",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "NSCameraUsageDescription": "photos",
    }
    with zipfile.ZipFile(ipa, "w") as z:
        z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(plist, fmt=plistlib.FMT_BINARY))
        z.writestr("Payload/Demo.app/config.json", f'{{"k": "{FAKE_SLACK}"}}')
    result = analyze_app(str(ipa))
    assert result["app"]["package"] == "com.example.ios"
    assert {c["rule"] for c in result["candidates"]} == {
        "ats_arbitrary_loads",
        "secret_slack_token",
    }
    for candidate in result["candidates"]:
        assert evaluate(candidate["validation"], candidate["cwe"])["status"] == "verified"


def test_unsupported_and_broken_apps_raise(tmp_path: Path) -> None:
    assert platform_for("a.APK") == "android"
    assert platform_for("a.zip") is None
    with pytest.raises(ValueError, match=r"only \.apk and \.ipa"):
        analyze_app("a.zip")
    no_manifest = tmp_path / "n.apk"
    with zipfile.ZipFile(no_manifest, "w") as z:
        z.writestr("x.txt", "hi")
    with pytest.raises(AxmlError):
        analyze_app(str(no_manifest))


# --- validators reject hallucinated evidence ----------------------------------------------------


def test_validators_reject_claims_the_evidence_does_not_support() -> None:
    clean = to_xml(decode(build(_manifest({"android:allowBackup": False}))))
    claim = {
        "type": "mobile_manifest",
        "platform": "android",
        "rule": "debuggable",
        "evidence": clean,
    }
    assert evaluate(claim, None)["status"] == "unverified"
    assert evaluate({**claim, "platform": "windows"}, None)["status"] == "unverified"
    assert evaluate({**claim, "evidence": "<<<not xml"}, None)["status"] == "unverified"
    placeholder = {
        "type": "mobile_secret",
        "rule": "secret_aws_access_key_id",
        "evidence": "k=AKIAIOSFODNN7EXAMPLE",
    }
    assert evaluate(placeholder, None)["status"] == "unverified"
    wrong_rule = {
        "type": "mobile_secret",
        "rule": "secret_slack_token",
        "evidence": f"k={FAKE_AWS}",
    }
    assert evaluate(wrong_rule, None)["status"] == "unverified"
    assert (
        evaluate({"type": "mobile_secret", "rule": "", "evidence": ""}, None)["status"]
        == "unverified"
    )


# --- target + tool wiring ---------------------------------------------------------------------------  # noqa: E501


def test_apk_and_ipa_targets_are_inferred(tmp_path: Path) -> None:
    apk, ipa, aab = tmp_path / "a.apk", tmp_path / "b.ipa", tmp_path / "c.aab"
    for f in (apk, ipa, aab):
        f.write_bytes(b"PK")
    assert infer_target_type(str(apk)) == (
        "mobile_app",
        {"target_app": str(apk.resolve()), "platform": "android"},
    )
    assert infer_target_type(str(ipa))[1]["platform"] == "ios"
    with pytest.raises(ValueError, match="aab"):
        infer_target_type(str(aab))


def test_apps_are_staged_rendered_and_authorized(tmp_path: Path) -> None:
    src = tmp_path / "demo.apk"
    src.write_bytes(b"PK")
    targets = [
        {
            "type": "mobile_app",
            "details": {"target_app": str(src), "platform": "android"},
            "original": str(src),
        }
    ]
    sources = stage_mobile_apps(targets, "run-mobile-test")
    assert sources[0]["workspace_subdir"] == "mobile-apps"
    assert targets[0]["details"]["workspace_path"] == "/workspace/mobile-apps/demo.apk"
    config = {"targets": targets}
    task = build_root_task(config)
    assert "/workspace/mobile-apps/demo.apk" in task
    assert "analyze_mobile_app" in task
    assert "NOT in scope" in task
    assert str(src) in json.dumps(build_scope_context(config))


async def test_tool_only_opens_declared_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    apk = tmp_path / "demo.apk"
    _write_apk(apk, _manifest({"android:debuggable": True}))
    secret_file = tmp_path / "other.apk"
    _write_apk(secret_file, _manifest())
    state = ReportState(run_name="mobile-tool")
    state.set_scan_config(
        {
            "targets": [
                {
                    "type": "mobile_app",
                    "details": {"target_app": str(apk), "platform": "android"},
                    "original": str(apk),
                }
            ]
        }
    )
    set_global_report_state(state)

    ok = json.loads(await run_analysis(""))
    assert ok["success"] is True
    assert ok["app"]["package"] == "com.example.demo"

    by_name = json.loads(await run_analysis("demo.apk"))
    assert by_name["success"] is True
    # an undeclared file on the host cannot be opened, whatever path is supplied
    for attempt in (str(secret_file), "../other.apk", "/etc/passwd"):
        refused = json.loads(await run_analysis(attempt))
        assert refused["success"] is False
        assert "Unknown app" in refused["error"]

    set_global_report_state(ReportState(run_name="empty"))
    none = json.loads(await run_analysis(""))
    assert none["success"] is False


def test_resolve_requires_a_name_when_several_apps() -> None:
    targets = [
        {"type": "mobile_app", "details": {"target_app": "/a/one.apk"}, "original": "/a/one.apk"},
        {"type": "mobile_app", "details": {"target_app": "/b/two.apk"}, "original": "/b/two.apk"},
    ]
    assert _resolve("", targets) is None
    assert _resolve("two.apk", targets) is targets[1]
    assert _resolve("TWO.APK", targets) is targets[1]
