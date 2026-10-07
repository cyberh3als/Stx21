"""Build a real, binary-correct APK and score the mobile engine against it.

A genuinely compiled third-party APK can't be fetched here: this environment
has no general internet egress (only the GitHub API for attached repos), so
there is no sanctioned source to download one from. Instead this builds a real
zip containing a real Android binary-XML manifest (via the same encoder the
unit tests use, built from the public AOSP ResourceTypes format) — the
archive/zip handling and the AXML decoder are exercised exactly as they would
be on a real APK; only the "was this app written by a real developer" part is
necessarily substituted.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from benchmarks.harness.ground_truth import GroundTruthFinding, ProbeResult
from benchmarks.harness.scoring import Scorecard
from strix.mobile import analyze_app
from strix.validators import evaluate
from tests.axml_builder import build as build_axml


_MANIFEST: tuple[Any, ...] = (
    "manifest",
    {"package": "bench.vulnerable.app"},
    [
        ("uses-sdk", {"android:minSdkVersion": 21, "android:targetSdkVersion": 24}, []),
        (
            "application",
            {"android:debuggable": True, "android:usesCleartextTraffic": True},
            [
                (
                    "activity",
                    {"android:name": ".Main", "android:exported": True},
                    [
                        (
                            "intent-filter",
                            {},
                            [
                                ("action", {"android:name": "android.intent.action.MAIN"}, []),
                                (
                                    "category",
                                    {"android:name": "android.intent.category.LAUNCHER"},
                                    [],
                                ),
                            ],
                        )
                    ],
                ),
                ("service", {"android:name": ".Background", "android:exported": True}, []),
                (
                    "receiver",
                    {
                        "android:name": ".Guarded",
                        "android:exported": True,
                        "android:permission": "bench.SIGNATURE",
                    },
                    [],
                ),
            ],
        ),
    ],
)
_AWS_KEY = "AKIAVKQ7X4B2PL9M3RST"  # made up, not a real credential
_SECRET_FILE = f'String key = "{_AWS_KEY}";'.encode()


def _build_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", build_axml(_MANIFEST))
        z.writestr("classes.dex", _SECRET_FILE)


GROUND_TRUTH: list[GroundTruthFinding] = [
    GroundTruthFinding(
        "apk_debuggable", "CWE-489", expect_vulnerable=True, detail="android:debuggable=true"
    ),
    GroundTruthFinding(
        "apk_cleartext_traffic",
        "CWE-319",
        expect_vulnerable=True,
        detail="usesCleartextTraffic=true",
    ),
    GroundTruthFinding(
        "apk_exported_service_no_permission",
        "CWE-926",
        expect_vulnerable=True,
        detail=".Background exported, unguarded",
    ),
    GroundTruthFinding(
        "apk_launcher_not_flagged",
        "CWE-926",
        expect_vulnerable=False,
        detail=".Main is the launcher activity",
    ),
    GroundTruthFinding(
        "apk_permission_guarded_not_flagged",
        "CWE-926",
        expect_vulnerable=False,
        detail=".Guarded requires a permission",
    ),
    GroundTruthFinding(
        "apk_embedded_aws_key",
        "CWE-798",
        expect_vulnerable=True,
        detail="AWS key literal in classes.dex",
    ),
]


def run() -> Scorecard:
    with TemporaryDirectory() as tmp:
        apk_path = Path(tmp) / "bench.apk"
        _build_apk(apk_path)
        analysis = analyze_app(str(apk_path))

    rules_present = {c["rule"] for c in analysis["candidates"]}
    by_rule = {c["rule"]: c for c in analysis["candidates"]}
    expect_rule = {
        "apk_debuggable": "debuggable",
        "apk_cleartext_traffic": "cleartext_traffic",
        "apk_exported_service_no_permission": "exported_component:.Background",
        "apk_embedded_aws_key": "secret_aws_access_key_id",
    }

    results = []
    for gt in GROUND_TRUTH:
        if gt.name in expect_rule:
            rule = expect_rule[gt.name]
            candidate = by_rule.get(rule)
            if candidate:
                status = evaluate(candidate["validation"], candidate["cwe"])["status"]
            else:
                status = "unverified"
            results.append(ProbeResult(gt, status, f"rule={rule} present={rule in rules_present}"))
        elif gt.name == "apk_launcher_not_flagged":
            flagged = "exported_component:.Main" in rules_present
            results.append(ProbeResult(gt, "verified" if flagged else "unverified"))
        else:  # apk_permission_guarded_not_flagged
            flagged = "exported_component:.Guarded" in rules_present
            results.append(ProbeResult(gt, "verified" if flagged else "unverified"))
    return Scorecard("Mobile engine (real zip/AXML binary; synthetic manifest content)", results)
