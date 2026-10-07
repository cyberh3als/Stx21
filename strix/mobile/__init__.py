"""Static mobile app assessment (Android APK/AAB-manifest and iOS IPA)."""

from __future__ import annotations

from typing import Any

from strix.mobile.android import analyze_apk
from strix.mobile.archive import AppArchive
from strix.mobile.ios import analyze_ipa
from strix.mobile.secrets import scan_archive


PLATFORM_SUFFIXES = {".apk": "android", ".ipa": "ios"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def platform_for(path: str) -> str | None:
    lowered = path.lower()
    return next((p for suffix, p in PLATFORM_SUFFIXES.items() if lowered.endswith(suffix)), None)


def analyze_app(path: str) -> dict[str, Any]:
    """Analyse an APK or IPA and return app info plus finding candidates."""
    platform = platform_for(path)
    if platform is None:
        raise ValueError("only .apk and .ipa files are supported")
    with AppArchive(path) as archive:
        info, findings = analyze_apk(archive) if platform == "android" else analyze_ipa(archive)
        findings = findings + scan_archive(archive)
    subject = info.get("package") or path
    candidates = [f.to_candidate(platform, str(subject)) for f in findings]
    candidates.sort(key=lambda c: (_SEVERITY_ORDER.get(c["severity"], 5), c["title"]))
    return {"app": info, "candidates": candidates}
