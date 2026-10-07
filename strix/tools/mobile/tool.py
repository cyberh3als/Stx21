"""Mobile assessment tool: static analysis of an in-scope APK/IPA target."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.mobile import analyze_app
from strix.mobile.archive import ArchiveError
from strix.mobile.axml import AxmlError
from strix.report.state import get_global_report_state


logger = logging.getLogger(__name__)


def _mobile_targets() -> list[dict[str, Any]]:
    state = get_global_report_state()
    targets = (state.run_record.get("targets_info") if state else None) or []
    return [t for t in targets if t.get("type") == "mobile_app"]


def _resolve(app: str, targets: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick a declared mobile target. Arbitrary paths are never accepted."""
    wanted = app.strip().lower()
    if not wanted:
        return targets[0] if len(targets) == 1 else None
    for target in targets:
        details = target.get("details") or {}
        names = {
            str(target.get("original", "")).lower(),
            Path(str(details.get("target_app", ""))).name.lower(),
            str(details.get("workspace_path", "")).lower(),
        }
        if wanted in names:
            return target
    return None


async def run_analysis(app: str) -> str:
    """Analyse a declared mobile target; arbitrary paths are never accepted."""
    targets = _mobile_targets()
    if not targets:
        return json.dumps({"success": False, "error": "No mobile app (.apk/.ipa) in scope."})
    target = _resolve(app, targets)
    if target is None:
        names = [str(t.get("original", "")) for t in targets]
        return json.dumps({"success": False, "error": f"Unknown app '{app}'. Available: {names}"})
    path = str((target.get("details") or {}).get("target_app", ""))
    try:
        result = await asyncio.to_thread(analyze_app, path)
    except (ArchiveError, AxmlError, ValueError) as exc:
        return json.dumps({"success": False, "error": str(exc)})
    return json.dumps({"success": True, **result}, ensure_ascii=False)


@function_tool(timeout=300, strict_mode=False)
async def analyze_mobile_app(ctx: RunContextWrapper, app: str = "") -> str:
    """Statically analyse an in-scope mobile app (APK or IPA) and return finding candidates.

    ``app`` is the file name of one of the scan's mobile targets (optional when
    there is exactly one). Only apps the user declared as targets can be
    analysed. The analysis is read-only and never executes the app; it
    decodes the manifest / Info.plist, checks Android components, network
    security configuration and iOS App Transport Security, and scans the
    package for hard-coded provider secrets.

    Each candidate has a ready-made ``validation`` object: file it with
    ``create_vulnerability_report`` passing that object unchanged, so a
    deterministic validator re-checks the evidence. Report secrets using the
    masked value only. Backends or URLs you discover inside the app are NOT
    automatically in scope; test only hosts that are in the authorized targets.
    """
    return await run_analysis(app)
