"""CWE -> compliance framework mapping and per-run summaries."""

from __future__ import annotations

import re
from typing import Any

from strix.compliance.catalog import (
    ASSESSMENT_CONTROLS,
    ASSESSMENT_TITLES,
    CATEGORY_CONTROLS,
    CONTROL_TITLES,
    CWE_ASVS_REQUIREMENTS,
    FRAMEWORKS,
    TOP10_CWES,
    TOP10_TITLES,
)


__all__ = [
    "FRAMEWORKS",
    "map_cwe",
    "render_markdown",
    "summarize",
    "top10_category",
]

Controls = dict[str, list[dict[str, str]]]


def _cwe_number(cwe: object) -> int | None:
    match = re.search(r"\d+", str(cwe or ""))
    return int(match.group(0)) if match else None


def top10_category(cwe: object) -> str | None:
    number = _cwe_number(cwe)
    if number is None:
        return None
    return next((cat for cat, cwes in TOP10_CWES.items() if number in cwes), None)


def _control(framework: str, control_id: str) -> dict[str, str]:
    title = CONTROL_TITLES.get(framework, {}).get(control_id, "")
    return {"id": control_id, "title": title} if title else {"id": control_id}


def map_cwe(cwe: object) -> Controls:
    """Return ``{framework: [{id, title}, ...]}`` for a CWE, or ``{}`` if unmapped."""
    category = top10_category(cwe)
    if category is None:
        return {}
    controls: Controls = {
        "owasp_top10_2021": [{"id": category, "title": TOP10_TITLES[category]}],
    }
    for framework, ids in CATEGORY_CONTROLS[category].items():
        entries = [_control(framework, i) for i in ids]
        if framework == "owasp_asvs_4_0_3":
            number = _cwe_number(cwe)
            specific = CWE_ASVS_REQUIREMENTS.get(number, ()) if number is not None else ()
            entries = [_control(framework, i) for i in specific] + entries
        controls[framework] = entries
    return controls


def summarize(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate findings per framework control.

    Only controls with findings are reported. "Tested, no findings" rows need
    scan coverage data that is not yet recorded, so they are deliberately
    absent rather than guessed.
    """
    frameworks: dict[str, dict[str, Any]] = {}
    unmapped: list[dict[str, str]] = []
    for report in reports:
        controls = report.get("controls") or map_cwe(report.get("cwe"))
        if not controls:
            unmapped.append(
                {"id": str(report.get("id", "")), "title": str(report.get("title", ""))}
            )
            continue
        for framework, entries in controls.items():
            bucket = frameworks.setdefault(framework, {})
            for entry in entries:
                row = bucket.setdefault(
                    entry["id"], {"title": entry.get("title", ""), "findings": []}
                )
                row["findings"].append(
                    {
                        "id": report.get("id"),
                        "title": report.get("title"),
                        "severity": report.get("severity"),
                        "verification": (report.get("verification") or {}).get("status"),
                    }
                )
    assessment = {
        fw: [{"id": cid, "title": ASSESSMENT_TITLES.get(fw, {}).get(cid, "")} for cid in ids]
        for fw, ids in ASSESSMENT_CONTROLS.items()
    }
    return {
        "frameworks": {fw: FRAMEWORKS[fw] for fw in frameworks},
        "findings_by_control": frameworks,
        "assessment_evidence": assessment,
        "unmapped_findings": unmapped,
        "notes": [
            "Mappings are advisory and derived from CWE; not an attestation of compliance.",
            "Only controls with findings are listed; per-control 'tested, no findings' "
            "coverage is not recorded yet.",
        ],
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines = ["# Compliance Mapping\n"]
    lines.extend(f"> {note}" for note in summary.get("notes", []))
    lines.append("")
    by_control = summary.get("findings_by_control", {})
    for framework, name in summary.get("frameworks", {}).items():
        lines.append(f"## {name}\n")
        for control_id, row in sorted(by_control.get(framework, {}).items()):
            title = f" — {row['title']}" if row.get("title") else ""
            lines.append(f"### {control_id}{title}\n")
            for finding in row["findings"]:
                status = finding.get("verification")
                suffix = f" · {status.replace('_', ' ')}" if status else ""
                lines.append(
                    f"- `{finding.get('id')}` [{str(finding.get('severity')).upper()}] "
                    f"{finding.get('title')}{suffix}"
                )
            lines.append("")
    lines.append("## Assessment evidence\n")
    lines.append("This penetration test contributes evidence toward:\n")
    for framework, entries in summary.get("assessment_evidence", {}).items():
        for entry in entries:
            title = f" — {entry['title']}" if entry.get("title") else ""
            lines.append(f"- {FRAMEWORKS[framework]}: {entry['id']}{title}")
    unmapped = summary.get("unmapped_findings", [])
    if unmapped:
        lines.append("\n## Unmapped findings\n")
        lines.append("No CWE-based mapping (missing or unrecognised CWE):\n")
        lines.extend(f"- `{u['id']}` {u['title']}" for u in unmapped)
    return "\n".join(lines).rstrip() + "\n"
