"""Tests for CWE -> compliance framework mapping."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from strix.compliance import map_cwe, render_markdown, summarize, top10_category
from strix.compliance.catalog import CATEGORY_CONTROLS, CONTROL_TITLES, TOP10_CWES, TOP10_TITLES
from strix.report.sarif import build_sarif_report
from strix.report.state import ReportState
from strix.report.writer import render_vulnerability_md


if TYPE_CHECKING:
    from pathlib import Path


def _ids(controls: dict, framework: str) -> list[str]:
    return [c["id"] for c in controls[framework]]


def test_cwe_resolves_to_top10_category_in_any_format() -> None:
    for form in ("CWE-79", "cwe: 79", "79", 79):
        assert top10_category(form) == "A03:2021"
    assert top10_category("CWE-918") == "A10:2021"
    assert top10_category("CWE-639") == "A01:2021"
    assert top10_category("CWE-9999999") is None
    assert top10_category(None) is None


def test_specific_asvs_requirement_precedes_chapter() -> None:
    controls = map_cwe("CWE-89")
    assert _ids(controls, "owasp_asvs_4_0_3") == ["5.3.4", "V5"]
    assert _ids(controls, "owasp_top10_2021") == ["A03:2021"]
    assert "SI-10" in _ids(controls, "nist_800_53_r5")
    assert "6.2.4" in _ids(controls, "pci_dss_4_0")


def test_unmapped_cwe_returns_empty() -> None:
    assert map_cwe("CWE-9999999") == {}
    assert map_cwe("") == {}


def test_catalog_is_internally_consistent() -> None:
    assert set(TOP10_CWES) == set(TOP10_TITLES) == set(CATEGORY_CONTROLS)
    seen: dict[int, str] = {}
    for category, cwes in TOP10_CWES.items():
        for cwe in cwes:
            assert cwe not in seen, f"CWE-{cwe} in both {seen[cwe]} and {category}"
            seen[cwe] = category
    for controls in CATEGORY_CONTROLS.values():
        for framework, ids in controls.items():
            for control_id in ids:
                assert control_id in CONTROL_TITLES[framework], (framework, control_id)


def test_summary_groups_findings_and_lists_unmapped() -> None:
    reports = [
        {
            "id": "vuln-0001",
            "title": "SQLi",
            "severity": "high",
            "cwe": "CWE-89",
            "verification": {"status": "verified"},
        },
        {"id": "vuln-0002", "title": "XSS", "severity": "medium", "cwe": "CWE-79"},
        {"id": "vuln-0003", "title": "Odd thing", "severity": "low"},
    ]
    summary = summarize(reports)
    injection = summary["findings_by_control"]["owasp_top10_2021"]["A03:2021"]["findings"]
    assert [f["id"] for f in injection] == ["vuln-0001", "vuln-0002"]
    assert injection[0]["verification"] == "verified"
    assert [u["id"] for u in summary["unmapped_findings"]] == ["vuln-0003"]
    assert "PCI DSS 4.0" in summary["frameworks"].values()
    md = render_markdown(summary)
    assert "A03:2021" in md
    assert "11.4.3" in md  # assessment evidence
    assert "Unmapped findings" in md
    assert "not an attestation" in md
    json.dumps(summary)


def test_state_attaches_controls_and_writes_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="compliance-run")
    state.add_vulnerability_report(title="Reflected XSS", severity="medium", cwe="CWE-79")
    report = state.vulnerability_reports[0]
    assert "5.3.3" in _ids(report["controls"], "owasp_asvs_4_0_3")
    assert "Compliance Mapping" in render_vulnerability_md(report)

    state.save_run_data()
    run_dir = state.get_run_dir()
    assert (run_dir / "compliance_mapping.json").exists()
    assert "A03:2021" in (run_dir / "compliance_mapping.md").read_text()

    sarif = build_sarif_report(state.vulnerability_reports)
    props = sarif["runs"][0]["results"][0]["properties"]["strix"]
    assert "A03:2021" in props["controls"]["owasp_top10_2021"]


def test_finding_without_cwe_has_no_controls(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="no-cwe")
    state.add_vulnerability_report(title="Something", severity="low")
    assert "controls" not in state.vulnerability_reports[0]
