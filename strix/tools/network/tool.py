"""Network assessment tool: turn raw scanner output into scoped finding candidates."""

from __future__ import annotations

import json
import logging

from agents import RunContextWrapper, function_tool

from strix.network import NetworkScope, analyze
from strix.report.state import get_global_report_state


logger = logging.getLogger(__name__)


@function_tool(timeout=60, strict_mode=False)
async def analyze_network_scan(
    ctx: RunContextWrapper,
    nmap_xml: str = "",
    naabu_jsonl: str = "",
    nuclei_jsonl: str = "",
) -> str:
    """Analyse raw network-scan output and return finding candidates.

    Paste the RAW output of the scanners you ran in the sandbox (do not
    summarise it). Results are limited to hosts in the authorized scan scope;
    anything else is ignored and listed so you know to stop scanning it.

    Inputs (all optional, give what you have):
      - ``nmap_xml``: ``nmap -sV --script ssl-enum-ciphers,ssl-cert -oX -`` output.
      - ``naabu_jsonl``: ``naabu -json`` output.
      - ``nuclei_jsonl``: ``nuclei -jsonl`` output.

    Returns candidates (exposed services, deprecated TLS, weak ciphers, expired
    certificates, nuclei matches) each with a ready-to-use ``validation``
    object. File a candidate with ``create_vulnerability_report`` passing that
    ``validation`` unchanged; a deterministic validator re-checks the raw
    evidence. A reachable port proves exposure, not weak authentication: do not
    claim unauthenticated access without demonstrating it within scope and
    without altering data.
    """
    state = get_global_report_state()
    targets = (state.run_record.get("targets_info") if state else None) or []
    try:
        scope = NetworkScope.from_targets(targets)
    except ValueError as exc:
        return json.dumps({"success": False, "error": str(exc)})
    if not scope:
        return json.dumps(
            {"success": False, "error": "No network targets (IP, range, domain or URL) in scope."}
        )
    result = analyze(scope, nmap_xml=nmap_xml, naabu_jsonl=naabu_jsonl, nuclei_jsonl=nuclei_jsonl)
    return json.dumps({"success": True, **result}, ensure_ascii=False)
