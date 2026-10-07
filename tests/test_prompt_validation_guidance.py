"""Keep agent-facing guidance in sync with the deterministic validators.

Every JSON example in a skill's "Validation Evidence" section must actually be
accepted by the validator it documents, and the system prompt must name every
validator type, so prompts cannot drift from the code.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from strix.validators import available_types, evaluate


ROOT = Path(__file__).resolve().parents[1] / "strix"
SKILLS = ROOT / "skills" / "vulnerabilities"
_SECTION = re.compile(r"^## Validation Evidence\n(.*?)(?=^## |\Z)", re.MULTILINE | re.DOTALL)
_JSON_BLOCK = re.compile(r"```json\n(.*?)\n```", re.DOTALL)


def _examples() -> list[tuple[str, dict]]:
    found: list[tuple[str, dict]] = []
    for path in sorted(SKILLS.glob("*.md")):
        match = _SECTION.search(path.read_text())
        if not match:
            continue
        found.extend((path.name, json.loads(raw)) for raw in _JSON_BLOCK.findall(match.group(1)))
    return found


EXAMPLES = _examples()


def test_every_core_class_documents_validation_evidence() -> None:
    documented = {name for name, _ in EXAMPLES}
    assert documented >= {
        "xss.md",
        "sql_injection.md",
        "ssti.md",
        "rce.md",
        "ssrf.md",
        "path_traversal_lfi_rfi.md",
        "open_redirect.md",
        "idor.md",
    }


@pytest.mark.parametrize(
    ("skill", "example"), EXAMPLES, ids=[f"{n}:{e['type']}" for n, e in EXAMPLES]
)
def test_skill_examples_are_accepted_by_their_validator(skill: str, example: dict) -> None:
    verdict = evaluate(example, None)
    assert verdict["status"] == "verified", (skill, verdict)


def test_system_prompt_names_every_validator_type() -> None:
    prompt = (ROOT / "agents" / "prompts" / "system_prompt.jinja").read_text()
    assert "DETERMINISTIC VALIDATION" in prompt
    missing = [t for t in available_types() if t not in prompt]
    assert not missing, f"system prompt does not mention validator types: {missing}"


def test_rendered_prompt_carries_guidance_literally() -> None:
    from strix.agents.prompt import render_system_prompt  # noqa: PLC0415

    prompt = render_system_prompt(skills=["xss"], is_root=False)
    assert prompt, "system prompt failed to render"
    assert "DETERMINISTIC VALIDATION" in prompt
    # Jinja must not evaluate the example expression in the guidance text.
    assert "{{7*7}}" in prompt
    assert "## Validation Evidence" in prompt  # the loaded xss skill's section
    assert "execution_token" in prompt
