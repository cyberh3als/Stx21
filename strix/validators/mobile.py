"""Validators for mobile findings: the evidence must re-trigger the rule."""

from __future__ import annotations

from strix.mobile.android import rules_in_manifest_evidence
from strix.mobile.ios import rules_in_plist_evidence
from strix.mobile.secrets import rules_in_secret_evidence
from strix.validators.base import Check, Outcome, Spec, register


def _text(spec: Spec, key: str) -> str:
    value = spec.get(key)
    return value.strip() if isinstance(value, str) else ""


@register("mobile_manifest", aliases=("android_manifest", "ios_plist", "mobile_config"))
def validate_mobile_manifest(spec: Spec) -> Outcome:
    check = Check("mobile_manifest")
    platform, rule, evidence = (_text(spec, k) for k in ("platform", "rule", "evidence"))
    if platform not in ("android", "ios") or not rule or not evidence:
        check.failed(
            "'platform' (android|ios), 'rule' and the decoded manifest/plist in "
            "'evidence' are required"
        )
        return check.result()
    detected = (
        rules_in_manifest_evidence(evidence)
        if platform == "android"
        else rules_in_plist_evidence(evidence)
    )
    check.require(
        rule in detected,
        f"rule '{rule}' re-detected in the supplied {platform} configuration",
        f"rule '{rule}' is not triggered by the supplied evidence (detected: "
        f"{', '.join(sorted(detected)) or 'none'})",
    )
    return check.result()


@register("mobile_secret", aliases=("hardcoded_secret", "embedded_secret"))
def validate_mobile_secret(spec: Spec) -> Outcome:
    check = Check("mobile_secret")
    rule, evidence = _text(spec, "rule"), _text(spec, "evidence")
    if not rule or not evidence:
        check.failed("'rule' and the raw matching text in 'evidence' are required")
        return check.result()
    detected = rules_in_secret_evidence(evidence)
    check.require(
        rule in detected,
        f"secret pattern '{rule}' matches the evidence and is not a placeholder",
        f"evidence does not contain a genuine match for '{rule}' (placeholder, wrong pattern, "
        "or no secret)",
    )
    return check.result()
