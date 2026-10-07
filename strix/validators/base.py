"""Validator contract and registry.

A validator is a deterministic (non-LLM) check that decides whether the
captured evidence for a finding actually demonstrates the vulnerability. The
agent proposes; the validator disposes.

Validators only look at the evidence the agent submits (raw HTTP exchanges,
timings, out-of-band callback logs). They never talk to the target, so they are
cheap, repeatable and safe to run host-side.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


Spec = dict[str, Any]


@dataclass
class Outcome:
    """Result of running one validator against one evidence spec."""

    validator: str
    ok: bool
    checks: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "verified" if self.ok else "unverified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "validator": self.validator,
            "checks": self.checks,
            "reasons": self.reasons,
        }


class Check:
    """Accumulates passed checks and failure reasons for one validator run."""

    def __init__(self, validator: str) -> None:
        self._outcome = Outcome(validator=validator, ok=True)

    def passed(self, message: str) -> None:
        self._outcome.checks.append(message)

    def failed(self, reason: str) -> None:
        self._outcome.ok = False
        self._outcome.reasons.append(reason)

    def require(self, condition: bool, ok_msg: str, fail_msg: str) -> bool:
        (self.passed if condition else self.failed)(ok_msg if condition else fail_msg)
        return condition

    def result(self) -> Outcome:
        return self._outcome


Validator = Callable[[Spec], Outcome]

_REGISTRY: dict[str, Validator] = {}
_ALIASES: dict[str, str] = {}


def register(name: str, *, aliases: tuple[str, ...] = ()) -> Callable[[Validator], Validator]:
    def decorator(fn: Validator) -> Validator:
        _REGISTRY[name] = fn
        for alias in aliases:
            _ALIASES[alias] = name
        return fn

    return decorator


def canonical_type(name: str | None) -> str | None:
    if not name:
        return None
    key = name.strip().lower().replace("-", "_").replace(" ", "_")
    key = _ALIASES.get(key, key)
    return key if key in _REGISTRY else None


def available_types() -> list[str]:
    return sorted(_REGISTRY)


def get_validator(name: str) -> Validator | None:
    return _REGISTRY.get(name)
