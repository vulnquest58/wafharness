"""Live measurements against the OWASP CRS Sandbox.

The sandbox is a public, shared testing environment. Its policy explicitly
permits automated attack-payload testing at ten requests per second or less:

    https://coreruleset.org/docs/crs-sandbox-policy

This module is pure: it takes a transport and parses the sandbox's JSON. The
CLI owns the HTTP request, exactly as it does for ``profile`` and ``plan``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from wafharness import canaries
from wafharness.canaries import Canary

#: ``transport(payload: bytes) -> (status: int, body: bytes)``.
Transport = Callable[[bytes], "tuple[int, bytes]"]


@dataclass(frozen=True)
class RuleMatch:
    """One CRS rule that fired for a request."""

    id: str
    message: str = ""
    paranoia_level: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "id": self.id,
            "message": self.message,
            "paranoia_level": self.paranoia_level,
        }


@dataclass
class CanaryResult:
    """What the sandbox said about one canary."""

    canary: Canary
    status: int
    rules: List[RuleMatch] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        if self.rules:
            return True
        # A blocking-mode sandbox can return 403 without an audit body. The
        # status is still evidence; do not silently call that "allowed".
        return self.status == 403

    def to_dict(self) -> Dict[str, object]:
        return {
            "canary": self.canary.name,
            "detects": self.canary.detects,
            "status": self.status,
            "detected": self.detected,
            "rules": [rule.to_dict() for rule in self.rules],
        }


def parse_rules(body: bytes) -> List[RuleMatch]:
    """Parse the ``json-matched-rules`` payload; never raise on garbage."""
    try:
        payload = json.loads(body.decode("utf-8", "replace"))
    except (TypeError, ValueError):
        return []
    if not isinstance(payload, list):
        return []

    rules: List[RuleMatch] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("id")
        if rule_id is None:
            continue
        rules.append(RuleMatch(
            id=str(rule_id),
            message=str(item.get("message", "") or ""),
            paranoia_level=str(item.get("paranoia_level", "") or ""),
        ))
    return rules


def measure(transport: Transport,
            selected: Optional[Sequence[Canary]] = None) -> List[CanaryResult]:
    """Send each canary through ``transport`` and keep the matched rules."""
    results: List[CanaryResult] = []
    for canary in selected or canaries.CANARIES:
        try:
            status, body = transport(canary.payload)
        except Exception:  # noqa: BLE001 - a dead sandbox is a result
            status, body = 0, b""
        results.append(CanaryResult(canary, status, parse_rules(body)))
    return results


def unique_rules(results: Sequence[CanaryResult]) -> List[RuleMatch]:
    """Every rule that fired, once, ordered by rule id."""
    seen: Dict[str, RuleMatch] = {}
    for result in results:
        for rule in result.rules:
            seen.setdefault(rule.id, rule)
    return [seen[key] for key in sorted(seen)]


def summary(results: Sequence[CanaryResult]) -> Dict[str, object]:
    detected = [result for result in results if result.detected]
    rules = unique_rules(results)
    return {
        "canaries": len(results),
        "detected": len(detected),
        "rules": len(rules),
        "rule_ids": [rule.id for rule in rules],
        "detected_canaries": [result.canary.name for result in detected],
    }
