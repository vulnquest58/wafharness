"""Professional WAF/application identification.

The fingerprint deliberately refuses to turn a few canaries into a vendor
certificate. This module keeps that honesty but presents the result the way an
operator needs it: a label, a side (WAF vs application), the modelled fit, the
evidence, the alternatives, and the caveats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from wafharness.models import Profile

_PREFIXES = ("no:", "best_fit:", "also:", "framing:")


@dataclass
class Identity:
    """A measured label plus the evidence behind it."""

    target: str
    side: str = "unknown"
    label: str = "unknown"
    fit: float = 0.0
    evidence: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        if self.side == "waf":
            return "WAF-like"
        if self.side == "backend":
            return "application/backend-like"
        return "undetermined"

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "side": self.side,
            "kind": self.kind,
            "label": self.label,
            "fit": round(self.fit, 2),
            "evidence": list(self.evidence),
            "alternatives": list(self.alternatives),
            "warnings": list(self.warnings),
        }


def identify(profile: Profile, side: str = "unknown") -> Identity:
    """Build an identity from a profile and the plan's measured side."""
    evidence = [
        f"{name} {value:.2f}" for name, value in sorted(
            profile.detected.items(), key=lambda item: (-item[1], item[0]))
        if value >= 0.5 and not name.startswith(_PREFIXES)
    ][:6]
    alternatives = [
        f"{name[len('also:'):]} {value:.2f}"
        for name, value in sorted(
            profile.detected.items(), key=lambda item: (-item[1], item[0]))
        if name.startswith("also:")
    ]
    fit = 0.0
    if profile.vendor:
        fit = profile.detected.get(f"best_fit:{profile.vendor}", 0.0)
    label = profile.vendor or "unknown"
    return Identity(
        target=profile.target,
        side=side,
        label=label,
        fit=fit,
        evidence=evidence,
        alternatives=alternatives,
        warnings=list(profile.warnings),
    )
