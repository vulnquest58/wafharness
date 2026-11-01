"""Direct live comparison: the same bytes to a front door and an origin.

The offline matrix answers a hypothetical question: *which WAF/backend pair
could disagree?* This module answers a measured one: *do these two live
endpoints actually disagree?* It sends one canary to each endpoint and compares
the status, the reflected marker and the body shape.

It knows nothing about vendors, stacks or models. That is the point: a
``front-blocked`` result is evidence from the wire, not a prediction.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from wafharness import canaries
from wafharness.canaries import Canary
from wafharness.fingerprint import BLOCK_STATUSES

#: ``transport(payload: bytes) -> (status: int, body: bytes)``.
Transport = Callable[[bytes], "tuple[int, bytes]"]

CONTROL = b"wafharness-control"
BODY_DIFF_THRESHOLD = 0.30

#: Verdicts that mean the two live endpoints did not behave the same way.
DIVERGENT = frozenset({
    "front-blocked",
    "origin-blocked",
    "front-sees-payload",
    "origin-sees-payload",
    "body-diverges",
})


@dataclass
class Probe:
    """One live response, including the failure case."""

    status: int = 0
    body: bytes = b""
    error: str = ""

    @property
    def blocked(self) -> bool:
        return self.status in BLOCK_STATUSES

    def reflects(self, canary: Canary) -> bool:
        if not canary.marker:
            return False
        return canary.marker.encode("utf-8", "replace") in self.body

    def to_dict(self) -> Dict[str, object]:
        return {
            "status": self.status,
            "size": len(self.body),
            "blocked": self.blocked,
            "error": self.error,
        }


@dataclass
class Comparison:
    """One canary, sent to both endpoints, and the verdict."""

    canary: Canary
    front: Probe
    origin: Probe
    verdict: str
    detail: str = ""

    @property
    def divergent(self) -> bool:
        return self.verdict in DIVERGENT

    def to_dict(self) -> Dict[str, object]:
        return {
            "canary": self.canary.name,
            "detects": self.canary.detects,
            "verdict": self.verdict,
            "detail": self.detail,
            "front": self.front.to_dict(),
            "origin": self.origin.to_dict(),
        }


@dataclass
class ComparisonReport:
    """The receipt for one direct comparison."""

    front: str
    origin: str
    control_front: Probe = field(default_factory=Probe)
    control_origin: Probe = field(default_factory=Probe)
    comparisons: List[Comparison] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def divergences(self) -> List[Comparison]:
        return [item for item in self.comparisons if item.divergent]

    def to_dict(self) -> Dict[str, object]:
        return {
            "front": self.front,
            "origin": self.origin,
            "controls": {
                "front": self.control_front.to_dict(),
                "origin": self.control_origin.to_dict(),
            },
            "comparisons": [item.to_dict() for item in self.comparisons],
            "divergences": len(self.divergences),
            "notes": list(self.notes),
        }


def _probe(transport: Transport, payload: bytes) -> Probe:
    try:
        status, body = transport(payload)
    except Exception as exc:  # noqa: BLE001 - a dead endpoint is a result
        return Probe(error=f"{type(exc).__name__}: {exc}")
    if status == 0:
        return Probe(body=body, error="no response (status 0)")
    return Probe(status=status, body=body)


def classify(canary: Canary, front: Probe, origin: Probe) -> "tuple[str, str]":
    """Compare two responses to the same bytes."""
    if front.error or origin.error:
        return "error", front.error or origin.error

    if front.blocked and not origin.blocked:
        return "front-blocked", "front refused; origin accepted"
    if origin.blocked and not front.blocked:
        return "origin-blocked", "origin refused; front accepted"
    if front.blocked and origin.blocked:
        return "both-blocked", "both endpoints refused"

    front_reflects = front.reflects(canary)
    origin_reflects = origin.reflects(canary)
    if origin_reflects and not front_reflects:
        return "origin-sees-payload", "origin reflected the marker; front did not"
    if front_reflects and not origin_reflects:
        return "front-sees-payload", "front reflected the marker; origin did not"

    if front.body != origin.body:
        ratio = 1.0 - difflib.SequenceMatcher(
            None, front.body, origin.body, autojunk=False).ratio()
        if ratio > BODY_DIFF_THRESHOLD:
            return "body-diverges", f"bodies differ by {ratio:.0%}"
    return "same", ""


def compare(front_transport: Transport, origin_transport: Transport,
            selected: Optional[Sequence[Canary]] = None,
            front_name: str = "front", origin_name: str = "origin"
            ) -> ComparisonReport:
    """Send one control and every canary to both endpoints."""
    report = ComparisonReport(front=front_name, origin=origin_name)
    report.control_front = _probe(front_transport, CONTROL)
    report.control_origin = _probe(origin_transport, CONTROL)

    if report.control_front.blocked:
        report.notes.append(
            "front control was blocked; its canary results may not be "
            "comparable")
    if report.control_origin.blocked:
        report.notes.append(
            "origin control was blocked; its canary results may not be "
            "comparable")
    if report.control_front.error:
        report.notes.append(f"front control failed: {report.control_front.error}")
    if report.control_origin.error:
        report.notes.append(
            f"origin control failed: {report.control_origin.error}")
    if report.control_front.error and report.control_origin.error:
        report.notes.append("both controls failed; no canaries were sent")
        return report

    chosen = canaries.CANARIES if selected is None else selected
    for canary in chosen:
        front = _probe(front_transport, canary.payload)
        origin = _probe(origin_transport, canary.payload)
        verdict, detail = classify(canary, front, origin)
        report.comparisons.append(
            Comparison(canary, front, origin, verdict, detail))

    return report
