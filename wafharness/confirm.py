"""Single-URL confirmation: measure, hypothesise, send a few witnesses.

This is the "enter your own domain" path. It fingerprints the target, asks the
offline planner which modelled pair is the best explanation, and sends that
pair's witnesses with the normal sender limits.

It is deliberately weaker than :mod:`wafharness.live`: with only the front door,
a delivered witness proves the WAF allowed the bytes, not that the application
executed them. A reflected marker is the strongest result available; everything
else is reported as a candidate, never as a confirmed bypass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from wafharness.plan import Hypothesis
from wafharness.sender import RunReport

CONFIRMED = "confirmed"
CANDIDATE = "candidate"
BLOCKED = "blocked"
INCONCLUSIVE = "inconclusive"
NO_WITNESSES = "no-witnesses"


@dataclass
class Confirmation:
    """The result of one single-URL confirmation run."""

    target: str
    hypothesis: Hypothesis
    run: RunReport
    verdict: str
    notes: List[str] = field(default_factory=list)

    @property
    def positive(self) -> bool:
        return self.verdict == CONFIRMED

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "verdict": self.verdict,
            "notes": list(self.notes),
            "hypothesis": self.hypothesis.to_dict(),
            "run": self.run.to_dict(),
        }


def assess(hypothesis: Hypothesis, run: RunReport) -> Confirmation:
    """Turn a sender receipt into an evidence level, not a guarantee."""
    notes: List[str] = []

    if not hypothesis.bypasses:
        return Confirmation(
            run.target, hypothesis, run, NO_WITNESSES,
            ["the selected hypothesis has no modelled witness to send"])

    if run.stopped_reason.startswith("control request was blocked"):
        return Confirmation(
            run.target, hypothesis, run, INCONCLUSIVE,
            ["the control request was blocked; the target refuses everything, "
             "so no witness result is interpretable"])

    witnesses = [attempt for attempt in run.attempts if attempt.index != 0]
    if not witnesses:
        return Confirmation(
            run.target, hypothesis, run, INCONCLUSIVE,
            ["no witness request was sent"])

    reflected = [attempt for attempt in witnesses
                 if attempt.reflected and not attempt.blocked and not attempt.error]
    delivered = [attempt for attempt in witnesses
                 if not attempt.blocked and not attempt.error and attempt.status]
    blocked = [attempt for attempt in witnesses if attempt.blocked]
    errors = [attempt for attempt in witnesses if attempt.error]

    if reflected:
        notes.append(
            f"{len(reflected)} witness(es) passed the WAF and reflected a marker")
        notes.append(
            "reflection is evidence that the application received the value; "
            "confirm exploitability separately")
        return Confirmation(
            run.target, hypothesis, run, CONFIRMED, notes)

    if delivered:
        notes.append(
            f"{len(delivered)} witness(es) passed the WAF; no marker was reflected")
        notes.append(
            "this is a candidate, not a confirmed bypass: the application may "
            "have rewritten or ignored the value")
        return Confirmation(
            run.target, hypothesis, run, CANDIDATE, notes)

    if blocked:
        notes.append(
            f"{len(blocked)} witness(es) were blocked; the modelled divergence "
            "did not transfer to the live WAF")
        if errors:
            notes.append(f"{len(errors)} request(s) failed before a decision")
        return Confirmation(run.target, hypothesis, run, BLOCKED, notes)

    return Confirmation(
        run.target, hypothesis, run, INCONCLUSIVE,
        ["no interpretable response from any witness"])


def summarise(confirmation: Confirmation) -> str:
    """One-screen receipt: hypothesis, verdict and the usual sender table."""
    from wafharness import sender

    hypothesis = confirmation.hypothesis
    lines = [
        "",
        f"  hypothesis  {hypothesis.waf.name} vs {hypothesis.backend.name} "
        f"(fit {hypothesis.fit:.2f})",
        f"  verdict     {confirmation.verdict.upper()}",
    ]
    for note in confirmation.notes:
        lines.append(f"  note        {note}")
    lines.append(sender.summarise(confirmation.run))
    return "\n".join(lines)
