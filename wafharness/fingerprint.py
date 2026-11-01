"""Fingerprinting a live target's cascade.

Sending canaries and reading the answers gives a *measured* profile instead of a
modelled one. This module is the bridge between the offline matrix and a real
target, and it is built to be honest about how little two responses can prove.

Three signals, in order of strength:

1. **Reflection** — the response contains the canary's marker. Strongest, because
   it means the stack decoded the value and the application echoed it.
2. **Rejection** — the WAF blocked the canary while allowing a benign control.
   Says the stack saw something dangerous, which narrows it.
3. **Silence** — neither. Almost no information; recorded but weighted near zero.

A single canary proves nothing about a whole stack. Confidence is accumulated per
*transform* and combined, so "this target decodes twice" can be stated with more
confidence than "this target is Cloudflare" ever should be.

No traffic is sent by this module. It takes a ``transport`` callable, so the
caller decides what a request means and the tests supply a fake.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

from wafharness import canaries, stacks
from wafharness.canaries import Canary
from wafharness.models import Observation, Profile, Stack

#: ``transport(payload: bytes) -> (status: int, body: bytes)``.
#:
#: The callable owns every detail of the request — method, path, headers. That
#: keeps this module free of HTTP assumptions and keeps it testable without a
#: network.
Transport = Callable[[bytes], "tuple[int, bytes]"]

#: Statuses that mean "refused", not "handled".
BLOCK_STATUSES = frozenset({400, 403, 406, 413, 418, 429, 501, 503})

#: Confidence awarded per outcome. Deliberately modest: a WAF that blocks a
#: percent-encoded tag may simply have a broad rule, not a decoder.
CONFIDENCE = {
    "reflected": 0.80,
    "reflected_literal": 0.65,
    "blocked": 0.45,
    "allowed_for_encoded": 0.35,
    "silent": 0.05,
}


@dataclass
class ProbeResult:
    """What one canary did on the wire."""

    canary: Canary
    status: int
    body: bytes
    outcome: str
    reflection: str = ""

    @property
    def blocked(self) -> bool:
        return self.status in BLOCK_STATUSES

    def to_dict(self) -> Dict[str, object]:
        return {
            "canary": self.canary.name,
            "detects": self.canary.detects,
            "status": self.status,
            "outcome": self.outcome,
            "reflection": self.reflection[:60],
        }


def _reflects(body: bytes, marker: str) -> bool:
    if not marker:
        return False
    return marker.encode("utf-8", "replace") in body


def _differs(left: bytes, right: bytes) -> float:
    """How different two bodies are, 0.0 identical to 1.0 unrelated."""
    return 1.0 - difflib.SequenceMatcher(None, left, right, autojunk=False).ratio()


def classify(canary: Canary, status: int, body: bytes,
             control_status: Optional[int] = None,
             control_body: bytes = b"") -> ProbeResult:
    """Decide what one response says about the canary.

    The control is a benign request made first. It exists because "the server
    returned 403" means nothing without knowing what it returns for everything
    else: a target that 403s everything is not a WAF deciding about your payload.
    """
    if _reflects(body, canary.marker):
        return ProbeResult(canary, status, body, "reflected", canary.marker)

    # The canary came back but still encoded: the stack did not decode it.
    if canary.payload and canary.payload in body:
        return ProbeResult(canary, status, body, "reflected_literal",
                           canary.payload.decode("latin-1")[:40])

    if status in BLOCK_STATUSES:
        # A WAF that blocks everything is not discriminating; only call it a
        # block when the control was allowed.
        if control_status is not None and control_status in BLOCK_STATUSES:
            return ProbeResult(canary, status, body, "silent")
        return ProbeResult(canary, status, body, "blocked")

    if control_status is not None and control_body:
        if _differs(body, control_body) > 0.30:
            # The page changed because of the canary, without reflecting it.
            return ProbeResult(canary, status, body, "allowed_for_encoded")

    return ProbeResult(canary, status, body, "silent")


def annotate(profile: Profile) -> Profile:
    """Add the interpretation notes that make a profile readable.

    The most common real-world profile is *all absence*: an application that
    reflects the query string verbatim, seen through no WAF. That is a finding —
    the stack does not decode — but it reads like a failure, so it is explained
    here rather than left to each caller to remember.
    """
    positive = [name for name, value in profile.detected.items()
                if value >= 0.45
                and not name.startswith(("no:", "best_fit:", "also:"))]
    if profile.detected and not positive:
        absent = sorted(name[3:] for name in profile.detected
                        if name.startswith("no:"))
        profile.note(
            "every canary came back undecoded — the target reflects the raw "
            f"value. Absent: {', '.join(absent[:6])}"
            + ("…" if len(absent) > 6 else "")
            + ". This is a finding about the stack, not a failure.")
    return profile


def probe(transport: Transport, target: str = "",
          selected: Optional[Sequence[Canary]] = None) -> Profile:
    """Run every canary (or a subset) and return a profile.

    The control request is sent first and its result reused for every canary, so
    a scan of thirteen canaries costs fourteen requests, not twenty-six.
    """
    selected = list(selected or canaries.CANARIES)
    profile = Profile(target=target or "target")

    try:
        control_status, control_body = transport(b"nexus-control-token")
    except Exception as exc:  # noqa: BLE001 - a dead target is a result
        profile.note(f"control request failed: {type(exc).__name__}: {exc}")
        return profile

    if control_status in BLOCK_STATUSES:
        profile.note(
            "control request was itself blocked; canary results carry no "
            "information about decoding")

    for canary in selected:
        try:
            status, body = transport(canary.payload)
        except Exception as exc:  # noqa: BLE001
            profile.note(f"{canary.name}: transport error "
                         f"{type(exc).__name__}")
            continue

        result = classify(canary, status, body, control_status, control_body)
        profile.observations.append(Observation(
            canary=canary.name,
            sent=canary.payload,
            received=result.reflection.encode("utf-8", "replace") or body[:120],
            decided=result.outcome,
        ))

        weight = CONFIDENCE.get(result.outcome, 0.05)
        if result.outcome in ("reflected", "blocked"):
            # Reflected means the transform is present. Blocked means the stack
            # saw something worth blocking, which is weaker: a broad rule does
            # that too.
            profile.add(canary.detects, weight)
        elif result.outcome == "reflected_literal":
            # Echoed but *not* decoded: evidence the transform is absent. Record
            # the absence at the same confidence so the report can show it.
            profile.add(f"no:{canary.detects}", weight)

    _infer_vendor(profile)
    annotate(profile)
    return profile


def _infer_vendor(profile: Profile) -> None:
    """Name the modelled stack that best explains the detected transforms.

    The comparison runs against **every** stack, not only WAFs, because the
    probe cannot know which side of the deployment it reached: a backend that
    reflects a canary is measured exactly like a WAF that blocks one. Reporting
    "best fit: java-spring" for a Java target is correct and useful — reporting
    it as a WAF would be a category error, so the label says ``best_fit`` and the
    report shows the whole ranking.
    """
    detected = {name for name, value in profile.detected.items()
                if value >= 0.45 and not name.startswith("no:")
                and not name.startswith("best_fit:")}
    if not detected:
        return

    scored = []
    for name, stack in stacks.ALL_STACKS.items():
        steps = {t.name for t in stack.decode} | {t.name for t in stack.normalize}
        if not steps:
            continue
        overlap = len(detected & steps)
        if not overlap:
            continue
        # Jaccard: a stack that explains what was seen without postulating steps
        # that were never observed wins.
        scored.append((overlap / len(detected | steps), name, len(steps)))

    if not scored:
        return

    # Sort by score, then by how few steps the stack postulates: a stack that
    # explains the observation with two decoders is a better hypothesis than one
    # that needs six and happens to overlap. Sorting by name as a final tiebreak
    # would silently make the answer depend on the alphabet, which is how
    # "python-werkzeug" got reported for a PHP target.
    scored.sort(key=lambda item: (-item[0], item[2], item[1]))
    best_score, best_name, best_steps = scored[0]
    tied = [name for score, name, _steps in scored if abs(score - best_score) < 1e-9]

    profile.vendor = best_name
    profile.add(f"best_fit:{best_name}", min(0.85, best_score))

    if len(tied) > 1:
        # Four stacks fitting identically is not a weak answer to be hidden, it
        # is *no* answer: the canaries cannot separate them, and the report must
        # say so rather than picking whichever name sorts first.
        profile.note(
            "ambiguous: " + ", ".join(sorted(tied)) +
            f" all fit equally ({best_score:.2f}); the canaries cannot "
            "distinguish them — add a canary that separates these stacks")

    for score, name, _steps in scored[1:3]:
        if score >= 0.5 and name not in tied:
            profile.add(f"also:{name}", min(0.85, score))

    if best_score < 0.5:
        profile.note(
            f"best fit is {best_name} at {best_score:.2f}; the observed "
            "transforms do not fit any modelled stack well")


def suggested_stacks(profile: Profile) -> List[str]:
    """Stacks worth comparing locally, given what was measured.

    Returns transform names, not stack names, when the vendor is unknown — the
    search engine consumes transforms, so guessing a vendor would add a step of
    unwarranted certainty.
    """
    return sorted(name for name, value in profile.detected.items()
                  if value >= 0.45 and not name.startswith("no:"))


def summarise(profile: Profile) -> str:
    """One-line summary for the console."""
    if not profile.detected:
        return "no transforms detected — target may not reflect or may block all"
    parts = [f"{name} ({value:.2f})"
             for name, value in sorted(profile.detected.items(),
                                       key=lambda item: -item[1])
             if not name.startswith("no:")]
    return "detected: " + ", ".join(parts[:6])

