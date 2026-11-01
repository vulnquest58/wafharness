"""From measurement to plan: join the fingerprint to the divergence search.

The fingerprint answers *what transforms does this target apply*. The engine
answers *where do two modelled stacks disagree*. Neither alone tells an operator
what to try next: the first describes behaviour without saying which backend it
feeds, the second describes a hypothesis without saying whether the target is
anywhere near it.

This module is the join. It scores every modelled stack against the measured
evidence, keeps the stacks that fit, searches the plausible WAF/backend pairs
offline, and returns the requests worth making — ranked by evidence and by how
few requests they need.

The join is deliberately humble. A profile is evidence about transforms, not a
certificate about vendors. If four stacks explain the canaries equally, the plan
searches all four instead of inventing a winner; the alternative is choosing a
witness by alphabetical order, which is how an earlier layer reported
``python-werkzeug`` for a PHP target. The extra searches are local and free.

Two facts make the planner useful even when it is uncertain:

* The canaries cannot tell which side of a deployment they reached. If the
  evidence fits a backend model better than any WAF model, the plan says so and
  searches every WAF against the measured backend, instead of pretending the
  application is a firewall.
* Absence is evidence. A target that echoes a canary still encoded has
  demonstrably *not* applied that transform, so a stack that claims it is
  penalised. This is what keeps the simplest stack from always winning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from wafharness import engine, stacks
from wafharness.models import Divergence, DivergenceKind, Profile, Stack

#: Confidence at or above which an observation counts as evidence.
EVIDENCE_THRESHOLD = 0.45

#: A stack at or above this fit is a candidate rather than a fallback.
FIT_THRESHOLD = 0.50

#: How many stacks of one kind to keep before the pair search.
MAX_CANDIDATES = 4

#: Default cap on local searches. Eight WAF models against four distinct backend
#: pipelines is thirty-two pairs; anything beyond that is the matrix command's
#: job, not the planner's.
MAX_PAIRS = 32

#: A backend profile that scores this much better than every WAF profile is
#: probably the application itself, not the firewall.
SIDE_MARGIN = 0.15

#: Steps that are framing rules rather than byte rewrites. They are real
#: evidence, but no ``Stack`` contains them, so they would dilute every score
#: equally; the report points at the ``frames`` command instead.
_FRAMING_PREFIX = "framing:"


@dataclass(frozen=True)
class Hypothesis:
    """One WAF/backend pair, its evidential fit, and what the search found."""

    waf: Stack
    backend: Stack
    fit: float
    divergences: Tuple[Divergence, ...] = ()

    @property
    def bypasses(self) -> Tuple[Divergence, ...]:
        return tuple(d for d in self.divergences
                     if d.kind is DivergenceKind.HIDDEN_FROM_WAF)

    @property
    def rewritten(self) -> Tuple[Divergence, ...]:
        return tuple(d for d in self.divergences
                     if d.kind is DivergenceKind.REWRITTEN)

    def to_dict(self) -> Dict[str, object]:
        return {
            "waf": self.waf.name,
            "backend": self.backend.name,
            "fit": round(self.fit, 3),
            "bypass": len(self.bypasses),
            "rewritten": len(self.rewritten),
            "witnesses": [d.to_dict() for d in self.bypasses[:5]],
        }


@dataclass
class Plan:
    """Ranked hypotheses plus the caveats behind their ranking."""

    target: str
    profile: Profile
    measured_side: str = "unknown"
    #: Best-fitting stack on the side the canaries measured. Kept separate from
    #: ``profile.vendor`` because the fingerprint refuses to name a vendor when
    #: all it observed was absence; the plan can still say "the app behaves like
    #: the identity stack" without upgrading that to a vendor claim.
    measured_stack: str = ""
    hypotheses: List[Hypothesis] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def bypasses(self) -> Tuple[Divergence, ...]:
        return tuple(d for hypothesis in self.hypotheses
                     for d in hypothesis.bypasses)

    @property
    def best(self) -> Optional[Hypothesis]:
        return self.hypotheses[0] if self.hypotheses else None

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "best_fit": self.profile.vendor or self.measured_stack,
            "measured_side": self.measured_side,
            "measured_stack": self.measured_stack,
            "bypass_total": len(self.bypasses),
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "notes": list(self.notes),
            "profile": self.profile.to_dict(),
        }


# ══════════════════════════════════════════════════════════════════════════════
#  Evidence
# ══════════════════════════════════════════════════════════════════════════════


def positive_transforms(profile: Profile) -> Dict[str, float]:
    """Transforms the target was observed to apply, with their confidence."""
    return {
        name: value for name, value in profile.detected.items()
        if value >= EVIDENCE_THRESHOLD
        and not name.startswith(("no:", "best_fit:", "also:"))
        and not name.startswith(_FRAMING_PREFIX)
    }


def absent_transforms(profile: Profile) -> Dict[str, float]:
    """Transforms the target was observed *not* to apply.

    These matter as much as the positives. Without them, a stack that models
    every decoder would explain every observation and the ranking would be
    constant.
    """
    return {
        name[len("no:"):]: value for name, value in profile.detected.items()
        if name.startswith("no:") and value >= EVIDENCE_THRESHOLD
        and not name[len("no:"):].startswith(_FRAMING_PREFIX)
    }


def stack_fit(stack: Stack, profile: Profile) -> float:
    """How much of the measured evidence a stack explains, in ``[0, 1]``.

    Positive evidence is weighted more than absence: failing to decode a canary
    that the target demonstrably decoded is a stronger contradiction than
    carrying a transform the canaries never exercised. A stack with no steps
    therefore fits best only when the evidence is all absence — which is the
    honest reading of a target that reflects everything verbatim.
    """
    positive = positive_transforms(profile)
    absent = absent_transforms(profile)
    if not positive and not absent:
        return 0.0

    steps = {t.name for t in stack.decode} | {t.name for t in stack.normalize}

    if not positive:
        # No positive evidence: every stack is equally good at "explaining"
        # nothing, so awarding a blanket 0.65 would make even a contradicted
        # stack look like a fit. Score absence alone.
        return round(len(set(absent) - steps) / len(absent), 6)

    recall = len(set(positive) & steps) / len(positive)
    if not absent:
        return round(recall, 6)

    accuracy = len(set(absent) - steps) / len(absent)
    return round(0.65 * recall + 0.35 * accuracy, 6)


def _score_pool(profile: Profile, pool: Dict[str, Stack]) -> List[Tuple[float, Stack]]:
    scored = [(stack_fit(stack, profile), stack) for stack in pool.values()]
    return sorted(scored, key=lambda item: (-item[0], item[1].name))


def _dedupe_by_pipeline(stacks_: Iterable[Stack],
                        preferred: str = "") -> List[Stack]:
    """Drop stacks that model the same cascade under another name.

    ``php``, ``node-express`` and ``go-net-http`` all reduce to
    ``url_decode_plus``. Searching all three produces the same witnesses three
    times; the ambiguity is reported in the notes instead. A row whose name
    matches the measured best fit is kept first so the plan leads with the
    stack the fingerprint already suspected.
    """
    ordered = sorted(stacks_, key=lambda s: (s.name != preferred, s.name))
    seen: Dict[Tuple[str, ...], Stack] = {}
    for stack in ordered:
        key = tuple(t.name for t in stack.decode + stack.normalize)
        seen.setdefault(key, stack)
    return list(seen.values())


def _real_backends() -> List[Stack]:
    return [stack for name, stack in stacks.BACKEND_STACKS.items()
            if name not in ("permissive", "identity")]


# ══════════════════════════════════════════════════════════════════════════════
#  Planning
# ══════════════════════════════════════════════════════════════════════════════


def _side_of(profile: Profile) -> str:
    """Which side of the deployment the canaries probably measured."""
    waf_fit = _score_pool(profile, stacks.WAF_STACKS)[0][0]
    backend_fit = _score_pool(profile, stacks.BACKEND_STACKS)[0][0]
    if backend_fit >= FIT_THRESHOLD and backend_fit > waf_fit + SIDE_MARGIN:
        return "backend"
    if waf_fit >= FIT_THRESHOLD and waf_fit > backend_fit + SIDE_MARGIN:
        return "waf"
    return "ambiguous"


def _hypothesis_fit(waf: Stack, backend: Stack, profile: Profile,
                    side: str) -> float:
    """Confidence in a pair, using only the side the canaries measured.

    Averaging both fits punishes the correct WAF for pairing with an unknown
    backend, which is backwards: the backend is *supposed* to be unknown. The
    unobserved side contributes nothing to the score and everything to the
    search.
    """
    waf_fit = stack_fit(waf, profile)
    backend_fit = stack_fit(backend, profile)
    if side == "waf":
        return waf_fit
    if side == "backend":
        return backend_fit
    return (waf_fit + backend_fit) / 2.0


def _candidates(scored: Sequence[Tuple[float, Stack]], preferred: str,
                fallback: Sequence[Stack]) -> Tuple[List[Stack], bool]:
    """Stacks worth searching, and whether evidence chose them.

    Keep the winner when the evidence is strong, and the plausible ties when it
    is not. "Plausible" has a narrow tolerance on purpose: a stack that claims a
    transform the target demonstrably lacks is a different hypothesis, not a
    variation on the winner. When nothing clears the fit floor, falling back to
    the whole pool is honest only because the caller says so in a note: the plan
    is then a survey, not a prediction.
    """
    best_fit = scored[0][0] if scored else 0.0
    if best_fit < FIT_THRESHOLD:
        return _dedupe_by_pipeline(fallback, preferred)[:MAX_CANDIDATES], False

    if best_fit >= 0.80:
        # A strong winner does not need company.
        keep = [stack for fit, stack in scored if abs(fit - best_fit) < 1e-9]
    else:
        keep = [stack for fit, stack in scored if fit >= best_fit - 0.05]

    return _dedupe_by_pipeline(keep, preferred)[:MAX_CANDIDATES], True


def build(profile: Profile, *,
          waf: Optional[Stack] = None,
          backend: Optional[Stack] = None,
          budget: Optional[engine.Budget] = None,
          max_pairs: int = MAX_PAIRS) -> Plan:
    """Turn a measured profile into ranked, locally-searched hypotheses.

    No traffic is sent here. The caller decides how the profile was obtained;
    this function only joins it to the search engine.
    """
    budget = budget or engine.Budget(max_depth=2, max_divergences=8)
    result = Plan(target=profile.target, profile=profile)

    if not profile.detected:
        result.note(
            "no evidence was collected (the control request may have failed); "
            "there is nothing to rank — the profile is a measurement, and this "
            "one is empty")
        return result

    waf_scored = _score_pool(profile, stacks.WAF_STACKS)
    backend_scored = _score_pool(profile, stacks.BACKEND_STACKS)
    preferred = profile.vendor

    side = _side_of(profile)
    result.measured_side = side

    best_waf_fit, best_waf = waf_scored[0]
    best_backend_fit, best_backend = backend_scored[0]
    # When the two sides are close, the best individual stack still tells us
    # which one was probably measured. Search the other side broadly: it is the
    # side the canaries cannot see.
    leaning = ("backend" if best_backend_fit > best_waf_fit
               else "waf" if best_waf_fit > best_backend_fit
               else "neither")
    measured = side if side in ("waf", "backend") else leaning

    if measured == "backend" and best_backend_fit >= FIT_THRESHOLD:
        result.measured_stack = best_backend.name
    elif measured == "waf" and best_waf_fit >= FIT_THRESHOLD:
        result.measured_stack = best_waf.name

    if side == "backend":
        result.note(
            "the canaries fit a backend model better than any WAF model; the "
            "measured stack is probably the application, not the firewall, so "
            "the WAF side is unconstrained and every WAF model is searched")
    elif side == "ambiguous":
        result.note(
            "the evidence does not separate the WAF and backend explanations; "
            f"it leans {leaning}, and the other side is searched unconstrained")
    if len(positive_transforms(profile)) > 1:
        ties = [name for name in profile.detected
                if name.startswith("best_fit:") or name.startswith("also:")]
        if ties:
            result.note(
                "the canaries cannot name a vendor on their own; hypotheses "
                "are ranked by how much evidence each cascade explains")

    if waf is not None:
        waf_candidates = [waf]
    elif measured == "backend":
        waf_candidates = _dedupe_by_pipeline(stacks.WAF_STACKS.values())
    else:
        waf_candidates, waf_by_evidence = _candidates(
            waf_scored, preferred, list(stacks.WAF_STACKS.values()))
        if not waf_by_evidence:
            result.note(
                "no WAF model fits the evidence; surveying every modelled WAF "
                "instead of pretending one was identified")

    if backend is not None:
        backend_candidates = [backend]
    elif measured == "waf":
        backend_candidates = _dedupe_by_pipeline(_real_backends())
        result.note(
            "the measured side behaves like a WAF; the backend is unobserved, "
            "so every real backend model is searched against it")
    else:
        backend_candidates, backend_by_evidence = _candidates(
            backend_scored, preferred, _real_backends())
        if not backend_by_evidence:
            result.note(
                "no backend model fits the evidence; surveying the modelled "
                "backends instead of pretending one was identified")

    hypotheses: List[Hypothesis] = []
    truncated = False
    for waf_stack in waf_candidates:
        for backend_stack in backend_candidates:
            if len(hypotheses) >= max_pairs:
                truncated = True
                break
            found = engine.search_pair(waf_stack, backend_stack, budget=budget)
            fit = _hypothesis_fit(waf_stack, backend_stack, profile, side)
            hypotheses.append(Hypothesis(
                waf=waf_stack,
                backend=backend_stack,
                fit=round(fit, 6),
                divergences=tuple(found),
            ))
        if truncated:
            break

    if truncated:
        result.note(
            f"the pair search was capped at {max_pairs}; the remaining "
            "combinations are still available through `find`")

    # Evidence first, findings second. The measured side is the part of the
    # deployment that was actually observed; ordering by bypass count first
    # would let an unmeasured WAF model outrank the one the canaries support
    # merely because it happens to have a wider gap. Ties fall back to the
    # findings and then to the pair names, so the order never depends on
    # dictionary iteration.
    hypotheses.sort(key=lambda h: (-h.fit, -len(h.bypasses),
                                   h.waf.name, h.backend.name))
    result.hypotheses = hypotheses

    if not result.bypasses:
        result.note(
            "no executable bypass was found under the measured hypotheses; "
            "absence here is a result about the models, not about the target")

    if any(name.startswith(_FRAMING_PREFIX)
           or name.startswith("no:" + _FRAMING_PREFIX)
           for name in profile.detected):
        result.note(
            "the profile contains framing evidence; run `wafharness frames` "
            "for the boundary layer, which is modelled separately")

    return result


def plan(profile: Profile, **kwargs) -> Plan:
    """Alias kept short for callers: ``plan.plan(profile)`` reads badly."""
    return build(profile, **kwargs)


def explain(hypothesis: Hypothesis) -> str:
    """Human-readable reason for a hypothesis, strongest witness first."""
    lines = [
        f"{hypothesis.waf.name} vs {hypothesis.backend.name}   "
        f"fit {hypothesis.fit:.2f}   bypass {len(hypothesis.bypasses)}",
        f"  waf     {hypothesis.waf.pipeline}",
        f"  backend {hypothesis.backend.pipeline}",
    ]
    if hypothesis.bypasses:
        lines.append("  first witness: "
                     + engine.explain(hypothesis.bypasses[0]).splitlines()[1])
    return "\n".join(lines)
