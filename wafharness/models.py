"""Core model: WAF bypass as divergence between rewriting systems.

The premise of this project is narrow and, once stated, hard to argue with: a
request is a byte string, and every component that touches it applies a
*cascade of rewrites* before it decides anything. A WAF inspects the result of
its cascade; the backend acts on the result of its own. Where the two cascades
disagree, the WAF is looking at one thing and the application at another.

So a bypass is not a payload. It is a **pair of stacks that disagree about a
particular byte string**, and the interesting object is the disagreement, not
the string.

Three types make up the model:

* :class:`Stack` — a named cascade: decode, frame, normalize, then inspect.
* :class:`Divergence` — two stacks, a witness input and what each one sees.
* :class:`Profile` — the observed properties of a live target, inferred from
  canary probes (:mod:`wafharness.fingerprint`).

Everything here is pure data. No module in this file performs I/O, which is what
lets the whole search engine run in CI without a network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence, Tuple


# ══════════════════════════════════════════════════════════════════════════════
#  Transform
# ══════════════════════════════════════════════════════════════════════════════


class Family(str, Enum):
    """Which stage of the cascade a transform belongs to.

    The family is not cosmetic: two transforms in the same family are
    *substitutable* (a stack applies at most one charset fix-up), while
    transforms in different families compose. The search engine relies on this
    when it decides which edits are meaningful.
    """

    DECODING = "decoding"
    FRAMING = "framing"
    NORMALIZING = "normalizing"
    INSPECTION = "inspection"


@dataclass(frozen=True)
class Transform:
    """One rewrite step: ``bytes -> bytes``.

    ``idempotent`` is a promise the engine uses to avoid exploring a derivation
    that applies the same transform twice for no reason. It is a claim about the
    *implementation*, so a transform that lies here makes the search wider, never
    wrong — a conservative ``False`` simply costs a little time.
    """

    name: str
    family: Family
    apply: Callable[[bytes], bytes]
    idempotent: bool = False

    def __call__(self, data: bytes) -> bytes:
        return self.apply(data)

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return self.name


# ══════════════════════════════════════════════════════════════════════════════
#  Stack
# ══════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Stack:
    """A named cascade: what a component does to bytes before deciding.

    ``decode`` and ``normalize`` are ordered — order is the whole point, since
    "decode then normalize" and "normalize then decode" are different functions
    and that difference is itself a bypass class.

    ``sensitive_tokens`` is what the component *acts on*: a WAF blocks when one
    appears after normalization, an application executes when one appears after
    decoding. Comparing the two token sets is how the engine decides whether a
    witness is interesting.
    """

    name: str
    decode: Tuple[Transform, ...] = ()
    normalize: Tuple[Transform, ...] = ()
    #: Characters the stack rejects outright, before any normalisation.
    forbidden: Tuple[bytes, ...] = ()
    #: Free-form notes that end up in the report (vendor, version, caveat).
    notes: str = ""

    def run(self, data: bytes) -> Tuple[bytes, Optional[str]]:
        """Apply the cascade. Returns ``(view, rejection_reason)``.

        A rejection is a legitimate outcome, not an error: "this stack refuses
        the input" is exactly what makes a witness interesting when the other
        stack accepts it.
        """
        for marker in self.forbidden:
            if marker and marker in data:
                return b"", f"forbidden byte {marker!r}"

        view = data
        for step in self.decode:
            try:
                view = step.apply(view)
            except Exception as exc:  # noqa: BLE001 - a broken decoder is data
                return b"", f"{step.name} failed: {type(exc).__name__}"

        for step in self.normalize:
            try:
                view = step.apply(view)
            except Exception as exc:  # noqa: BLE001
                return b"", f"{step.name} failed: {type(exc).__name__}"

        return view, None

    def accepts(self, data: bytes) -> bool:
        view, rejection = self.run(data)
        return rejection is None

    @property
    def pipeline(self) -> str:
        steps = [t.name for t in self.decode] + [t.name for t in self.normalize]
        return " -> ".join(steps) if steps else "(identity)"

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "pipeline": self.pipeline,
            "decode": [t.name for t in self.decode],
            "normalize": [t.name for t in self.normalize],
            "forbidden": [m.decode("latin-1") for m in self.forbidden],
            "notes": self.notes,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  Divergence
# ══════════════════════════════════════════════════════════════════════════════


class DivergenceKind(str, Enum):
    """How the two stacks came apart.

    Keeping these separate matters operationally: a ``HIDDEN FROM WAF`` means
    the payload reaches the backend intact (execute it), while a
    ``REWRITTEN BY WAF`` means the backend receives something different from
    what was sent (useful for smuggling, useless for direct execution).
    """

    #: The WAF rejects, the backend accepts. The classic bypass.
    HIDDEN_FROM_WAF = "hidden_from_waf"
    #: The WAF accepts but its view differs from the backend's view.
    REWRITTEN = "rewritten"
    #: The WAF rejects everything the backend accepts, including the witness.
    NO_GAP = "no_gap"
    #: Both reject, or both see the same thing.
    DEAD_END = "dead_end"


@dataclass(frozen=True)
class Divergence:
    """A witness where two stacks disagree, with the evidence for it."""

    left: str
    right: str
    witness: bytes
    kind: DivergenceKind
    #: What each stack ended up looking at.
    left_view: bytes
    right_view: bytes
    left_rejection: Optional[str] = None
    right_rejection: Optional[str] = None
    #: The tokens that made the witness interesting in the first place.
    tokens: Tuple[str, ...] = ()
    #: Which transform names differ between the two pipelines.
    differing_steps: Tuple[str, ...] = ()

    @property
    def severity(self) -> int:
        """Ranking used to order the report. Higher is more actionable."""
        if self.kind is DivergenceKind.HIDDEN_FROM_WAF:
            return 100 + len(self.tokens) * 10
        if self.kind is DivergenceKind.REWRITTEN:
            return 40 + len(self.tokens) * 5
        return 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "left": self.left,
            "right": self.right,
            "kind": self.kind.value,
            "severity": self.severity,
            "witness": self.witness.decode("latin-1"),
            "witness_hex": self.witness.hex(),
            "left_view": self.left_view.decode("latin-1"),
            "right_view": self.right_view.decode("latin-1"),
            "left_rejection": self.left_rejection,
            "right_rejection": self.right_rejection,
            "tokens": list(self.tokens),
            "differing_steps": list(self.differing_steps),
        }


# ══════════════════════════════════════════════════════════════════════════════
#  Profile — what a live target was observed to do
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class Observation:
    """One canary probe and what came back."""

    canary: str
    sent: bytes
    received: bytes
    decided: str          # blocked | echoed | rewritten | ignored

    def to_dict(self) -> Dict[str, object]:
        return {
            "canary": self.canary,
            "decided": self.decided,
            "sent": self.sent.decode("latin-1")[:120],
            "received": self.received.decode("latin-1")[:120],
        }


@dataclass
class Profile:
    """A best-guess stack for a live target, assembled from observations.

    ``confidence`` is per-transform, not global: a target can confidently apply
    URL decoding and remain unknown about Unicode normalization. Collapsing that
    into one number would hide exactly the information an operator needs.
    """

    target: str = ""
    vendor: str = ""
    #: transform name -> confidence in [0, 1]
    detected: Dict[str, float] = field(default_factory=dict)
    observations: List[Observation] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add(self, transform: str, confidence: float) -> None:
        current = self.detected.get(transform, 0.0)
        self.detected[transform] = max(current, min(1.0, confidence))

    def has(self, transform: str) -> bool:
        return self.detected.get(transform, 0.0) >= 0.5

    def note(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "vendor": self.vendor,
            "detected": {name: round(value, 2)
                         for name, value in sorted(self.detected.items())},
            "observations": [o.to_dict() for o in self.observations],
            "warnings": list(self.warnings),
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "Profile":
        """Rebuild a profile from :meth:`to_dict` output.

        This is what makes a measurement reusable: a profile captured once can
        be re-planned offline, compared across runs, or committed as a fixture
        without re-sending the canaries. Unknown keys are ignored and malformed
        entries are skipped rather than raising — a truncated report should
        still plan the evidence it does contain.
        """
        if not isinstance(payload, dict):
            raise ValueError("profile payload must be a JSON object")

        profile = cls(
            target=str(payload.get("target", "") or ""),
            vendor=str(payload.get("vendor", "") or ""),
        )

        detected = payload.get("detected") or {}
        if isinstance(detected, dict):
            for name, value in detected.items():
                try:
                    profile.add(str(name), float(value))
                except (TypeError, ValueError):
                    continue

        observations = payload.get("observations") or []
        if isinstance(observations, list):
            for entry in observations:
                if not isinstance(entry, dict):
                    continue
                try:
                    profile.observations.append(Observation(
                        canary=str(entry.get("canary", "")),
                        sent=str(entry.get("sent", "")).encode(
                            "latin-1", "replace"),
                        received=str(entry.get("received", "")).encode(
                            "latin-1", "replace"),
                        decided=str(entry.get("decided", "")),
                    ))
                except (TypeError, ValueError):
                    continue

        warnings = payload.get("warnings") or []
        if isinstance(warnings, list):
            for warning in warnings:
                profile.note(str(warning))

        return profile


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════


def differing(left: Stack, right: Stack) -> Tuple[str, ...]:
    """Names of the transforms that are not common to both pipelines.

    Used purely for reporting: naming the step explains *why* a witness works,
    which is the difference between a bypass list and a bypass model.
    """
    left_names = {t.name for t in left.decode} | {t.name for t in left.normalize}
    right_names = {t.name for t in right.decode} | {t.name for t in right.normalize}
    return tuple(sorted(left_names.symmetric_difference(right_names)))


def pipeline_of(stack: Stack) -> Sequence[str]:
    return [t.name for t in stack.decode] + [t.name for t in stack.normalize]
