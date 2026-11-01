"""wafharness — WAF bypass as divergence between rewriting systems.

The premise: a WAF and a backend both rewrite the request before deciding
anything. Where their rewrite cascades disagree, they disagree about what the
request *says* — and that disagreement is the bypass.

Public surface:

* :class:`Stack` — a named cascade (decode, frame, normalize, inspect).
* :class:`Divergence` — two stacks, a witness, and what each one saw.
* :func:`engine.search` — construct witnesses, do not guess them.
* :func:`fingerprint.probe` — infer a live target's cascade with canary tokens.
* :func:`plan.build` — join a measured profile to the divergence search.
* :func:`live.compare` — send the same canaries to a front door and an origin.
* :func:`confirm.assess` — turn a single-URL send receipt into an evidence level.
* :func:`identity.identify` — name the measured side, evidence and caveats.
* :mod:`finding` — bind a witness to the exact request and response.

The analysis modules are pure unless a transport callable is supplied. Live I/O
lives in the CLI transports and :mod:`wafharness.sender`: ``crs`` (public
sandbox), ``identify``/``profile --url``/``plan --url`` (canaries),
``compare --yes`` (canaries to two endpoints), and ``confirm --yes`` /
``verify --yes`` / ``send --yes`` (witnesses).
"""

from wafharness.models import (
    Divergence,
    DivergenceKind,
    Family,
    Observation,
    Profile,
    Stack,
    Transform,
)

__all__ = [
    "Divergence",
    "DivergenceKind",
    "Family",
    "Observation",
    "Profile",
    "Stack",
    "Transform",
    "__version__",
]

__version__ = "0.1.0"
