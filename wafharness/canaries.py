"""Canary tokens: inputs whose fate reveals a stack's rewrite rules.

Each canary is a pair: bytes that a *particular* transform would change, plus a
way to tell whether it did. Sending a canary to a live target and reading the
response narrows the set of stacks the target could be running — turning the
modelled matrix into a measured one.

The design constraint that shapes everything here: **a canary must be observable
from the outside.** Most real applications echo nothing back, so the primary
signal is not reflection but the WAF's own decision — blocked versus allowed.
That is a weaker signal, and the fingerprint engine treats it as such: one
observation never yields high confidence.

Canaries are ordered cheapest-first so the caller can stop as soon as the profile
is decided.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from wafharness.transforms import get as get_transform


@dataclass(frozen=True)
class Canary:
    """One discriminating input.

    ``expect`` names what a stack with the given transform does differently. The
    fingerprint engine compares observed behaviour against these expectations
    rather than against a vendor name — which is why the same canary set works
    whatever the target turns out to be.
    """

    name: str
    #: The bytes to place in the request.
    payload: bytes
    #: Transform whose presence this canary detects.
    detects: str
    #: Human note explaining the discrimination.
    rationale: str
    #: What to look for when the transform *is* applied.
    marker: str = ""


def _rfc2047(value: bytes) -> bytes:
    return b"=?UTF-8?B?" + base64.b64encode(value).rstrip(b"=") + b"?="


def _build() -> List[Canary]:
    return [
        # ── decoding ────────────────────────────────────────────────────────
        Canary(
            name="percent",
            payload=b"%3Cnexus%3E",
            detects="url_decode",
            marker="<nexus>",
            rationale="a stack that percent-decodes sees a tag; one that does "
                      "not sees literal %3C",
        ),
        Canary(
            name="percent-double",
            payload=b"%253Cnexus%253E",
            detects="url_decode_twice",
            marker="<nexus>",
            rationale="only a stack that decodes twice reaches the tag",
        ),
        Canary(
            name="plus",
            payload=b"nexus+token",
            detects="url_decode_plus",
            marker="nexus token",
            rationale="'+' is a space to form decoders and a literal elsewhere",
        ),
        Canary(
            name="html-entity",
            payload=b"&#60;nexus&#62;",
            detects="html_entity",
            marker="<nexus>",
            rationale="entity decoding happens in template layers, not in most "
                      "WAF decoders",
        ),
        Canary(
            name="unicode-escape",
            payload=b"\\u003cnexus\\u003e",
            detects="unicode_escape",
            marker="<nexus>",
            rationale="Java and .NET accept \\uXXXX; percent-only stacks do not",
        ),
        Canary(
            name="percent-u",
            payload=b"%u003cnexus%u003e",
            detects="percent_u",
            marker="<nexus>",
            rationale="IIS-style escaping, ignored by everything else",
        ),
        Canary(
            name="nul",
            payload=b"nexus\x00token",
            detects="strip_nul",
            marker="nexustoken",
            rationale="NUL-tolerant parsers splice the two halves together",
        ),
        Canary(
            name="utf7",
            payload=b"+ADw-nexus+AD4-",
            detects="utf7",
            marker="<nexus>",
            rationale="legacy IIS charset; a rare but decisive marker",
        ),
        Canary(
            name="rfc2047",
            payload=_rfc2047(b"nexus"),
            detects="framing:rfc2047",
            marker="nexus",
            rationale="encoded-word decoding in form parameter names — a "
                      "framing rule, not a byte transform",
        ),
        # ── normalising ─────────────────────────────────────────────────────
        Canary(
            name="fullwidth",
            payload="＜nexus＞".encode(),
            detects="nfkc",
            marker="<nexus>",
            rationale="NFKC folding turns fullwidth brackets into real ones",
        ),
        Canary(
            name="whitespace",
            payload=b"nexus\t\ttoken",
            detects="collapse_ws",
            marker="nexus token",
            rationale="CRS and several proxies collapse runs of whitespace; a "
                      "stack that only lowercases passes the tabs through",
        ),
        Canary(
            name="case",
            payload=b"NEXUS",
            detects="lowercase",
            marker="nexus",
            rationale="case folding is silent, so this is observed through the "
                      "WAF's rule matching rather than the echoed value",
        ),
        Canary(
            name="sql-comment",
            payload=b"nex/**/us",
            detects="strip_sql_comments",
            marker="nexus",
            rationale="comment stripping reconstructs the keyword for a SQL "
                      "parser while leaving it split for a matcher",
        ),
    ]


CANARIES: List[Canary] = _build()

CANARIES_BY_NAME: Dict[str, Canary] = {c.name: c for c in CANARIES}


def get(name: str) -> Canary:
    try:
        return CANARIES_BY_NAME[name]
    except KeyError:
        raise KeyError(
            f"unknown canary {name!r}; known: {', '.join(sorted(CANARIES_BY_NAME))}"
        ) from None


def detects() -> Dict[str, List[str]]:
    """``transform -> [canary names]`` so a gap in coverage is visible."""
    mapping: Dict[str, List[str]] = {}
    for canary in CANARIES:
        mapping.setdefault(canary.detects, []).append(canary.name)
    return mapping


def for_transforms(names: Sequence[str]) -> List[Canary]:
    """Canaries that discriminate any of the given transforms."""
    wanted = set(names)
    return [c for c in CANARIES if c.detects in wanted]
