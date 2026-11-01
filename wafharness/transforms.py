"""The rewrite primitives.

Each transform models something a real component actually does to a request, and
each is documented with the stack that performs it. The point is not to be
exhaustive — it is to be *faithful*: a transform that does not match reality
produces a divergence that does not exist, which is worse than a missing one.

Design rules every transform here follows:

* **Total.** It accepts arbitrary bytes and never raises on malformed input;
  where a real decoder would error, the transform leaves the input unchanged and
  the stack records the difference. That mirrors how lenient parsers behave and
  keeps the search space finite.
* **Named after the behaviour, not the vendor.** ``url_decode`` rather than
  ``cloudflare_decode``, because several vendors share the behaviour and one
  vendor has several.
* **Pure.** Same bytes in, same bytes out, forever. The engine memoises on this.
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import List

from wafharness.models import Family, Transform

# ══════════════════════════════════════════════════════════════════════════════
#  Decoding
# ══════════════════════════════════════════════════════════════════════════════

_PERCENT = re.compile(rb"%([0-9A-Fa-f]{2})")
_PERCENT_U = re.compile(rb"%u([0-9A-Fa-f]{4})")


def _percent_decode(data: bytes) -> bytes:
    """Decode ``%XX``. Malformed escapes are left alone, as lenient parsers do."""
    return _PERCENT.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def url_decode(data: bytes) -> bytes:
    """Single URL-decode.

    Performed by essentially every WAF *and* every backend, which is why a single
    decode is never interesting on its own — the divergences appear at depth two
    and above.
    """
    return _percent_decode(data)


def url_decode_plus(data: bytes) -> bytes:
    """URL-decode with ``+`` read as space (form encoding).

    ``application/x-www-form-urlencoded`` backends do this; a WAF inspecting a
    raw body as text does not. A payload that reads as benign with a literal
    ``+`` and as a space after decoding is a classic application-layer bypass.
    """
    return _percent_decode(data.replace(b"+", b" "))


def url_decode_twice(data: bytes) -> bytes:
    """Decode twice.

    Models the recursion bug every encoder/decoder pair eventually has: the WAF
    decodes once and inspects, the backend decodes twice and executes. The input
    that exploits it is double-encoded (``%253C`` for ``<``).
    """
    return _percent_decode(_percent_decode(data))


def percent_u_decode(data: bytes) -> bytes:
    """Decode IIS-style ``%uXXXX`` escapes."""
    def replace(match: re.Match) -> bytes:
        value = int(match.group(1), 16)
        return chr(value).encode("utf-8", "replace")

    return _PERCENT_U.sub(replace, data)


def html_entity_decode(data: bytes) -> bytes:
    """Decode HTML entities (``&#60;``, ``&lt;``).

    Applied by template engines and by some WAF decoders. ``html.unescape`` is
    used because it handles named, decimal and hex forms the way browsers do.
    """
    try:
        return html.unescape(data.decode("utf-8", "replace")).encode("utf-8")
    except Exception:  # noqa: BLE001 - never let a decoder break the search
        return data


def unicode_escape_decode(data: bytes) -> bytes:
    """Decode ``\\uXXXX`` and ``\\xXX`` sequences.

    Java's ``MessageFormat``, JavaScript string literals and .NET's
    ``Uri.UnescapeDataString`` all accept these; a WAF that only reaches for
    percent-encoding decodes nothing here.
    """
    def replace(match: re.Match) -> bytes:
        escape = match.group(0)
        try:
            if escape.startswith(b"\\u"):
                return chr(int(escape[2:], 16)).encode("utf-8", "replace")
            return bytes([int(escape[2:], 16)])
        except (ValueError, OverflowError):
            return escape

    return re.sub(rb"\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}", replace, data)


def backslash_unescape(data: bytes) -> bytes:
    """Collapse backslash escapes (``\\/`` -> ``/``).

    JSON decoders and PHP's ``magic_quotes``-era code both do this. A WAF that
    inspects before this step sees ``<\\/script>`` and misses the tag.
    """
    return re.sub(rb"\\(.)", lambda m: m.group(1), data, flags=re.S)


def strip_nul(data: bytes) -> bytes:
    """Remove NUL bytes.

    Windows APIs truncate at NUL; PHP's filesystem functions historically did
    too. A WAF matching the whole string sees a harmless prefix, the backend sees
    only the prefix as well — except where it does not, and that asymmetry is the
    bug being hunted.
    """
    return data.replace(b"\x00", b"")


def utf7_decode(data: bytes) -> bytes:
    """Decode UTF-7 (``+ADw-`` for ``<``).

    Legacy IIS and some Active Directory paths accept it. Rare, but it is the
    example par excellence of "the WAF never heard of this charset".
    """
    try:
        return data.decode("utf-7", "strict").encode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return data


def charset_latin1(data: bytes) -> bytes:
    """Reinterpret bytes as Latin-1 and re-encode as UTF-8.

    Happens whenever a component mis-detects the charset of a body. It changes
    the byte string without changing the intent, which is exactly the shape of a
    parsing differential.
    """
    try:
        return data.decode("latin-1").encode("utf-8")
    except Exception:  # noqa: BLE001
        return data


# ══════════════════════════════════════════════════════════════════════════════
#  Normalising
# ══════════════════════════════════════════════════════════════════════════════


def lowercase(data: bytes) -> bytes:
    """ASCII-only lowercasing.

    WAF rules are usually case-insensitive; a backend that is *not* (a Linux
    filesystem, a case-sensitive template key) turns case into a divergence.
    """
    return data.lower()


def nfkc(data: bytes) -> bytes:
    """Unicode NFKC.

    Maps fullwidth ``＜`` to ``<``, ligatures to letters, and compatibility
    characters to their canonical form. Browsers and most servers normalise;
    a WAF matching raw bytes does not, and vice versa.
    """
    try:
        return unicodedata.normalize("NFKC", data.decode("utf-8", "replace")) \
            .encode("utf-8")
    except Exception:  # noqa: BLE001
        return data


def collapse_whitespace(data: bytes) -> bytes:
    """Collapse runs of whitespace to a single space.

    HTML parsers and many request wrappers do this. It matters for payloads that
    rely on a *second* whitespace character to break a filter's regex.
    """
    return re.sub(rb"\s+", b" ", data)


def strip_sql_comments(data: bytes) -> bytes:
    """Remove ``/* ... */`` blocks.

    ModSecurity's CRS strips comments before matching; MySQL also strips them
    before parsing. The divergence is real when only one of the two strips them
    *and* the payload needs the comment as a separator.

    The comment is removed **without** inserting a space. Replacing it with a
    space is what a naive implementation does, and it is wrong for the case that
    matters: ``UN/**/ION`` is ``UNION`` to MySQL and to CRS, but ``UN ION`` to an
    implementation that substitutes. That difference made the canary for this
    transform report "not detected" against every stack — the fingerprint was
    silently blind to comment stripping.
    """
    return re.sub(rb"/\*.*?\*/", b"", data, flags=re.S)


def strip_html_comments(data: bytes) -> bytes:
    """Remove ``<!-- ... -->`` blocks."""
    return re.sub(rb"<!--.*?-->", b" ", data, flags=re.S)


def backslash_strip(data: bytes) -> bytes:
    """Remove backslashes entirely (MySQL's escape convention).

    MySQL treats ``\\<`` as a literal ``<`` but some filters read ``\\<`` as an
    escaped, therefore safe, character. Only one of them is right.
    """
    return data.replace(b"\\", b"")


def trim(data: bytes) -> bytes:
    """Strip surrounding whitespace."""
    return data.strip()


# ══════════════════════════════════════════════════════════════════════════════
#  Registry
# ══════════════════════════════════════════════════════════════════════════════


def _t(name: str, family: Family, fn, idempotent: bool = False) -> Transform:
    return Transform(name=name, family=family, apply=fn, idempotent=idempotent)


#: Every transform the engine may use, keyed by name.
#:
#: ``idempotent`` is set only where applying twice is provably a no-op for the
#: inputs the engine generates. A wrong ``True`` narrows the search and could hide
#: a divergence, so the flag is conservative.
TRANSFORMS = {
    # decoding
    "url_decode": _t("url_decode", Family.DECODING, url_decode),
    "url_decode_plus": _t("url_decode_plus", Family.DECODING, url_decode_plus),
    "url_decode_twice": _t("url_decode_twice", Family.DECODING, url_decode_twice),
    "percent_u": _t("percent_u", Family.DECODING, percent_u_decode),
    "html_entity": _t("html_entity", Family.DECODING, html_entity_decode),
    "unicode_escape": _t("unicode_escape", Family.DECODING, unicode_escape_decode),
    "backslash_unescape": _t("backslash_unescape", Family.DECODING,
                             backslash_unescape),
    "strip_nul": _t("strip_nul", Family.DECODING, strip_nul, idempotent=True),
    "utf7": _t("utf7", Family.DECODING, utf7_decode),
    "latin1": _t("latin1", Family.DECODING, charset_latin1),

    # normalising
    "lowercase": _t("lowercase", Family.NORMALIZING, lowercase, idempotent=True),
    "nfkc": _t("nfkc", Family.NORMALIZING, nfkc, idempotent=True),
    "collapse_ws": _t("collapse_ws", Family.NORMALIZING, collapse_whitespace,
                      idempotent=True),
    "strip_sql_comments": _t("strip_sql_comments", Family.NORMALIZING,
                             strip_sql_comments),
    "strip_html_comments": _t("strip_html_comments", Family.NORMALIZING,
                              strip_html_comments),
    "backslash_strip": _t("backslash_strip", Family.NORMALIZING, backslash_strip,
                          idempotent=True),
    "trim": _t("trim", Family.NORMALIZING, trim, idempotent=True),
}


def by_family(family: Family) -> List[Transform]:
    """All transforms of one family, in registry order."""
    return [t for t in TRANSFORMS.values() if t.family is family]


def get(name: str) -> Transform:
    """Look a transform up by name, with an error that names the culprit."""
    try:
        return TRANSFORMS[name]
    except KeyError:
        raise KeyError(
            f"unknown transform {name!r}; known: {', '.join(sorted(TRANSFORMS))}"
        ) from None


def resolve(names) -> tuple:
    """Turn an iterable of names into a tuple of transforms, preserving order."""
    return tuple(get(name) for name in names)
