"""Framing: how a message is split into fields.

Decoding and normalisation act on *bytes*. Framing decides **where one field ends
and the next begins** — and that boundary is negotiated by rules that differ
between implementations far more than byte-level decoding does.

This is the layer the original motivation for the project lived in. A multipart
body whose `filename` parameter is RFC 2047-encoded is one message with two
readings:

    filename="=?UTF-8?B?PD9waHAgZWNobyAxOz8+?="

A framing that decodes the encoded-word sees a PHP tag. A framing that treats it
as opaque text sees base64 noise. Neither is wrong; they are different rules, and
the request means two things at once.

Seven ambiguities are modelled, each a real class:

* **Duplicate keys** — first-wins or last-wins. A WAF checks the first, PHP's
  ``$_POST`` keeps the last.
* **Parameter encoding** — is ``filename`` RFC 2047 decoded, or literal?
* **Boundary strictness** — must the delimiter be preceded by ``\\r\\n``, or is
  a bare ``\\n`` accepted?
* **Header line endings** — does a header block accept bare ``\\n``, or only
  ``\\r\\n``? A proxy may normalise one and reject the other.
* **Header duplicates** — two copies of the same header name; the inspector may
  read the first while the application reads the last.
* **Cookie duplicates** — the same rule, one level deeper: the ``Cookie`` header
  is itself a list of ``name=value`` pairs.
* **Parameter quoting** — is ``filename=evil.php`` without quotes legal?

Everything here is pure: bytes in, list of ``(key, value)`` out.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

Field = Tuple[bytes, bytes]


# ══════════════════════════════════════════════════════════════════════════════
#  Model
# ══════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Frame:
    """A named set of splitting rules.

    ``parse`` must preserve duplicates, in order. Collapsing them inside the
    parser would destroy exactly the information the divergence search needs, so
    the "which one wins" decision is a separate, explicit step.
    """

    name: str
    parse: Callable[[bytes], List[Field]]

    def fields(self, data: bytes) -> List[Field]:
        try:
            return self.parse(data)
        except Exception:  # noqa: BLE001 - a broken parser is data, not an error
            return []

    def value(self, data: bytes, key: bytes) -> Optional[bytes]:
        """First or last occurrence, depending on the frame's own rules."""
        raise NotImplementedError

    def to_dict(self) -> Dict[str, str]:
        return {"name": self.name}


#: Frames differ in how they resolve duplicates, so that is a property of the
#: frame rather than of the caller.
@dataclass(frozen=True)
class KeyedFrame(Frame):
    """A frame that also knows which duplicate wins."""

    last_wins: bool = True

    def value(self, data: bytes, key: bytes) -> Optional[bytes]:
        matches = [value for name, value in self.fields(data) if name == key]
        if not matches:
            return None
        return matches[-1] if self.last_wins else matches[0]


# ══════════════════════════════════════════════════════════════════════════════
#  Parsers
# ══════════════════════════════════════════════════════════════════════════════

_RFC2047 = re.compile(rb"=\?([A-Za-z0-9_-]+)\?([BbQq])\?([^?]*)\?=")


def rfc2047_decode(data: bytes) -> bytes:
    """Decode RFC 2047 encoded-words (``=?UTF-8?B?...?=``).

    Mail headers require this; form parameters almost never do. PHP's multipart
    parser is widely reported to apply it to ``filename`` anyway, which is why an
    encoded ``<?php`` reaches the filesystem as a tag while the WAF saw base64.
    """
    def replace(match: re.Match) -> bytes:
        _charset, encoding, payload = match.groups()
        try:
            if encoding.upper() == b"B":
                return base64.b64decode(payload + b"===")
            # Q-encoding: underscore is space, =XX is a byte.
            decoded = payload.replace(b"_", b" ")
            return re.sub(rb"=([0-9A-Fa-f]{2})",
                          lambda m: bytes([int(m.group(1), 16)]), decoded)
        except (binascii.Error, ValueError):
            return match.group(0)

    return _RFC2047.sub(replace, data)


def rfc2047_encode(data: bytes) -> bytes:
    """Inverse of :func:`rfc2047_decode`, used to build witnesses."""
    encoded = base64.b64encode(data).rstrip(b"=")
    return b"=?UTF-8?B?" + encoded + b"?="


def parse_query_lenient(data: bytes) -> List[Field]:
    """Split on ``&`` and ``;``, which different stacks accept differently."""
    fields: List[Field] = []
    for chunk in re.split(rb"[&;]", data):
        if not chunk:
            continue
        name, _, value = chunk.partition(b"=")
        fields.append((name, value))
    return fields


def parse_query_strict(data: bytes) -> List[Field]:
    """Split on ``&`` only; a ``;`` is part of the value."""
    fields: List[Field] = []
    for chunk in data.split(b"&"):
        if not chunk:
            continue
        name, _, value = chunk.partition(b"=")
        fields.append((name, value))
    return fields


def parse_multipart_strict(data: bytes, boundary: bytes = b"__B__") -> List[Field]:
    """Multipart with a strict ``\\r\\n`` delimiter requirement."""
    separator = b"--" + boundary
    fields: List[Field] = []
    for part in data.split(separator):
        if not part.strip() or part.startswith(b"--"):
            continue
        # A strict parser only accepts a part that starts with CRLF.
        if not part.startswith(b"\r\n"):
            continue
        body = part[2:]
        headers, _, content = body.partition(b"\r\n\r\n")
        fields.append((_name_of(headers), content))
    return fields


def parse_multipart_lenient(data: bytes, boundary: bytes = b"__B__") -> List[Field]:
    """Multipart that accepts a bare ``\\n`` delimiter as well as ``\\r\\n``."""
    separator = b"--" + boundary
    fields: List[Field] = []
    for part in data.split(separator):
        if not part.strip() or part.startswith(b"--"):
            continue
        part = part.lstrip(b"\r\n")
        # Prefer the RFC-correct separator, fall back to the bare one. Writing
        # this as a tuple unpacking trick was unreadable and was the only place
        # in the module that was not obvious at a glance.
        if b"\r\n\r\n" in part:
            headers, _, content = part.partition(b"\r\n\r\n")
        else:
            headers, _, content = part.partition(b"\n\n")
        fields.append((_name_of(headers), content))
    return fields


def _name_of(headers: bytes) -> bytes:
    """Extract ``name=`` from a Content-Disposition header, quoted or not."""
    match = re.search(rb'name="?([^";\r\n]+)"?', headers, re.I)
    return match.group(1) if match else b""


def parse_multipart_rfc2047(data: bytes, boundary: bytes = b"__B__") -> List[Field]:
    """Multipart whose ``name`` parameter goes through RFC 2047 decoding."""
    decoded = rfc2047_decode(data)
    return parse_multipart_lenient(decoded, boundary)


def parse_headers_strict(data: bytes) -> List[Field]:
    """Parse a header block that must use ``\\r\\n`` line endings.

    A line containing a bare ``\\n`` or ``\\r`` is not a header at all: the
    strict reader rejects the block rather than guessing where the line ended.
    Names are lower-cased because HTTP header names are case-insensitive; values
    keep their case.
    """
    fields: List[Field] = []
    for raw in data.split(b"\r\n"):
        if b"\r" in raw or b"\n" in raw:
            continue
        if not raw.strip():
            continue
        name, separator, value = raw.partition(b":")
        if not separator:
            continue
        fields.append((name.strip().lower(), value.strip()))
    return fields


def parse_headers_lenient(data: bytes) -> List[Field]:
    """Parse a header block that accepts bare ``\\n`` and obs-fold continuations.

    Obs-fold is the old HTTP/1.0 rule that a line starting with a space or tab
    continues the previous header. It was deprecated but never disappeared from
    parsers, which is exactly the kind of rule that creates a differential.
    """
    normalized = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    fields: List[Field] = []
    for raw in normalized.split(b"\n"):
        if raw[:1] in (b" ", b"\t") and fields:
            name, value = fields[-1]
            fields[-1] = (name, value + b" " + raw.strip())
            continue
        name, separator, value = raw.partition(b":")
        if not separator:
            continue
        fields.append((name.strip().lower(), value.strip()))
    return fields


def parse_cookie_header(data: bytes) -> List[Field]:
    """Flatten ``Cookie`` headers into ``(name, value)`` pairs, duplicates kept.

    The header is split on ``;`` first and on the first ``=`` second, because a
    cookie value may contain ``=`` (base64 padding, for one). Collapsing
    duplicates here would destroy the information the comparison needs.
    """
    fields: List[Field] = []
    for name, value in parse_headers_lenient(data):
        if name != b"cookie":
            continue
        for chunk in value.split(b";"):
            key, separator, val = chunk.partition(b"=")
            key = key.strip().lower()
            if not key or not separator:
                continue
            fields.append((key, val.strip()))
    return fields


def parse_json_pairs(data: bytes) -> List[Field]:
    """Flatten a JSON object into ``(key, raw value)`` pairs, duplicates kept.

    ``json.loads`` would silently drop one of two duplicate keys — the exact
    information this module exists to preserve. The regex-based scan is
    deliberately shallow: it only needs top-level keys, and staying shallow keeps
    it total on malformed input.
    """
    text = data.strip()
    if text.startswith(b"{"):
        text = text[1:]
    if text.endswith(b"}"):
        text = text[:-1]

    fields: List[Field] = []
    depth = 0
    start = 0
    in_string = False
    escaped = False

    for index, byte in enumerate(text):
        char = bytes([byte])
        if escaped:
            escaped = False
            continue
        if char == b"\\":
            escaped = True
        elif char == b'"':
            in_string = not in_string
        elif in_string:
            continue
        elif char in (b"{", b"["):
            depth += 1
        elif char in (b"}", b"]"):
            depth -= 1
        elif char == b"," and depth == 0:
            fields.append(_json_pair(text[start:index]))
            start = index + 1
    if start <= len(text):
        fields.append(_json_pair(text[start:]))

    return [field for field in fields if field[0]]


def _json_pair(chunk: bytes) -> Field:
    chunk = chunk.strip()
    if not chunk or b":" not in chunk:
        return (b"", b"")
    key, _, value = chunk.partition(b":")
    return (key.strip().strip(b'"'), value.strip())


# ══════════════════════════════════════════════════════════════════════════════
#  Registry
# ══════════════════════════════════════════════════════════════════════════════


def _frame(name: str, parser, last_wins: bool = True) -> KeyedFrame:
    return KeyedFrame(name=name, parse=parser, last_wins=last_wins)


#: Frames that disagree with each other on a specific, named rule.
#:
#: Each pair below is the same bytes read two ways. The divergence search walks
#: these pairs, not arbitrary combinations: two frames that differ in five ways
#: make it impossible to say which difference caused the finding.
FRAMES: Dict[str, KeyedFrame] = {
    "query-last-wins": _frame("query-last-wins", parse_query_lenient, True),
    "query-first-wins": _frame("query-first-wins", parse_query_lenient, False),
    "query-semicolon": _frame("query-semicolon", parse_query_strict, True),
    "multipart-strict": _frame("multipart-strict", parse_multipart_strict, True),
    "multipart-lenient": _frame("multipart-lenient", parse_multipart_lenient, True),
    "multipart-rfc2047": _frame("multipart-rfc2047", parse_multipart_rfc2047, True),
    "json-last-wins": _frame("json-last-wins", parse_json_pairs, True),
    "json-first-wins": _frame("json-first-wins", parse_json_pairs, False),
    "header-first-wins": _frame("header-first-wins", parse_headers_strict, False),
    "header-last-wins": _frame("header-last-wins", parse_headers_strict, True),
    "header-strict": _frame("header-strict", parse_headers_strict, True),
    "header-lenient": _frame("header-lenient", parse_headers_lenient, True),
    "cookie-first-wins": _frame("cookie-first-wins", parse_cookie_header, False),
    "cookie-last-wins": _frame("cookie-last-wins", parse_cookie_header, True),
}

#: Pairs that differ in exactly one rule, so a finding is attributable.
DISAGREEING_PAIRS: Sequence[Tuple[str, str]] = (
    ("query-first-wins", "query-last-wins"),
    ("query-semicolon", "query-last-wins"),
    ("multipart-strict", "multipart-lenient"),
    ("multipart-lenient", "multipart-rfc2047"),
    ("json-first-wins", "json-last-wins"),
    ("header-first-wins", "header-last-wins"),
    ("header-strict", "header-lenient"),
    ("cookie-first-wins", "cookie-last-wins"),
)


def get(name: str) -> KeyedFrame:
    try:
        return FRAMES[name]
    except KeyError:
        raise KeyError(
            f"unknown frame {name!r}; known: {', '.join(sorted(FRAMES))}"
        ) from None


def names() -> List[str]:
    return sorted(FRAMES)
