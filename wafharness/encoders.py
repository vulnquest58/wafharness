"""Encoders: the inverses of the decode transforms.

The search needs to *construct* a witness, not guess one. For that it needs to
know how to produce bytes that a given decoder will turn into a token while a
different decoder leaves alone.

Each encoder here is the inverse of one transform in :mod:`wafharness.transforms`,
and the pairing is deliberate: ``percent_encode`` produces what ``url_decode``
consumes, so "backend decodes, WAF does not" becomes "encode once". Depth two
becomes "encode twice". The engine derives the encoding chain from the pipeline
difference instead of hard-coding a list of tricks — which is the difference
between modelling and cataloguing.

Encoders are not guaranteed exact inverses: ``percent_encode`` of everything is
legal but noisy, while encoding only the interesting characters is subtler. Both
forms ship, and the engine prefers the least noisy one that still creates the
divergence, because a witness that survives a real WAF is usually the quiet one.
"""

from __future__ import annotations

import string
from typing import Callable, Dict, Iterable

#: Characters that carry meaning in the payloads this project generates. Encoding
#: only these keeps the witness readable and keeps the request small.
INTERESTING = set(b"<>'\"()[]{}/\\;&|=+-% #*\n\r\t")

FULLWIDTH_OFFSET = 0xFEE0


def percent_encode(data: bytes, aggressive: bool = False) -> bytes:
    """Percent-encode bytes.

    ``aggressive=False`` encodes only :data:`INTERESTING`, which is what a
    careful attacker does: the rest of the request looks ordinary, so a rule
    that scores suspiciousness rather than matching a pattern has less to work
    with.
    """
    out = bytearray()
    for byte in data:
        if aggressive or byte in INTERESTING or byte > 0x7E:
            out.extend(f"%{byte:02X}".encode())
        else:
            out.append(byte)
    return bytes(out)


def percent_encode_all(data: bytes) -> bytes:
    """Percent-encode every byte. Noisier, but guarantees a full decode."""
    return percent_encode(data, aggressive=True)


def percent_encode_twice(data: bytes) -> bytes:
    """Double-encode, so a single decode yields the still-encoded form.

    This is the witness for backend-decodes-twice / WAF-decodes-once: after one
    decode the WAF sees ``%3Cscript%3E`` (harmless text), the backend decodes
    again and sees the tag.
    """
    return percent_encode(percent_encode(data))


def form_encode(data: bytes) -> bytes:
    """Form encoding: percent escapes plus ``+`` for space.

    The ``+`` matters because it is where ``url_decode_plus`` and ``url_decode``
    disagree — a payload that reads as a literal plus to one side and a space to
    the other.
    """
    return percent_encode(data).replace(b"%20", b"+")


def html_encode(data: bytes) -> bytes:
    """Decimal HTML entities for the interesting characters."""
    out = bytearray()
    for byte in data:
        if byte in (0x3C, 0x3E, 0x26, 0x22, 0x27):     # < > & " '
            out.extend(f"&#{byte};".encode())
        else:
            out.append(byte)
    return bytes(out)


def hex_html_encode(data: bytes) -> bytes:
    """Hexadecimal HTML entities — a different spelling of the same character."""
    out = bytearray()
    for byte in data:
        if byte in (0x3C, 0x3E, 0x26, 0x22, 0x27):
            out.extend(f"&#x{byte:02x};".encode())
        else:
            out.append(byte)
    return bytes(out)


def unicode_escape_encode(data: bytes) -> bytes:
    """``\\uXXXX`` escapes for non-alphanumeric bytes.

    Java's ``MessageFormat`` and JavaScript string literals accept these, and a
    WAF that only reaches for percent-decoding sees plain text.
    """
    out = bytearray()
    for byte in data:
        if byte in INTERESTING or byte > 0x7E:
            out.extend(f"\\u{byte:04x}".encode())
        else:
            out.append(byte)
    return bytes(out)


def percent_u_encode(data: bytes) -> bytes:
    """IIS-style ``%uXXXX`` escapes."""
    out = bytearray()
    for byte in data:
        if byte in INTERESTING or byte > 0x7E:
            out.extend(f"%u{byte:04x}".encode())
        else:
            out.append(byte)
    return bytes(out)


def fullwidth_encode(data: bytes) -> bytes:
    """Map ASCII printable characters to their fullwidth forms.

    NFKC folding turns ``＜`` back into ``<``. A stack that normalises sees the
    tag; one that matches raw bytes does not.
    """
    out = bytearray()
    for byte in data:
        if 0x21 <= byte <= 0x7E:
            out.extend(chr(byte + FULLWIDTH_OFFSET).encode("utf-8"))
        else:
            out.append(byte)
    return bytes(out)


def backslash_escape_encode(data: bytes) -> bytes:
    """Escape the interesting characters with a backslash."""
    out = bytearray()
    for byte in data:
        if byte in INTERESTING:
            out.append(0x5C)
        out.append(byte)
    return bytes(out)


def comment_break_encode(data: bytes) -> bytes:
    """Insert SQL comment breaks between keyword characters.

    ``UN/**/ION`` is two tokens to a naive filter and one to a SQL parser that
    strips comments first. The encoder needs a keyword to interleave, so it
    splits on runs of letters.
    """
    out = bytearray()
    run = 0
    for byte in data:
        if 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A:
            run += 1
            out.append(byte)
            if run == 3:
                out.extend(b"/**/")
                run = 0
        else:
            run = 0
            out.append(byte)
    return bytes(out)


def utf7_encode(data: bytes) -> bytes:
    """UTF-7 encode, producing the ``+ADw-`` style that legacy IIS accepts."""
    try:
        return data.decode("latin-1").encode("utf-7")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return data


#: Encoder registry, keyed by the name of the transform it inverts.
ENCODERS: Dict[str, Callable[[bytes], bytes]] = {
    "url_decode": percent_encode,
    "url_decode_plus": form_encode,
    "url_decode_twice": percent_encode_twice,
    "html_entity": html_encode,
    "unicode_escape": unicode_escape_encode,
    "percent_u": percent_u_encode,
    "nfkc": fullwidth_encode,
    "backslash_unescape": backslash_escape_encode,
    "strip_sql_comments": comment_break_encode,
    "utf7": utf7_encode,
}


def for_transform(name: str) -> Callable[[bytes], bytes]:
    """Return the encoder that defeats a given decode transform.

    A transform with no encoder simply returns the input unchanged: it means the
    engine cannot *construct* a witness for that step, only observe one. That is
    reported rather than silently ignored.
    """
    return ENCODERS.get(name, lambda data: data)


def has_encoder(name: str) -> bool:
    return name in ENCODERS
