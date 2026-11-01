"""Transform and encoder tests.

A transform that does not match reality produces a divergence that does not
exist, so these pin the byte-level behaviour of each primitive rather than
asserting it "runs without error".
"""

from __future__ import annotations

import pytest

from wafharness import encoders, transforms
from wafharness.models import Family


# ── decoding ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("raw,expected", [
    (b"%3Cscript%3E", b"<script>"),
    (b"%3c%3e", b"<>"),
    (b"a%20b", b"a b"),
    (b"plain", b"plain"),
])
def test_url_decode(raw, expected):
    assert transforms.url_decode(raw) == expected


def test_url_decode_leaves_malformed_escapes_alone():
    """A lenient parser does not error on ``%ZZ``; it passes it through."""
    assert transforms.url_decode(b"%ZZ%3") == b"%ZZ%3"


def test_url_decode_plus_converts_only_plus():
    assert transforms.url_decode_plus(b"a+b%2Bc") == b"a b+c"


def test_plain_url_decode_keeps_plus():
    """This asymmetry against ``url_decode_plus`` is a real bypass class."""
    assert transforms.url_decode(b"a+b") == b"a+b"


def test_url_decode_twice_is_not_url_decode():
    assert transforms.url_decode(b"%253C") == b"%3C"
    assert transforms.url_decode_twice(b"%253C") == b"<"


def test_percent_u_decode():
    assert transforms.percent_u_decode(b"%u003c") == b"<"


def test_html_entity_decode_handles_named_and_numeric():
    assert transforms.html_entity_decode(b"&#60;a&#62;") == b"<a>"
    assert transforms.html_entity_decode(b"&lt;a&gt;") == b"<a>"
    assert transforms.html_entity_decode(b"&#x3c;a&#x3e;") == b"<a>"


def test_unicode_escape_decode():
    assert transforms.unicode_escape_decode(b"\\u003cscript\\u003e") == b"<script>"
    assert transforms.unicode_escape_decode(b"\\x3c") == b"<"


def test_backslash_unescape():
    assert transforms.backslash_unescape(b"<\\/script>") == b"</script>"


def test_strip_nul():
    assert transforms.strip_nul(b"a\x00b") == b"ab"


def test_utf7_decode_handles_the_iis_form():
    assert transforms.utf7_decode(b"+ADw-script+AD4-") == b"<script>"


def test_utf7_decode_is_total_on_garbage():
    """A decoder must never raise: the search would lose the branch silently."""
    assert transforms.utf7_decode(b"\xff\xfe\x00garbage") is not None


# ── normalising ─────────────────────────────────────────────────────────────


def test_lowercase_is_ascii_lowercase():
    assert transforms.lowercase(b"ABC") == b"abc"


def test_nfkc_maps_fullwidth_to_ascii():
    """NFKC is how ``＜script＞`` becomes a real tag at the backend."""
    assert transforms.nfkc("＜script＞".encode()) == b"<script>"


def test_nfkc_leaves_normal_ascii_alone():
    assert transforms.nfkc(b"<script>") == b"<script>"


def test_collapse_whitespace():
    assert transforms.collapse_whitespace(b"a\n\n  b") == b"a b"


def test_strip_sql_comments_joins_the_halves():
    """``UN/**/ION`` must become ``UNION``, not ``UN ION``.

    Inserting a space is the naive implementation, and it breaks the only case
    that matters: MySQL and CRS both reconstruct the keyword, so a space here
    would make the tool blind to comment stripping entirely.
    """
    assert transforms.strip_sql_comments(b"UN/**/ION") == b"UNION"


def test_comment_encoder_survives_the_strip():
    payload = b"UNIONSELECT"
    encoded = encoders.comment_break_encode(payload)
    assert transforms.strip_sql_comments(encoded) == payload


def test_backslash_strip():
    """MySQL reads ``\\<`` as ``<``; a strip-only filter reads it as safe."""
    assert transforms.backslash_strip(b"\\<script\\>") == b"<script>"


# ── encoders ────────────────────────────────────────────────────────────────


def test_percent_encode_survives_a_url_decode():
    payload = b"<script>"
    assert transforms.url_decode(encoders.percent_encode(payload)) == payload


def test_percent_encode_twice_survives_two_decodes():
    payload = b"<script>"
    once = encoders.percent_encode_twice(payload)
    assert transforms.url_decode(once) != payload
    assert transforms.url_decode_twice(once) == payload


def test_form_encode_uses_plus_for_space():
    assert b"+" in encoders.form_encode(b"a b")


def test_html_encode_survives_html_decode():
    payload = b"<script>"
    assert transforms.html_entity_decode(encoders.html_encode(payload)) == payload


def test_hex_html_encode_survives_html_decode():
    payload = b"<script>"
    assert transforms.html_entity_decode(
        encoders.hex_html_encode(payload)) == payload


def test_unicode_escape_encode_survives_unicode_decode():
    payload = b"<script>"
    assert transforms.unicode_escape_decode(
        encoders.unicode_escape_encode(payload)) == payload


def test_fullwidth_encode_survives_nfkc():
    payload = b"<script>"
    assert transforms.nfkc(encoders.fullwidth_encode(payload)) == payload


def test_comment_break_encode_survives_comment_strip():
    payload = b"UNIONSELECT"
    assert transforms.strip_sql_comments(
        encoders.comment_break_encode(payload)).replace(b" ", b"") == payload


def test_encoder_registry_covers_every_decoder_that_matters():
    """A decoder with no encoder cannot be searched, only observed."""
    for name in ("url_decode", "url_decode_plus", "url_decode_twice",
                 "html_entity", "unicode_escape", "percent_u", "nfkc"):
        assert encoders.has_encoder(name), f"{name} has no encoder"


def test_unknown_transform_encodes_to_identity():
    assert encoders.for_transform("no_such_step")(b"abc") == b"abc"


# ── registry ────────────────────────────────────────────────────────────────


def test_every_transform_declares_a_family():
    for transform in transforms.TRANSFORMS.values():
        assert isinstance(transform.family, Family)


def test_transforms_are_total():
    """No transform may raise on arbitrary bytes; the search needs that."""
    nasty = bytes(range(256)) + b"\xff\xfe\x00"
    for transform in transforms.TRANSFORMS.values():
        result = transform.apply(nasty)
        assert isinstance(result, bytes)


def test_idempotent_flag_is_honest():
    """A wrong ``True`` narrows the search and could hide a divergence."""
    sample = b"<a href='x'>\x00 A  B "
    for transform in transforms.TRANSFORMS.values():
        if not transform.idempotent:
            continue
        once = transform.apply(sample)
        twice = transform.apply(once)
        assert once == twice, f"{transform.name} claims idempotence but is not"
