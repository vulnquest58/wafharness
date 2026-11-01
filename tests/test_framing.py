"""Framing tests: parsers, and the divergences between them.

Two defects were found while writing this module, both now pinned:

* the RFC 2047 witness encoded the payload twice, producing a field name that
  decoded to garbage at both ends;
* the search compared a value that one frame could not find at all, and skipped
  the case — hiding the strict-vs-lenient multipart divergence entirely.
"""

from __future__ import annotations

import pytest

from wafharness import engine, framing
from wafharness.models import DivergenceKind


# ── query parsing ───────────────────────────────────────────────────────────


def test_query_parser_preserves_duplicates():
    """Collapsing duplicates would destroy the information the search needs."""
    fields = framing.parse_query_lenient(b"a=1&a=2&a=3")
    assert fields == [(b"a", b"1"), (b"a", b"2"), (b"a", b"3")]


def test_first_wins_reads_the_first_value():
    sample = b"comment=benign&comment=evil"
    assert framing.get("query-first-wins").value(sample, b"comment") == b"benign"


def test_last_wins_reads_the_last_value():
    sample = b"comment=benign&comment=evil"
    assert framing.get("query-last-wins").value(sample, b"comment") == b"evil"


def test_missing_key_is_none_not_empty():
    assert framing.get("query-last-wins").value(b"a=1", b"comment") is None


def test_semicolon_frame_keeps_semicolon_in_the_value():
    sample = b"comment=benign;comment=evil"
    strict = framing.get("query-semicolon")
    # Splits on '&' only, so the whole remainder is one value.
    assert strict.value(sample, b"comment") == b"benign;comment=evil"


# ── multipart ───────────────────────────────────────────────────────────────


def _part(name: bytes, body: bytes, newline: bytes = b"\r\n") -> bytes:
    return (b"--__B__" + newline
            + b'Content-Disposition: form-data; name="' + name + b'"' + newline
            + newline
            + body + newline
            + b"--__B__--" + newline)


def test_strict_multipart_accepts_crlf_parts():
    frame = framing.get("multipart-strict")
    assert frame.value(_part(b"comment", b"payload"), b"comment")


def test_strict_multipart_rejects_bare_lf():
    """A bare LF is not a legal delimiter; a strict frame produces no field."""
    frame = framing.get("multipart-strict")
    assert frame.fields(_part(b"comment", b"payload", newline=b"\n")) == []


def test_lenient_multipart_accepts_bare_lf():
    frame = framing.get("multipart-lenient")
    assert frame.value(_part(b"comment", b"payload", newline=b"\n"),
                       b"comment")


# ── RFC 2047 ────────────────────────────────────────────────────────────────


def test_rfc2047_round_trip():
    payload = b"payload-value"
    assert framing.rfc2047_decode(framing.rfc2047_encode(payload)) == payload


def test_rfc2047_decode_handles_q_encoding():
    assert framing.rfc2047_decode(b"=?utf-8?Q?a=20b?=") == b"a b"


def test_rfc2047_encode_does_not_double_wrap():
    """Encoding twice produced a field name that decoded to garbage."""
    once = framing.rfc2047_encode(b"comment")
    assert once.count(b"=?") == 1
    assert framing.rfc2047_decode(once) == b"comment"


def test_rfc2047_frame_decodes_the_field_name():
    """The encoded name is the token carrier, so the frame must decode it."""
    witness = (b"--__B__\r\n"
               b'Content-Disposition: form-data; name="'
               + framing.rfc2047_encode(b"comment") + b'"\r\n'
               b"\r\npayload\r\n--__B__--\r\n")
    assert framing.get("multipart-rfc2047").value(witness, b"comment")


def test_plain_frame_sees_the_encoded_name_as_literal():
    witness = (b"--__B__\r\n"
               b'Content-Disposition: form-data; name="'
               + framing.rfc2047_encode(b"comment") + b'"\r\n'
               b"\r\npayload\r\n--__B__--\r\n")
    assert framing.get("multipart-lenient").value(witness, b"comment") is None


# ── JSON ────────────────────────────────────────────────────────────────────


def test_json_parser_keeps_duplicate_keys():
    fields = framing.parse_json_pairs(b'{"a":1,"a":2}')
    assert fields == [(b"a", b"1"), (b"a", b"2")]


def test_json_first_and_last_wins_differ():
    sample = b'{"a":"benign","a":"evil"}'
    assert framing.get("json-first-wins").value(sample, b"a") == b'"benign"'
    assert framing.get("json-last-wins").value(sample, b"a") == b'"evil"'


def test_json_parser_ignores_nested_commas():
    """A nested object must not be split into separate top-level pairs."""
    fields = framing.parse_json_pairs(b'{"a":{"x":1,"y":2},"b":3}')
    assert [name for name, _ in fields] == [b"a", b"b"]


def test_json_parser_is_total_on_garbage():
    assert framing.parse_json_pairs(b"not json at all") == []


# ── headers and cookies ─────────────────────────────────────────────────────


def test_header_parser_preserves_duplicates_and_lowercases_names():
    fields = framing.parse_headers_strict(b"X-A: one\r\nx-a: two\r\n")
    assert fields == [(b"x-a", b"one"), (b"x-a", b"two")]


def test_header_strict_rejects_bare_lf():
    """A strict header reader rejects the block instead of guessing the line."""
    sample = b"Comment: benign\nComment: evil\n"
    assert framing.parse_headers_strict(sample) == []


def test_header_lenient_accepts_bare_lf_and_folds_continuations():
    sample = b"Comment: benign\nComment: evil\nX-Test: a\n b\n"
    fields = framing.parse_headers_lenient(sample)
    assert (b"comment", b"evil") in fields
    assert (b"x-test", b"a b") in fields


def test_header_first_and_last_wins_differ():
    sample = b"Comment: benign\r\nComment: evil\r\n"
    assert framing.get("header-first-wins").value(sample, b"comment") == b"benign"
    assert framing.get("header-last-wins").value(sample, b"comment") == b"evil"


def test_cookie_parser_preserves_duplicates():
    sample = b"Cookie: Comment=benign; Comment=evil\r\n"
    assert framing.parse_cookie_header(sample) == [
        (b"comment", b"benign"), (b"comment", b"evil")]
    assert framing.get("cookie-first-wins").value(sample, b"comment") == b"benign"
    assert framing.get("cookie-last-wins").value(sample, b"comment") == b"evil"


def test_cookie_value_may_contain_equals():
    sample = b"Cookie: data=a=b\r\n"
    assert framing.get("cookie-last-wins").value(sample, b"data") == b"a=b"


# ── registry ────────────────────────────────────────────────────────────────


def test_declared_pairs_reference_real_frames():
    for left, right in framing.DISAGREEING_PAIRS:
        framing.get(left)
        framing.get(right)
        assert left != right


def test_unknown_frame_names_the_alternatives():
    with pytest.raises(KeyError) as exc:
        framing.get("no-such-frame")
    assert "query-first-wins" in str(exc.value)


# ── divergences ─────────────────────────────────────────────────────────────


def test_first_vs_last_wins_produces_a_bypass():
    found = engine.framing_search(("query-first-wins", "query-last-wins"))
    assert found
    assert all(d.kind is DivergenceKind.HIDDEN_FROM_WAF for d in found)
    assert all(d.left_view == b"benign" for d in found)


def test_strict_vs_lenient_produces_a_bypass():
    """The frame that rejects the delimiter produces no field at all."""
    found = engine.framing_search(("multipart-strict", "multipart-lenient"))
    assert found, "strict rejecting bare LF must be discoverable"
    assert all(d.kind is DivergenceKind.HIDDEN_FROM_WAF for d in found)
    assert all(d.left_view == b"<absent>" for d in found)


def test_json_duplicate_keys_produce_a_bypass():
    found = engine.framing_search(("json-first-wins", "json-last-wins"))
    assert found
    assert any("benign" in d.left_view.decode("latin-1") for d in found)


def test_header_duplicate_produces_a_bypass():
    found = engine.framing_search(("header-first-wins", "header-last-wins"))
    assert found, "a duplicated header must be discoverable"
    assert all(d.kind is DivergenceKind.HIDDEN_FROM_WAF for d in found)
    assert all(d.left_view == b"benign" for d in found)


def test_header_line_endings_produce_a_bypass():
    """The strict reader returns no header at all; the lenient one reads last."""
    found = engine.framing_search(("header-strict", "header-lenient"))
    assert found, "bare LF in a header block must be discoverable"
    assert all(d.left_view == b"<absent>" for d in found)


def test_cookie_duplicate_produces_a_bypass():
    found = engine.framing_search(("cookie-first-wins", "cookie-last-wins"))
    assert found, "a duplicated cookie must be discoverable"
    assert all(d.kind is DivergenceKind.HIDDEN_FROM_WAF for d in found)
    assert all(d.left_view == b"benign" for d in found)


def test_framing_search_is_deterministic():
    first = [d.witness for d in
             engine.framing_search(("query-first-wins", "query-last-wins"))]
    second = [d.witness for d in
              engine.framing_search(("query-first-wins", "query-last-wins"))]
    assert first == second


def test_framing_search_never_reports_a_pair_with_identical_values():
    for pair in engine.framing_pairs():
        for divergence in engine.framing_search(pair):
            assert divergence.left_view != divergence.right_view
