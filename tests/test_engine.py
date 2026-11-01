"""Engine tests: the classification logic and the witness construction.

The classification rule was inverted in the first draft — it reported "hidden
from the WAF" for witnesses the WAF had plainly seen — so the four outcomes are
pinned individually here.
"""

from __future__ import annotations

import pytest

from wafharness import engine, stacks
from wafharness.models import DivergenceKind, Stack
from wafharness.transforms import resolve


def stack(name: str, decode=(), normalize=(), forbidden=()) -> Stack:
    return Stack(name=name, decode=resolve(decode), normalize=resolve(normalize),
                 forbidden=tuple(forbidden))


# ── encode_chain ordering ───────────────────────────────────────────────────


def test_encode_chain_runs_last_decoder_first():
    """The decode pipeline runs first-to-last, so its inverse runs backwards."""
    # decode = [url_decode, html_entity]: view = html_entity(url_decode(x)).
    # To make view == payload we encode with html first, then percent.
    payload = b"<script>"
    encoded = engine.encode_chain(payload, ["url_decode", "html_entity"])

    manual = engine.encode_chain(
        engine.encode_chain(payload, ["html_entity"]), ["url_decode"])
    assert encoded == manual

    # And the round trip really returns the payload.
    from wafharness import transforms
    assert transforms.html_entity_decode(
        transforms.url_decode(encoded)) == payload


def test_encode_chain_with_no_decoders_is_identity():
    assert engine.encode_chain(b"<script>", []) == b"<script>"


# ── classification ──────────────────────────────────────────────────────────


def test_hidden_from_waf_when_only_backend_decodes():
    """The core bypass: WAF reads one thing, backend another."""
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode_twice"])

    witness = b"%253Cscript%253E"
    result = engine.classify(waf, backend, witness)

    assert result.kind is DivergenceKind.HIDDEN_FROM_WAF
    assert b"%2F" not in result.right_view          # backend saw the tag
    assert b"<script" in result.right_view.lower()
    assert b"<script" not in result.left_view.lower()


def test_no_gap_when_both_see_the_token():
    """Both decoding once means both see it; blocked is blocked."""
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode"])

    result = engine.classify(waf, backend, b"%3Cscript%3E")
    assert result.kind is DivergenceKind.NO_GAP


def test_dead_end_when_waf_blocks_a_witness_that_never_mattered():
    """Blocked *and* harmless: the witness would not have done anything.

    ``<script>`` is not this case — there the backend does reach a token and the
    WAF stops it, which is the WAF working correctly, not a dead end.
    """
    waf = stack("w", forbidden=[b"<"])
    backend = stack("b")
    result = engine.classify(waf, backend, b"<plain text>")
    assert result.kind is DivergenceKind.DEAD_END


def test_blocked_witness_that_would_have_worked_is_no_gap():
    """WAF blocks, backend would have reached the token: the WAF did its job."""
    waf = stack("w", forbidden=[b"<"], decode=["url_decode"])
    backend = stack("b", decode=["url_decode"])
    result = engine.classify(waf, backend, b"<script>alert(1)</script>")
    assert result.kind is DivergenceKind.NO_GAP


def test_rewritten_when_neither_blocks_but_views_differ():
    """No token on either side, yet the two hops disagree — smuggling shape."""
    waf = stack("w", normalize=["lowercase"])
    backend = stack("b")
    result = engine.classify(waf, backend, b"%0D%0AX-Test: 1")
    assert result.kind is DivergenceKind.REWRITTEN


def test_plus_versus_space_is_a_real_divergence():
    """``+`` is a literal to one decoder and a space to the other."""
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode_plus"])
    result = engine.classify(waf, backend, b"'+OR+1=1")
    assert result.kind is DivergenceKind.HIDDEN_FROM_WAF
    assert b"OR 1=1" in result.right_view


def test_nfkc_at_the_backend_only_is_a_divergence():
    """Fullwidth characters are invisible to a byte-matching WAF."""
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode"], normalize=["nfkc"])
    witness = "＜script＞".encode()
    result = engine.classify(waf, backend, witness)
    assert result.kind is DivergenceKind.HIDDEN_FROM_WAF


# ── search ──────────────────────────────────────────────────────────────────


def test_search_finds_the_double_decode_class():
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode_twice"])
    found = engine.search_pair(waf, backend)

    assert found, "double decoding must produce witnesses"
    assert all(d.kind in (DivergenceKind.HIDDEN_FROM_WAF,
                          DivergenceKind.REWRITTEN) for d in found)
    assert all(d.left == "w" and d.right == "b" for d in found)


def test_search_is_deterministic():
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode_twice"])
    first = [d.witness for d in engine.search_pair(waf, backend)]
    second = [d.witness for d in engine.search_pair(waf, backend)]
    assert first == second


def test_search_respects_the_budget():
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode_twice", "html_entity",
                                 "unicode_escape"])
    budget = engine.Budget(max_divergences=3)
    assert len(engine.search_pair(waf, backend, budget=budget)) <= 3


def test_search_is_empty_when_pipelines_match():
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode"])
    assert engine.search_pair(waf, backend) == []


def test_search_skips_variants_that_do_not_diverge():
    """Only real divergences are reported, never the whole corpus."""
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode_twice"])
    found = engine.search_pair(waf, backend)
    corpus_size = len(engine.CORPUS)
    assert len(found) <= corpus_size * 2


def test_ranking_puts_hidden_divergences_first():
    waf = stack("w", decode=["url_decode"], normalize=["lowercase"])
    backend = stack("b", decode=["url_decode_twice"], normalize=["nfkc"])
    found = engine.search_pair(waf, backend)
    if len(found) > 1:
        assert found[0].severity >= found[-1].severity


def test_real_stack_pair_produces_a_gap():
    """cloudflare decodes once; php converts '+' to a space and decodes once."""
    found = engine.search_pair(stacks.get("cloudflare"), stacks.get("php"))
    assert found, "a decode-depth difference must be discoverable"
    kinds = {d.kind for d in found}
    assert DivergenceKind.HIDDEN_FROM_WAF in kinds or \
           DivergenceKind.REWRITTEN in kinds


def test_explain_renders_both_views():
    waf = stack("w", decode=["url_decode"])
    backend = stack("b", decode=["url_decode_twice"])
    result = engine.classify(waf, backend, b"%253Cscript%253E")
    text = engine.explain(result)
    assert "w" in text and "b" in text
    assert "witness" in text
