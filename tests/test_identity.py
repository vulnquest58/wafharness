"""Tests for professional identity labels and their caveats."""

from __future__ import annotations

from wafharness import identity, report
from wafharness.models import Profile


def _profile():
    profile = Profile(target="https://target.example", vendor="cloudflare")
    profile.add("best_fit:cloudflare", 0.85)
    profile.add("url_decode", 0.80)
    profile.add("html_entity", 0.80)
    profile.add("no:strip_nul", 0.65)
    profile.add("also:wallarm", 0.80)
    profile.note("ambiguous: the canaries cannot separate the alternatives")
    return profile


def test_identity_names_the_measured_side():
    result = identity.identify(_profile(), "waf")
    assert result.kind == "WAF-like"
    assert result.label == "cloudflare"
    assert result.fit == 0.85


def test_identity_distinguishes_an_application_from_a_waf():
    result = identity.identify(_profile(), "backend")
    assert result.kind == "application/backend-like"
    assert identity.identify(_profile(), "ambiguous").kind == "undetermined"


def test_identity_keeps_evidence_and_alternatives():
    result = identity.identify(_profile(), "waf")
    assert any("url_decode" in item for item in result.evidence)
    assert not any("no:" in item for item in result.evidence)
    assert result.alternatives == ["wallarm 0.80"]
    assert result.warnings


def test_identity_serialises_and_renders():
    result = identity.identify(_profile(), "waf")
    payload = result.to_dict()
    assert payload["kind"] == "WAF-like"
    assert payload["fit"] == 0.85
    text = report.identity_console(result)
    assert "WAF-like" in text
    assert "cloudflare" in text
    assert "wallarm" in text
