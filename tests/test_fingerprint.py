"""Canary and fingerprint tests.

The transport is faked throughout: a fake target built from a real `Stack` lets
these tests assert *"if the target behaves like this stack, does the fingerprint
say so?"* — which is the only question that matters and the only one that can be
answered without a network.
"""

from __future__ import annotations

import pytest

from wafharness import canaries, fingerprint, stacks
from wafharness.models import Profile


def fake_target(stack, *, reflect: bool = True, block_on_token: bool = True,
                block_all: bool = False):
    """Build a transport that behaves like ``stack``.

    ``reflect=True``   echo the transformed value back (a verbose app)
    ``reflect=False``  never echo; only the WAF decision is observable
    """
    from wafharness.engine import TOKENS

    def transport(payload: bytes):
        if block_all:
            return 403, b"blocked"

        view, rejection = stack.run(payload)
        if rejection:
            return 403, b"blocked"

        if block_on_token:
            if any(token.encode().lower() in view.lower() for token in TOKENS):
                return 403, b"blocked"

        if reflect:
            return 200, b"<html>echo: " + view + b"</html>"
        return 200, b"<html>nothing to see</html>"

    return transport


# ── canary registry ─────────────────────────────────────────────────────────


def test_every_canary_names_a_real_transform():
    """A canary must name a byte transform or an explicitly framed rule."""
    from wafharness.transforms import TRANSFORMS
    for canary in canaries.CANARIES:
        if canary.detects.startswith("framing:"):
            continue          # framing rules live in framing.py, not TRANSFORMS
        assert canary.detects in TRANSFORMS, (
            f"{canary.name} detects unknown transform {canary.detects}")


def test_every_canary_explains_itself():
    for canary in canaries.CANARIES:
        assert canary.rationale, canary.name
        assert canary.payload, canary.name


def test_canary_names_are_unique():
    names = [c.name for c in canaries.CANARIES]
    assert len(names) == len(set(names))


def test_lookup_by_transform():
    found = canaries.for_transforms(["url_decode_twice"])
    assert [c.name for c in found] == ["percent-double"]


def test_unknown_canary_lists_the_alternatives():
    with pytest.raises(KeyError) as exc:
        canaries.get("nope")
    assert "percent" in str(exc.value)


# ── classification ──────────────────────────────────────────────────────────


def test_reflection_is_detected():
    canary = canaries.get("percent")
    result = fingerprint.classify(canary, 200, b"<nexus>")
    assert result.outcome == "reflected"


def test_encoded_echo_means_not_decoded():
    """The canary came back verbatim: the stack did not decode it."""
    canary = canaries.get("percent")
    result = fingerprint.classify(canary, 200, b"echo %3Cnexus%3E")
    assert result.outcome == "reflected_literal"


def test_blocked_is_only_a_block_when_the_control_passed():
    canary = canaries.get("percent")
    blocked = fingerprint.classify(canary, 403, b"denied",
                                   control_status=200)
    assert blocked.outcome == "blocked"

    everything = fingerprint.classify(canary, 403, b"denied",
                                      control_status=403)
    assert everything.outcome == "silent", \
        "a target that blocks everything is not discriminating"


def test_page_change_without_reflection_is_weak_evidence():
    canary = canaries.get("html-entity")
    result = fingerprint.classify(
        canary, 200, b"completely different content here",
        control_status=200, control_body=b"<html>the usual page</html>")
    assert result.outcome == "allowed_for_encoded"


def test_identical_body_is_silent():
    canary = canaries.get("utf7")
    body = b"<html>the usual page</html>"
    result = fingerprint.classify(canary, 200, body,
                                  control_status=200, control_body=body)
    assert result.outcome == "silent"


# ── profiling a target that behaves like a known stack ─────────────────────


def test_profile_recovers_a_decoding_stack():
    """If the target decodes twice, the profile must say so."""
    stack = stacks.Stack(
        name="twin", decode=__import__(
            "wafharness.transforms", fromlist=["resolve"]).resolve(
                ["url_decode_twice"]))
    profile = fingerprint.probe(fake_target(stack), target="twin")

    assert profile.detected.get("url_decode_twice", 0) >= 0.45
    assert any(o.canary == "percent-double" for o in profile.observations)


def test_profile_marks_absent_transforms_explicitly():
    """An echoed-but-undecoded canary is evidence the transform is missing."""
    stack = stacks.Stack(name="plain")
    profile = fingerprint.probe(fake_target(stack), target="plain")
    assert any(name.startswith("no:") for name in profile.detected)


def test_profile_is_honest_when_the_target_blocks_everything():
    transport = fake_target(stacks.Stack(name="x"), block_all=True)
    profile = fingerprint.probe(transport, target="walled")
    assert any("blocked" in note for note in profile.warnings)
    # Nothing may be claimed with high confidence in this situation.
    confident = [v for v in profile.detected.values() if v >= 0.8]
    assert not confident


def test_profile_records_a_dead_target_as_a_warning():
    def dead(_payload):
        raise ConnectionError("refused")

    profile = fingerprint.probe(dead, target="dead")
    assert any("failed" in note for note in profile.warnings)
    assert profile.detected == {}


def test_inference_picks_the_closest_modelled_stack():
    """A target acting like Cloudflare should name Cloudflare, weakly."""
    profile = fingerprint.probe(fake_target(stacks.get("cloudflare")),
                                target="cf-like")
    assert profile.vendor == "cloudflare"
    assert profile.detected.get("best_fit:cloudflare", 0) > 0


def test_inference_reports_runners_up():
    """A single name would hide that several stacks explain the same behaviour."""
    profile = fingerprint.probe(fake_target(stacks.get("cloudflare")),
                                target="cf-like")
    also = [key for key in profile.detected if key.startswith("also:")]
    assert also, "ambiguity must be visible, not hidden behind one name"


def test_vendor_inference_is_not_overconfident():
    """Inference from thirteen canaries must never look like certainty."""
    profile = fingerprint.probe(fake_target(stacks.get("cloudflare")),
                                target="cf-like")
    assert profile.detected.get("vendor:cloudflare", 0) <= 1.0
    assert profile.detected.get("vendor:cloudflare", 0) < 0.95


def test_suggested_stacks_returns_transforms_not_vendors():
    profile = fingerprint.probe(fake_target(stacks.get("php")), target="php-like")
    suggested = fingerprint.suggested_stacks(profile)
    assert all(not name.startswith("no:") for name in suggested)
    assert "url_decode_plus" in suggested


def test_summarise_is_readable():
    profile = fingerprint.probe(fake_target(stacks.get("php")), target="php-like")
    text = fingerprint.summarise(profile)
    assert "url_decode_plus" in text or "detected" in text


def test_profile_serialises():
    profile = fingerprint.probe(fake_target(stacks.get("php")), target="php-like")
    payload = profile.to_dict()
    assert payload["target"] == "php-like"
    assert isinstance(payload["detected"], dict)
    assert isinstance(payload["observations"], list)


# ── invariants ──────────────────────────────────────────────────────────────


def test_confidence_never_exceeds_one():
    profile = fingerprint.probe(fake_target(stacks.get("cloudflare")),
                                target="cf")
    for value in profile.detected.values():
        assert 0.0 <= value <= 1.0


def test_probing_twice_is_stable():
    transport = fake_target(stacks.get("php"))
    first = fingerprint.probe(transport, target="php").detected
    second = fingerprint.probe(transport, target="php").detected
    assert first == second


# ── newer canaries and round-tripping ───────────────────────────────────────


def test_whitespace_canary_detects_collapse_ws():
    """CRS collapses runs of whitespace; the canary must notice."""
    profile = fingerprint.probe(fake_target(stacks.get("modsecurity-crs")),
                                target="crs-like")
    assert profile.detected.get("collapse_ws", 0) >= 0.45


def test_profile_round_trips_through_json():
    profile = fingerprint.probe(fake_target(stacks.get("php")),
                                target="php-like")
    restored = type(profile).from_dict(profile.to_dict())

    assert restored.target == profile.target
    assert restored.vendor == profile.vendor
    assert restored.detected == profile.detected
    assert len(restored.observations) == len(profile.observations)
    assert restored.warnings == profile.warnings


def test_profile_from_dict_is_lenient_about_missing_fields():
    restored = Profile.from_dict({"detected": {"url_decode": 0.8},
                                  "observations": [{"canary": "x"}]})
    assert restored.target == ""
    assert restored.detected["url_decode"] == 0.8
    assert restored.observations[0].canary == "x"


# ── console safety ──────────────────────────────────────────────────────────


def test_cli_output_is_ascii_safe():
    """A cp1252 console cannot encode the fullwidth canary or a NUL byte.

    Printing the raw payload crashed ``wafharness canaries`` with
    UnicodeEncodeError on Windows — the kind of defect that only shows up when
    someone runs the tool rather than the tests.
    """
    import contextlib
    import io

    from wafharness import cli

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main(["canaries"])

    output = buffer.getvalue()
    output.encode("cp1252")          # must not raise
    assert "percent" in output
    assert "fullwidth" in output


def test_cli_profile_simulate_runs_offline():
    """``--simulate`` must work with no network at all."""
    import contextlib
    import io

    from wafharness import cli

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        exit_code = cli.main(["profile", "--simulate", "cloudflare"])

    assert exit_code == 0
    text = buffer.getvalue()
    assert "cloudflare" in text
    assert "url_decode" in text
