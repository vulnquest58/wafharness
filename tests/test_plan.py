"""Planner tests: joining a measurement to the divergence search.

The fingerprint layer says what a target does; the engine says where two models
disagree. The planner is the join, and the properties worth pinning are the ones
that keep it honest:

* absence of evidence must count against a stack that claims the transform;
* a profile of the application must not be reported as a firewall;
* when several stacks fit, all of them are searched rather than one being
  chosen by name;
* the plan is deterministic, serialisable, and never touches the network.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from wafharness import cli, fingerprint, plan, stacks
from wafharness.models import Profile


def simulated(stack_name: str):
    """A transport that behaves like the named stack, with no network at all."""
    stack = stacks.get(stack_name)

    def transport(payload: bytes):
        view, rejection = stack.run(payload)
        if rejection:
            return 403, b"blocked"
        return 200, b"<html>echo:" + view + b"</html>"

    return transport


def profile_of(stack_name: str) -> Profile:
    return fingerprint.probe(
        simulated(stack_name), target=f"simulated:{stack_name}")


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


# ── evidence ────────────────────────────────────────────────────────────────


def test_positive_and_absent_evidence_are_separated():
    measured = profile_of("cloudflare")
    positive = plan.positive_transforms(measured)
    absent = plan.absent_transforms(measured)

    assert "url_decode" in positive
    assert "url_decode_plus" in absent
    assert all(not name.startswith("no:") for name in positive)
    assert all(not name.startswith("framing:") for name in absent), \
        "framing rules are not byte steps and must not score stacks"


def test_framing_evidence_is_excluded_from_stack_scores():
    measured = profile_of("php")
    assert any(name.startswith("no:framing:")
               for name in measured.detected)
    assert not any(name.startswith("framing:")
                   for name in plan.absent_transforms(measured))


def test_a_stack_that_explains_more_evidence_fits_better():
    measured = profile_of("cloudflare")
    assert plan.stack_fit(stacks.get("cloudflare"), measured) > \
        plan.stack_fit(stacks.get("php"), measured)


def test_absence_penalises_a_stack_that_claims_the_transform():
    """A target that echoed a canary still encoded has not decoded it."""
    measured = profile_of("php")
    assert measured.detected.get("no:lowercase", 0) >= 0.45
    assert plan.stack_fit(stacks.get("java-spring"), measured) < \
        plan.stack_fit(stacks.get("go-net-http"), measured)


def test_identity_wins_when_every_canary_came_back_literal():
    """All absence is a finding: no rewriting is the simplest explanation."""
    def literal(payload):
        return 200, b"echo:" + payload

    measured = fingerprint.probe(literal, target="plain")
    assert plan.stack_fit(stacks.get("identity"), measured) == 1.0
    assert plan.stack_fit(stacks.get("cloudflare"), measured) < 1.0


def test_fit_is_always_a_probability():
    for name in stacks.names("waf") + stacks.names("backend"):
        profile = profile_of("cloudflare")
        value = plan.stack_fit(stacks.get(name), profile)
        assert 0.0 <= value <= 1.0, (name, value)


def test_empty_profile_has_no_opinion():
    assert plan.stack_fit(stacks.get("cloudflare"), Profile()) == 0.0


# ── pairing ─────────────────────────────────────────────────────────────────


def test_a_measured_waf_leads_the_plan():
    measured = profile_of("cloudflare")
    result = plan.build(measured, max_pairs=32)

    assert result.measured_side == "waf"
    assert result.hypotheses
    assert result.best.waf.name == "cloudflare"
    assert result.best.bypasses, "the top hypothesis must carry a witness"


def test_a_measured_backend_is_not_called_a_firewall():
    """The canaries cannot tell sides; the plan must not pretend they can."""
    measured = profile_of("php")
    result = plan.build(measured, max_pairs=32)

    assert result.measured_side in ("ambiguous", "backend")
    assert any("backend" in note for note in result.notes)
    assert any(h.backend.pipeline == "url_decode_plus"
               for h in result.hypotheses)
    assert result.bypasses


def test_pinned_models_produce_exactly_one_hypothesis():
    measured = profile_of("cloudflare")
    result = plan.build(measured,
                        waf=stacks.get("cloudflare"),
                        backend=stacks.get("php"))

    assert len(result.hypotheses) == 1
    hypothesis = result.hypotheses[0]
    assert hypothesis.waf.name == "cloudflare"
    assert hypothesis.backend.name == "php"


def test_fit_uses_only_the_measured_side():
    """An unknown backend must not drag down a measured WAF's confidence."""
    measured = profile_of("cloudflare")
    waf = stacks.get("cloudflare")
    good_backend = stacks.get("php")
    odd_backend = stacks.get("identity")

    fit_good = plan.build(measured, waf=waf, backend=good_backend).best.fit
    fit_odd = plan.build(measured, waf=waf, backend=odd_backend).best.fit
    assert fit_good == fit_odd
    assert fit_good == plan.stack_fit(waf, measured)


def test_an_application_profile_names_identity_without_a_vendor_claim():
    """All-absence evidence fits the identity stack, but that is not a vendor."""
    def literal(payload):
        return 200, b"echo:" + payload

    measured = fingerprint.probe(literal, target="plain")
    result = plan.build(measured)

    assert result.measured_side == "backend"
    assert result.measured_stack == "identity"
    assert result.profile.vendor == ""
    assert result.to_dict()["best_fit"] == "identity"
    assert not result.bypasses


def test_a_strong_winner_is_not_padded_with_weaker_models():
    measured = profile_of("cloudflare")
    scored = plan._score_pool(measured, stacks.WAF_STACKS)
    candidates, chosen = plan._candidates(scored, "cloudflare", [])

    assert chosen
    assert [stack.name for stack in candidates] == ["cloudflare"]


def test_a_close_tie_keeps_the_tied_candidates():
    measured = profile_of("php")
    scored = plan._score_pool(measured, stacks.BACKEND_STACKS)
    candidates, chosen = plan._candidates(scored, "php", [])

    assert chosen
    assert len(candidates) >= 2
    assert any(stack.pipeline == "url_decode_plus" for stack in candidates)
    assert any(stack.pipeline == "url_decode" for stack in candidates)


def test_dedupe_keeps_one_stack_per_cascade():
    same = [stacks.get("php"), stacks.get("node-express"),
            stacks.get("go-net-http")]
    unique = plan._dedupe_by_pipeline(same)
    assert len(unique) == 1
    assert unique[0].pipeline == "url_decode_plus"


def test_dedupe_prefers_the_measured_vendor_name():
    same = [stacks.get("php"), stacks.get("node-express"),
            stacks.get("go-net-http")]
    unique = plan._dedupe_by_pipeline(same, preferred="php")
    assert unique[0].name == "php"


def test_pair_search_is_capped_and_says_so():
    measured = profile_of("cloudflare")
    result = plan.build(measured, max_pairs=2)
    assert len(result.hypotheses) == 2
    assert any("capped" in note for note in result.notes)


def test_no_bypass_is_reported_as_a_result_not_an_error():
    measured = profile_of("identity")
    result = plan.build(measured,
                        waf=stacks.get("akamai"),
                        backend=stacks.get("identity"))
    assert not result.bypasses
    assert any("no executable bypass" in note for note in result.notes)


def test_dead_profile_produces_an_empty_plan():
    result = plan.build(Profile(target="dead"))
    assert result.hypotheses == []
    assert any("no evidence" in note for note in result.notes)


def test_plan_is_deterministic():
    measured = profile_of("cloudflare")
    first = plan.build(measured).to_dict()
    second = plan.build(measured).to_dict()
    assert first == second


def test_plan_serialises():
    measured = profile_of("cloudflare")
    payload = plan.build(measured, max_pairs=8).to_dict()
    encoded = json.dumps(payload)
    assert json.loads(encoded)["best_fit"] == "cloudflare"
    assert isinstance(payload["hypotheses"], list)
    assert payload["profile"]["detected"]


def test_explain_names_the_cause():
    measured = profile_of("cloudflare")
    result = plan.build(measured, max_pairs=4)
    text = plan.explain(result.best)
    assert "cloudflare" in text
    assert "fit" in text


# ── the offline command ─────────────────────────────────────────────────────


def test_plan_simulate_runs_offline():
    code, out, _ = run(["plan", "--simulate", "cloudflare"])
    assert code == 0
    assert "plan" in out
    assert "BYPASS" in out
    out.encode("cp1252")


def test_plan_simulate_json_is_valid():
    code, out, _ = run(["plan", "--simulate", "cloudflare", "--json"])
    payload = json.loads(out)
    assert code == 0
    assert payload["best_fit"] == "cloudflare"
    assert payload["bypass_total"] > 0
    assert payload["hypotheses"]


def test_plan_needs_exactly_one_of_url_and_simulate():
    code, _, err = run(["plan"])
    assert code == 2
    assert "exactly one" in err

    code, _, err = run(["plan", "--simulate", "cloudflare",
                        "--url", "https://example.com"])
    assert code == 2
    assert "exactly one" in err


def test_plan_unknown_stack_names_the_alternatives():
    code, _, err = run(["plan", "--simulate", "nope"])
    assert code == 2
    assert "cloudflare" in err


def test_plan_accepts_pinned_models():
    code, out, _ = run(["plan", "--simulate", "cloudflare",
                        "--waf", "cloudflare", "--backend", "php",
                        "--top", "3"])
    assert code == 0
    assert "cloudflare vs php" in out


def test_plan_reuses_a_saved_profile(tmp_path):
    saved = tmp_path / "profile.json"
    saved.write_text(json.dumps(profile_of("cloudflare").to_dict()),
                     encoding="utf-8")

    code, out, _ = run(["plan", "--profile", str(saved), "--top", "2"])
    assert code == 0
    assert "cloudflare" in out
    assert "BYPASS" in out


def test_plan_rejects_a_missing_or_malformed_profile(tmp_path):
    code, _, err = run(["plan", "--profile", str(tmp_path / "absent.json")])
    assert code == 2
    assert "cannot read profile" in err

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, _, err = run(["plan", "--profile", str(bad)])
    assert code == 2
    assert "cannot read profile" in err


def test_plan_rejects_two_measurement_sources(tmp_path):
    saved = tmp_path / "profile.json"
    saved.write_text(json.dumps(profile_of("cloudflare").to_dict()),
                     encoding="utf-8")
    code, _, err = run(["plan", "--simulate", "cloudflare",
                        "--profile", str(saved)])
    assert code == 2
    assert "exactly one" in err


def test_profile_command_also_requires_one_source():
    code, _, err = run(["profile", "--simulate", "cloudflare",
                        "--url", "https://example.com"])
    assert code == 2
    assert "exactly one" in err


# ── terminal safety ─────────────────────────────────────────────────────────


def test_safe_escapes_c1_controls():
    """Bytes 0x80-0x9F are unprintable on cp1252 and crashed the profile verb."""
    assert report_safe(b"\x9c") == "\\x9c"
    assert report_safe(b"\x00\x1f\x7f\x9c\xff") == \
        "\\x00\\x1f\\x7f\\x9c\\xff"


def report_safe(data: bytes) -> str:
    from wafharness.report import _safe
    return _safe(data, limit=100)


def test_plan_console_is_ascii_safe_with_unicode_witnesses():
    from wafharness.report import plan_console

    measured = profile_of("cloudflare")
    result = plan.build(measured, waf=stacks.get("azure-frontdoor"),
                         backend=stacks.get("java-spring"))
    text = plan_console(result)
    text.encode("cp1252")            # must not raise


def test_the_package_has_a_module_entry_point():
    """``python -m wafharness`` should behave like the console script."""
    import wafharness.__main__ as entry
    assert callable(entry.main)
