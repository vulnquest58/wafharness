"""Tests for the single-URL confirmation verdicts."""

from __future__ import annotations

from wafharness import cli, confirm, engine, plan, sender, stacks


def _hypothesis(with_witnesses=True):
    waf = stacks.get("cloudflare")
    backend = stacks.get("php")
    divergences = tuple(engine.search_pair(waf, backend)) if with_witnesses else ()
    return plan.Hypothesis(waf=waf, backend=backend, fit=1.0,
                           divergences=divergences)


def _attempt(index, status=200, blocked=False, reflected=False, error=""):
    return sender.Attempt(
        index=index, method="GET", url="https://own.example/?q=x",
        payload=b"x", status=status, blocked=blocked, reflected=reflected,
        error=error)


def _run(*attempts, stopped="completed"):
    return sender.RunReport(target="https://own.example",
                            attempts=list(attempts), stopped_reason=stopped)


def test_reflection_is_confirmed():
    run = _run(_attempt(0), _attempt(1, reflected=True))
    result = confirm.assess(_hypothesis(), run)
    assert result.verdict == confirm.CONFIRMED
    assert result.positive
    assert "reflected" in result.notes[0]


def test_a_pass_without_reflection_is_only_a_candidate():
    run = _run(_attempt(0), _attempt(1))
    result = confirm.assess(_hypothesis(), run)
    assert result.verdict == confirm.CANDIDATE
    assert not result.positive


def test_every_witness_blocked_is_not_a_bypass():
    run = _run(_attempt(0), _attempt(1, status=403, blocked=True))
    result = confirm.assess(_hypothesis(), run)
    assert result.verdict == confirm.BLOCKED


def test_a_blocked_response_is_not_confirmed_by_a_reflected_marker():
    run = _run(_attempt(0), _attempt(1, status=403, blocked=True,
                                    reflected=True))
    result = confirm.assess(_hypothesis(), run)
    assert result.verdict == confirm.BLOCKED


def test_a_blocked_control_makes_the_run_inconclusive():
    run = _run(
        _attempt(0, status=403, blocked=True),
        stopped="control request was blocked; the target refuses everything")
    result = confirm.assess(_hypothesis(), run)
    assert result.verdict == confirm.INCONCLUSIVE


def test_no_modelled_witness_is_reported_without_sending():
    result = confirm.assess(_hypothesis(with_witnesses=False), _run())
    assert result.verdict == confirm.NO_WITNESSES


def test_errors_without_a_decision_are_inconclusive():
    run = _run(_attempt(0), _attempt(1, status=0, error="ConnectionError: down"))
    result = confirm.assess(_hypothesis(), run)
    assert result.verdict == confirm.INCONCLUSIVE


def test_confirmation_serialises():
    run = _run(_attempt(0), _attempt(1, reflected=True))
    result = confirm.assess(_hypothesis(), run)
    payload = result.to_dict()
    assert payload["verdict"] == confirm.CONFIRMED
    assert payload["run"]["reflected"] == 1
    assert payload["hypothesis"]["waf"] == "cloudflare"


def test_summary_names_the_hypothesis_and_verdict():
    run = _run(_attempt(0), _attempt(1, reflected=True))
    result = confirm.assess(_hypothesis(), run)
    text = confirm.summarise(result)
    assert "cloudflare vs php" in text
    assert "CONFIRMED" in text


def test_confirm_refuses_without_confirmation(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("confirm opened a socket without --yes")

    monkeypatch.setattr(cli, "_http_transport", explode)
    assert cli.main([
        "confirm", "--url", "https://own.example",
    ]) == 2


def test_confirm_rejects_an_absurd_witness_budget(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("confirm opened a socket before validating")

    monkeypatch.setattr(cli, "_http_transport", explode)
    assert cli.main([
        "confirm", "--url", "https://own.example", "--yes",
        "--max-witnesses", "100",
    ]) == 2
