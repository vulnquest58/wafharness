"""Tests for the payload-to-response evidence chain."""

from __future__ import annotations

import json

from wafharness import confirm, engine, finding, plan, report, sender, stacks


def _hypothesis():
    waf = stacks.get("cloudflare")
    backend = stacks.get("php")
    return plan.Hypothesis(waf=waf, backend=backend, fit=1.0,
                           divergences=tuple(engine.search_pair(waf, backend)))


def _attempt(index, payload, status=200, reflected=False, blocked=False):
    return sender.Attempt(
        index=index, method="GET", url=f"https://own.example/?q={payload.hex()}",
        payload=payload, status=status, size=20, reflected=reflected,
        blocked=blocked)


def _confirmation():
    hypothesis = _hypothesis()
    witness = hypothesis.bypasses[0].witness
    run = sender.RunReport(
        target="https://own.example",
        attempts=[_attempt(0, b"wafharness-control"),
                  _attempt(1, witness, reflected=True)],
        stopped_reason="completed")
    return confirm.assess(hypothesis, run)


def test_finding_binds_the_exact_payload_to_its_cause():
    hypothesis = _hypothesis()
    witness = hypothesis.bypasses[0].witness
    item = finding.from_attempt(
        hypothesis, _attempt(1, witness, reflected=True), "query:q")
    assert item.payload == witness
    assert item.verdict == "confirmed"
    assert item.cause == hypothesis.bypasses[0].differing_steps
    assert item.tokens == hypothesis.bypasses[0].tokens


def test_candidate_and_blocked_are_distinct_findings():
    hypothesis = _hypothesis()
    witness = hypothesis.bypasses[0].witness
    candidate = finding.from_attempt(
        hypothesis, _attempt(1, witness), "query:q")
    blocked = finding.from_attempt(
        hypothesis, _attempt(1, witness, status=403, blocked=True), "query:q")
    assert candidate.verdict == "candidate"
    assert blocked.verdict == "blocked"


def test_from_confirmation_skips_the_control():
    items = finding.from_confirmation(_confirmation(), "query:q",
                                      target="https://own.example")
    assert len(items) == 1
    assert items[0].target == "https://own.example"
    assert items[0].entry == "query:q"
    assert items[0].verdict == "confirmed"


def test_finding_serialises_the_payload_and_hex():
    item = finding.from_confirmation(_confirmation(), "query:q")[0]
    payload = item.to_dict()
    assert payload["payload_hex"] == item.payload.hex()
    assert payload["entry"] == "query:q"
    assert payload["reflected"] is True


def test_save_writes_json_and_markdown(tmp_path):
    items = finding.from_confirmation(_confirmation(), "query:q",
                                      target="https://own.example")
    paths = finding.save(items, tmp_path, extra={"identity": {"kind": "WAF-like"}})
    payload = json.loads(tmp_path.joinpath("wafharness_finding.json").read_text(
        encoding="utf-8"))
    assert payload["summary"]["confirmed"] == 1
    assert payload["findings"][0]["entry"] == "query:q"
    assert "CONFIRMED" in tmp_path.joinpath("wafharness_finding.md").read_text(
        encoding="utf-8")


def test_findings_console_shows_entry_and_payload():
    items = finding.from_confirmation(_confirmation(), "query:q")
    text = report.findings_console(items)
    assert "CONFIRMED" in text
    assert "query:q" in text
    assert "payload" in text
