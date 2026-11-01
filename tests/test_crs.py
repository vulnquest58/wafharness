"""Tests for live CRS sandbox parsing and measurement."""

from __future__ import annotations

import json

from wafharness import canaries, crs, report


def _rules_body(*rules) -> bytes:
    return json.dumps(list(rules)).encode("utf-8")


def test_parse_rules_reads_ids_messages_and_paranoia():
    body = _rules_body(
        {"id": "941100", "message": "XSS", "paranoia_level": "1"},
        {"id": 949110, "message": "score", "paranoia_level": "?"},
    )
    rules = crs.parse_rules(body)
    assert [rule.id for rule in rules] == ["941100", "949110"]
    assert rules[0].message == "XSS"
    assert rules[1].paranoia_level == "?"


def test_parse_rules_is_total_on_garbage():
    assert crs.parse_rules(b"not json") == []
    assert crs.parse_rules(b'{"id":"1"}') == []
    assert crs.parse_rules(b"[null, 3, {}]") == []


def test_measure_sends_each_selected_canary_once():
    sent = []

    def transport(payload: bytes):
        sent.append(payload)
        return 200, _rules_body({"id": "1"})

    selected = canaries.CANARIES[:3]
    results = crs.measure(transport, selected)
    assert [result.canary.name for result in results] == [
        canary.name for canary in selected]
    assert sent == [canary.payload for canary in selected]
    assert all(result.detected for result in results)


def test_measure_keeps_going_after_a_transport_error():
    calls = []

    def transport(payload: bytes):
        calls.append(payload)
        if len(calls) == 1:
            raise ConnectionError("sandbox is down")
        return 200, b"[]"

    results = crs.measure(transport, canaries.CANARIES[:2])
    assert len(results) == 2
    assert results[0].status == 0
    assert not results[0].detected
    assert not results[1].detected


def test_blocking_status_is_detection_even_without_an_audit_body():
    result = crs.CanaryResult(canaries.CANARIES[0], 403, [])
    assert result.detected


def test_summary_deduplicates_rules_across_canaries():
    first = crs.CanaryResult(canaries.CANARIES[0], 200, crs.parse_rules(
        _rules_body({"id": "1"}, {"id": "2"})))
    second = crs.CanaryResult(canaries.CANARIES[1], 200, crs.parse_rules(
        _rules_body({"id": "2"})))
    info = crs.summary([first, second])
    assert info["detected"] == 2
    assert info["rules"] == 2
    assert info["rule_ids"] == ["1", "2"]


def test_crs_console_shows_decision_and_rule_ids():
    result = crs.CanaryResult(canaries.CANARIES[0], 200, crs.parse_rules(
        _rules_body({"id": "941100", "message": "XSS"})))
    text = report.crs_console([result])
    assert "DETECTED" in text
    assert "941100" in text
    assert "1/1 canaries triggered CRS" in text


def test_crs_console_marks_an_allowed_canary():
    result = crs.CanaryResult(canaries.CANARIES[0], 200, [])
    text = report.crs_console([result])
    assert "allowed" in text
    assert "0/1 canaries triggered CRS" in text
