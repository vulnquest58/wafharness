"""Tests for direct live front-door/origin comparison."""

from __future__ import annotations

from wafharness import canaries, cli, live, report


def _pair(front_status=200, front_body=b"ok", origin_status=200,
          origin_body=b"ok"):
    def front(payload):
        return front_status, front_body

    def origin(payload):
        return origin_status, origin_body

    return front, origin


def test_same_response_is_not_a_divergence():
    front, origin = _pair(front_body=b"hello", origin_body=b"hello")
    result = live.compare(front, origin, selected=canaries.CANARIES[:1])
    assert result.comparisons[0].verdict == "same"
    assert result.divergences == []


def test_front_block_is_a_divergence():
    selected = canaries.CANARIES[:1]

    def front(payload):
        return (403, b"blocked") if payload != live.CONTROL else (200, b"ok")

    def origin(payload):
        return 200, b"echo:" + payload

    result = live.compare(front, origin, selected=selected)
    comparison = result.comparisons[0]
    assert comparison.verdict == "front-blocked"
    assert comparison.divergent
    assert result.divergences == [comparison]


def test_origin_reflection_is_a_divergence():
    selected = canaries.CANARIES[:1]
    marker = selected[0].marker.encode()

    def front(payload):
        return 200, b"not reflected"

    def origin(payload):
        return 200, b"echo:" + marker

    result = live.compare(front, origin, selected=selected)
    assert result.comparisons[0].verdict == "origin-sees-payload"


def test_body_difference_is_a_divergence():
    front, origin = _pair(front_body=b"A" * 100, origin_body=b"B" * 100)
    result = live.compare(front, origin, selected=canaries.CANARIES[:1])
    assert result.comparisons[0].verdict == "body-diverges"


def test_both_blocked_is_not_reported_as_a_gap():
    front, origin = _pair(front_status=403, origin_status=403)
    result = live.compare(front, origin, selected=canaries.CANARIES[:1])
    assert result.comparisons[0].verdict == "both-blocked"
    assert result.divergences == []


def test_transport_error_is_recorded_without_stopping():
    selected = canaries.CANARIES[:2]
    calls = []

    def front(payload):
        calls.append(payload)
        raise ConnectionError("front is down")

    def origin(payload):
        return 200, b"ok"

    result = live.compare(front, origin, selected=selected)
    assert len(result.comparisons) == 2
    assert all(item.verdict == "error" for item in result.comparisons)
    assert "front" in result.notes[0]


def test_a_zero_status_is_treated_as_a_dead_endpoint():
    result = live.compare(lambda payload: (0, b""),
                          lambda payload: (200, b"ok"),
                          selected=canaries.CANARIES[:1])
    assert result.comparisons[0].verdict == "error"
    assert "status 0" in result.comparisons[0].detail


def test_an_empty_selection_sends_nothing():
    calls = []

    def transport(payload):
        calls.append(payload)
        return 200, b"ok"

    result = live.compare(transport, transport, selected=[])
    assert calls == [live.CONTROL, live.CONTROL]
    assert result.comparisons == []


def test_both_controls_failing_sends_no_canaries():
    calls = []

    def dead(payload):
        calls.append(payload)
        raise ConnectionError("down")

    result = live.compare(dead, dead, selected=canaries.CANARIES)
    assert calls == [live.CONTROL, live.CONTROL]
    assert result.comparisons == []
    assert any("both controls failed" in note for note in result.notes)


def test_compare_sends_the_control_and_each_canary_to_both():
    front_calls = []
    origin_calls = []
    selected = canaries.CANARIES[:3]

    def front(payload):
        front_calls.append(payload)
        return 200, b"ok"

    def origin(payload):
        origin_calls.append(payload)
        return 200, b"ok"

    live.compare(front, origin, selected=selected)
    expected = [live.CONTROL] + [canary.payload for canary in selected]
    assert front_calls == expected
    assert origin_calls == expected


def test_comparison_report_serialises():
    front, origin = _pair(front_body=b"one", origin_body=b"two")
    result = live.compare(front, origin, selected=canaries.CANARIES[:1],
                          front_name="f", origin_name="o")
    payload = result.to_dict()
    assert payload["front"] == "f"
    assert payload["origin"] == "o"
    assert payload["divergences"] == 1
    assert payload["comparisons"][0]["verdict"] == "body-diverges"


def test_compare_console_marks_the_divergence():
    selected = canaries.CANARIES[:1]

    def front(payload):
        return (403, b"blocked") if payload != live.CONTROL else (200, b"ok")

    def origin(payload):
        return 200, b"ok"

    result = live.compare(front, origin, selected=selected)
    text = report.compare_console(result)
    assert "front-blocked" in text
    assert "1/1 live divergences" in text
    assert "*" in text


def test_compare_refuses_without_confirmation(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("compare opened a socket without --yes")

    monkeypatch.setattr(cli, "_http_transport", explode)
    code = cli.main([
        "compare", "--front", "https://front.example",
        "--origin", "https://origin.example",
    ])
    assert code == 2
