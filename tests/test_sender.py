"""Sender tests: pacing, breaker, budget and accounting.

The transport is faked, so these exercise the *whole* send path — delays,
circuit breaker, budget accounting — without a single packet. That is deliberate:
the safety behaviour is the part that must be provably right, and it is the part
nobody remembers to test.
"""

from __future__ import annotations

import pytest

from wafharness import sender
from wafharness.models import Divergence, DivergenceKind


def witness(text: bytes, kind: DivergenceKind = DivergenceKind.HIDDEN_FROM_WAF):
    return Divergence(
        left="waf", right="backend", witness=text, kind=kind,
        left_view=b"inert", right_view=text, tokens=("<script",),
    )


class Recorder:
    """A transport that records calls and replays a scripted response."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url: str, method: str):
        self.calls.append((method, url))
        if not self.responses:
            return 200, b"ok", 0
        return self.responses.pop(0)


def collector():
    slept = []
    return slept, slept.append


# ── pacing ──────────────────────────────────────────────────────────────────


def test_requests_are_sequential_and_spaced():
    slept, sleep = collector()
    transport = Recorder([(200, b"ok", 0)] * 5)
    divergences = [witness(b"%3Cscript%3E") for _ in range(3)]

    sender.send("https://t.example", divergences,
                sender.Limits(delay=2.5, max_requests=10),
                transport=transport, sleep=sleep)

    # One control + three witnesses = 4 requests, 3 gaps between them.
    assert len(transport.calls) == 4
    assert slept == [2.5, 2.5, 2.5]
    assert all(delay == 2.5 for delay in slept)


def test_zero_delay_is_possible_but_explicit():
    slept, sleep = collector()
    transport = Recorder([(200, b"ok", 0)] * 3)
    sender.send("https://t.example", [witness(b"x"), witness(b"y")],
                sender.Limits(delay=0.0), transport=transport, sleep=sleep)
    assert slept == []


# ── budget ──────────────────────────────────────────────────────────────────


def test_request_budget_is_hard():
    _, sleep = collector()
    transport = Recorder([(200, b"ok", 0)] * 50)
    divergences = [witness(f"w{i}".encode()) for i in range(20)]

    report = sender.send("https://t.example", divergences,
                         sender.Limits(delay=0, max_requests=4),
                         transport=transport, sleep=sleep)

    assert len(report.attempts) == 4
    assert "budget" in report.stopped_reason


def test_budget_counts_the_control_request():
    """Otherwise a run of ``max_requests`` witnesses would send one extra."""
    _, sleep = collector()
    transport = Recorder([(200, b"ok", 0)] * 10)
    report = sender.send("https://t.example",
                         [witness(b"a"), witness(b"b"), witness(b"c")],
                         sender.Limits(delay=0, max_requests=2),
                         transport=transport, sleep=sleep)
    assert len(transport.calls) == 2


# ── circuit breaker ─────────────────────────────────────────────────────────


def test_breaker_stops_after_consecutive_blocks():
    _, sleep = collector()
    # Control passes, then five blocks in a row.
    responses = [(200, b"ok", 0)] + [(403, b"denied", 0)] * 10
    transport = Recorder(responses)
    divergences = [witness(f"w{i}".encode()) for i in range(10)]

    report = sender.send("https://t.example", divergences,
                         sender.Limits(delay=0, breaker_threshold=5,
                                       max_requests=50),
                         transport=transport, sleep=sleep)

    assert report.blocked == 5
    assert len(report.attempts) == 6          # control + 5 blocks
    assert "circuit breaker" in report.stopped_reason


def test_breaker_resets_after_a_success():
    _, sleep = collector()
    responses = [
        (200, b"ok", 0),          # control
        (403, b"denied", 0),      # block 1
        (200, b"ok", 0),          # success resets
        (403, b"denied", 0),      # block 1 again
        (403, b"denied", 0),      # block 2
    ]
    transport = Recorder(responses)
    report = sender.send("https://t.example",
                         [witness(b"a"), witness(b"b"), witness(b"c"),
                          witness(b"d"), witness(b"e")],
                         sender.Limits(delay=0, breaker_threshold=3),
                         transport=transport, sleep=sleep)

    assert report.blocked == 3
    # The breaker never tripped, so all five witnesses were sent.
    assert len(report.attempts) == 6


def test_blocked_control_aborts_immediately():
    """A target that refuses the control refuses everything; results are noise."""
    _, sleep = collector()
    transport = Recorder([(403, b"denied", 0)])
    report = sender.send("https://t.example",
                         [witness(b"a"), witness(b"b")],
                         sender.Limits(delay=0), transport=transport,
                         sleep=sleep)

    assert len(report.attempts) == 1
    assert "control" in report.stopped_reason
    assert len(transport.calls) == 1


# ── accounting ──────────────────────────────────────────────────────────────


def test_reflection_is_detected():
    _, sleep = collector()
    transport = Recorder([
        (200, b"ok", 0),
        (200, b"<html><script>alert(1)</script></html>", 0),
    ])
    report = sender.send("https://t.example", [witness(b"%3Cscript%3E")],
                         sender.Limits(delay=0), transport=transport,
                         sleep=sleep)
    assert report.reflected == 1
    # ``delivered`` counts the control request as well: two requests were made,
    # neither was blocked, and the receipt must not hide one of them.
    assert report.delivered == 2
    assert len(report.attempts) == 2


def test_transport_errors_are_recorded_not_raised():
    _, sleep = collector()

    def broken(url, method):
        raise ConnectionError("refused")

    report = sender.send("https://t.example", [witness(b"a")],
                         sender.Limits(delay=0), transport=broken, sleep=sleep)
    assert report.attempts
    assert "ConnectionError" in report.attempts[-1].error


def test_report_is_serialisable():
    import json
    _, sleep = collector()
    transport = Recorder([(200, b"ok", 0), (403, b"no", 0)])
    report = sender.send("https://t.example", [witness(b"a")],
                         sender.Limits(delay=0), transport=transport,
                         sleep=sleep)
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["sent"] == 2
    assert payload["stopped_reason"] == "completed"


# ── request construction ────────────────────────────────────────────────────


def test_witness_is_percent_encoded_once():
    url = sender.build_request("https://t.example", b"%3Cscript%3E")
    # The percent signs must survive as %25 so the *server* decodes once.
    assert "%253Cscript%253E" in url


def test_query_separator_is_correct_with_an_existing_query():
    assert "&q=" in sender.build_request("https://t.example/?a=1", b"x")
    assert "?q=" in sender.build_request("https://t.example/", b"x")


def test_summarise_is_readable():
    _, sleep = collector()
    transport = Recorder([(200, b"ok", 0), (200, b"ok", 0)])
    report = sender.send("https://t.example", [witness(b"a")],
                         sender.Limits(delay=0), transport=transport,
                         sleep=sleep)
    text = sender.summarise(report)
    assert "target" in text
    assert "sent" in text


# ── the defaults are the safe ones ─────────────────────────────────────────


def test_default_limits_are_conservative():
    limits = sender.Limits()
    assert limits.delay >= 1.0, "speed must be a deliberate choice"
    assert limits.max_requests <= 50
    assert limits.breaker_threshold <= 10
