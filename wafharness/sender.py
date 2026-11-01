"""Sender: the one module that sends *witnesses*.

It is deliberately the smallest module and the most constrained. The canary
probes live in the CLI; this file is where a constructed witness becomes
traffic, and every rule below exists because a bypass tool that is careless
about pacing gets its user banned from the program they are working for.

Four constraints, none optional:

1. **Sequential, with a delay.** No concurrency, no bursts. The default three
   seconds is roughly "human exploring a form", which is the rate a WAF is
   designed to tolerate.
2. **Circuit breaker.** Five consecutive blocks and it stops. A wall of 403s
   means the target has decided about you, and continuing is both useless and
   hostile.
3. **A budget.** A hard cap on requests per run, so a loop cannot run away.
4. **A receipt for every attempt.** Method, path, status, size, duration — the
   raw material for a report, and the evidence that the pacing was respected.

There is no "scan" mode and no target discovery: it sends the witnesses you hand
it, to the host you name, and nothing else.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Sequence

from wafharness.models import Divergence

USER_AGENT = "wafharness/0.1 (authorised testing)"


@dataclass
class Limits:
    """Everything that keeps a run polite.

    The defaults are the recommended values, not a starting point to loosen. A
    caller who wants speed can change them, but has to write the number down.
    """

    #: Seconds between requests. Three is deliberately unhurried.
    delay: float = 3.0
    #: Hard cap on requests in one run.
    max_requests: int = 20
    #: Stop after this many consecutive blocks.
    breaker_threshold: int = 5
    #: Per-request timeout.
    timeout: float = 10.0
    #: Include a benign control request first, so a universal 403 is visible.
    send_control: bool = True


@dataclass
class Attempt:
    """One request and what came back."""

    index: int
    method: str
    url: str
    payload: bytes
    status: int = 0
    size: int = 0
    duration_ms: int = 0
    error: str = ""
    blocked: bool = False
    reflected: bool = False
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, object]:
        return {
            "index": self.index,
            "method": self.method,
            "url": self.url,
            "payload": self.payload.decode("latin-1")[:200],
            "status": self.status,
            "size": self.size,
            "duration_ms": self.duration_ms,
            "blocked": self.blocked,
            "reflected": self.reflected,
            "error": self.error,
            "timestamp": self.timestamp,
        }


@dataclass
class RunReport:
    """The receipt for one sending run."""

    target: str
    attempts: List[Attempt] = field(default_factory=list)
    stopped_reason: str = ""
    limits: Optional[Limits] = None

    @property
    def blocked(self) -> int:
        return sum(1 for a in self.attempts if a.blocked)

    @property
    def delivered(self) -> int:
        return sum(1 for a in self.attempts
                   if not a.blocked and not a.error)

    @property
    def reflected(self) -> int:
        return sum(1 for a in self.attempts if a.reflected)

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "stopped_reason": self.stopped_reason,
            "sent": len(self.attempts),
            "blocked": self.blocked,
            "delivered": self.delivered,
            "reflected": self.reflected,
            "limits": self.limits.__dict__ if self.limits else None,
            "attempts": [a.to_dict() for a in self.attempts],
        }


#: Statuses that mean the WAF refused, rather than the application answering.
BLOCK_STATUSES = frozenset({400, 403, 406, 413, 418, 429, 501, 503})

#: Markers that suggest the payload reached the application.
REFLECTION_MARKERS = (b"<script", b"onerror", b"jndi:", b"etc/passwd",
                      b"<nexus>", b"UNION")


def build_request(base: str, payload: bytes, method: str = "GET",
                  parameter: str = "q", body: bool = False) -> str:
    """Turn a witness into one URL.

    Query parameters are percent-encoded *once* by the transport, never by the
    caller: double-encoding at this layer would neutralise exactly the witnesses
    the engine spent its time constructing.
    """
    encoded = urllib.parse.quote_from_bytes(payload, safe="")

    if body:
        return f"{base.rstrip('/')}/{parameter}"

    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{parameter}={encoded}"


def send(
    base: str,
    divergences: Sequence[Divergence],
    limits: Optional[Limits] = None,
    method: str = "GET",
    parameter: str = "q",
    transport: Optional[Callable[[str, str], "tuple[int, bytes, int]"]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> RunReport:
    """Send witnesses one at a time, honouring every limit.

    ``transport`` exists so the tests can run the *whole* send logic — pacing,
    breaker, accounting — without a network. It receives ``(url, method)`` and
    returns ``(status, body, duration_ms)``.
    """
    limits = limits or Limits()
    report = RunReport(target=base, limits=limits)
    transport = transport or _urllib_transport(limits.timeout)

    consecutive_blocks = 0

    def _one(index: int, payload: bytes) -> Optional[Attempt]:
        nonlocal consecutive_blocks

        if len(report.attempts) >= limits.max_requests:
            report.stopped_reason = f"request budget reached ({limits.max_requests})"
            return None
        if consecutive_blocks >= limits.breaker_threshold:
            report.stopped_reason = (
                f"circuit breaker: {consecutive_blocks} consecutive blocks")
            return None

        url = build_request(base, payload, method=method, parameter=parameter)
        attempt = Attempt(index=index, method=method.upper(), url=url,
                          payload=payload)

        started = time.monotonic()
        try:
            status, body, _ = transport(url, method.upper())
            attempt.status = status
            attempt.size = len(body)
            attempt.blocked = status in BLOCK_STATUSES
            attempt.reflected = any(marker.lower() in body.lower()
                                    for marker in REFLECTION_MARKERS)
        except Exception as exc:  # noqa: BLE001 - a failure is data
            attempt.error = f"{type(exc).__name__}: {exc}"
        attempt.duration_ms = int((time.monotonic() - started) * 1000)

        if attempt.blocked:
            consecutive_blocks += 1
        else:
            consecutive_blocks = 0

        report.attempts.append(attempt)
        return attempt

    if limits.send_control:
        _one(0, b"wafharness-control")
        if report.attempts and report.attempts[0].blocked:
            # Every later result would be uninterpretable.
            report.stopped_reason = (
                "control request was blocked; the target refuses everything")
            return report
        if limits.delay and len(report.attempts) < limits.max_requests:
            sleep(limits.delay)

    for number, divergence in enumerate(divergences, start=1):
        attempt = _one(number, divergence.witness)
        if attempt is None:
            break
        if number < len(divergences) and limits.delay:
            sleep(limits.delay)

    if not report.stopped_reason:
        report.stopped_reason = "completed"
    return report


def _urllib_transport(timeout: float):
    """The real transport. Kept tiny and swappable."""
    def transport(url: str, method: str):
        request = urllib.request.Request(url, method=method)
        request.add_header("User-Agent", USER_AGENT)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read(65536), 0
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(8192), 0

    return transport


def summarise(report: RunReport) -> str:
    """One-screen receipt, printed after every run."""
    lines = [
        "",
        f"  target   {report.target}",
        f"  sent     {len(report.attempts)} request(s)",
        f"  delivered{report.delivered:>3}   blocked {report.blocked:>3}   "
        f"reflected {report.reflected:>3}",
    ]
    if report.stopped_reason:
        lines.append(f"  stopped  {report.stopped_reason}")
    if report.attempts:
        lines.append("")
        for attempt in report.attempts[:12]:
            mark = "BLOCK" if attempt.blocked else (
                "REFLECT" if attempt.reflected else "pass")
            lines.append(f"    [{mark:<7}] {attempt.status:>3} "
                         f"{attempt.size:>6}B {attempt.duration_ms:>5}ms  "
                         f"{attempt.url[:64]}")
    lines.append("")
    return "\n".join(lines)
