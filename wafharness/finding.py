"""Findings: the evidence chain from a model to one live request.

A confirmation report is only useful if it says *which entry point* accepted
*which exact bytes*, what the WAF did, and why the model expected a gap. This
module keeps that chain intact: payload, encoded URL, hypothesis, cause,
response status, reflection, and verdict.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from wafharness.confirm import Confirmation
from wafharness.models import Divergence
from wafharness.plan import Hypothesis
from wafharness.report import _safe
from wafharness.sender import Attempt


def _match(hypothesis: Hypothesis, payload: bytes) -> Optional[Divergence]:
    for divergence in hypothesis.bypasses:
        if divergence.witness == payload:
            return divergence
    return None


@dataclass
class Finding:
    """One witness, one entry point, one response."""

    target: str
    entry: str
    method: str
    waf: str
    backend: str
    fit: float
    payload: bytes
    url: str
    status: int = 0
    size: int = 0
    reflected: bool = False
    blocked: bool = False
    error: str = ""
    cause: Tuple[str, ...] = ()
    tokens: Tuple[str, ...] = ()
    verdict: str = "inconclusive"
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "entry": self.entry,
            "method": self.method,
            "waf": self.waf,
            "backend": self.backend,
            "fit": round(self.fit, 3),
            "payload": self.payload.decode("latin-1"),
            "payload_hex": self.payload.hex(),
            "payload_visible": _safe(self.payload, 200),
            "url": self.url,
            "status": self.status,
            "size": self.size,
            "reflected": self.reflected,
            "blocked": self.blocked,
            "error": self.error,
            "cause": list(self.cause),
            "tokens": list(self.tokens),
            "verdict": self.verdict,
            "notes": list(self.notes),
        }

    def to_markdown(self) -> str:
        lines = [
            f"## {self.verdict.upper()} — `{self.entry}`",
            "",
            f"- Target: `{self.target}`",
            f"- Method: `{self.method}`",
            f"- Entry point: `{self.entry}`",
            f"- Hypothesis: `{self.waf} vs {self.backend}` "
            f"(fit {self.fit:.2f})",
            f"- Cause: `{', '.join(self.cause) or 'modelled divergence'}`",
            f"- Payload: `{_safe(self.payload, 200)}`",
            f"- Payload hex: `{self.payload.hex()}`",
            f"- Request: `{self.url}`",
            f"- Response: status {self.status}, {self.size} bytes, "
            f"reflected={'yes' if self.reflected else 'no'}, "
            f"blocked={'yes' if self.blocked else 'no'}",
        ]
        if self.error:
            lines.append(f"- Error: `{self.error}`")
        if self.notes:
            lines.append("")
            for note in self.notes:
                lines.append(f"> {note}")
        lines.append("")
        return "\n".join(lines)


def from_attempt(hypothesis: Hypothesis, attempt: Attempt,
                 entry: str) -> Finding:
    """Bind one sender receipt to its modelled cause."""
    divergence = _match(hypothesis, attempt.payload)
    cause = divergence.differing_steps if divergence else ()
    tokens = divergence.tokens if divergence else ()

    if attempt.reflected and not attempt.blocked and not attempt.error:
        verdict = "confirmed"
        notes = ["the marker came back; the application received the value"]
    elif attempt.blocked:
        verdict = "blocked"
        notes = ["the WAF refused this witness"]
    elif attempt.error:
        verdict = "error"
        notes = ["the request failed before a decision was made"]
    elif attempt.status:
        verdict = "candidate"
        notes = ["the WAF allowed the bytes, but no marker was reflected"]
    else:
        verdict = "inconclusive"
        notes = []

    return Finding(
        target="",
        entry=entry,
        method=attempt.method,
        waf=hypothesis.waf.name,
        backend=hypothesis.backend.name,
        fit=hypothesis.fit,
        payload=attempt.payload,
        url=attempt.url,
        status=attempt.status,
        size=attempt.size,
        reflected=attempt.reflected,
        blocked=attempt.blocked,
        error=attempt.error,
        cause=cause,
        tokens=tokens,
        verdict=verdict,
        notes=notes,
    )


def from_confirmation(confirmation: Confirmation, entry: str,
                      target: str = "") -> List[Finding]:
    """All non-control attempts from a confirmation, in send order."""
    findings: List[Finding] = []
    for attempt in confirmation.run.attempts:
        if attempt.index == 0:
            continue
        finding = from_attempt(confirmation.hypothesis, attempt, entry)
        finding.target = target or confirmation.target
        findings.append(finding)
    return findings


def save(findings: Sequence[Finding], directory: Path,
        extra: Optional[Dict[str, object]] = None,
        stem: str = "wafharness_finding") -> Dict[str, str]:
    """Write the evidence chain as JSON and a human-readable Markdown report."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"{stem}.json"
    md_path = directory / f"{stem}.md"

    payload = {
        "findings": [finding.to_dict() for finding in findings],
        "summary": {
            "total": len(findings),
            "confirmed": sum(1 for f in findings if f.verdict == "confirmed"),
            "candidate": sum(1 for f in findings if f.verdict == "candidate"),
            "blocked": sum(1 for f in findings if f.verdict == "blocked"),
            "error": sum(1 for f in findings if f.verdict == "error"),
        },
    }
    if extra:
        payload.update(extra)
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = ["# wafharness finding", ""]
    if findings:
        first = findings[0]
        lines += [
            f"- Target: `{first.target}`",
            f"- WAF hypothesis: `{first.waf}`",
            f"- Backend hypothesis: `{first.backend}`",
            "",
        ]
    for finding in findings:
        lines.append(finding.to_markdown())
    lines += [
        "---",
        "",
        "Generated by wafharness. The model proposed the bytes; the live "
        "response is the evidence. Confirm authorisation and exploitability "
        "before reporting.",
        "",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}
