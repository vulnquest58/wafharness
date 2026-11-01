"""Report rendering: console, JSON and Markdown.

The console view is the product. It has to answer three questions in the order
an operator asks them:

1. *Is there a gap between my target's WAF and its backend?*
2. *What is the smallest request that proves it?*
3. *Why does it work?* — which transform pair caused it.

A wall of payloads answers none of them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

from wafharness.models import Divergence, DivergenceKind, Profile, Stack
from wafharness.plan import Plan

if TYPE_CHECKING:
    from wafharness import finding, identity, live

_KIND_LABEL = {
    DivergenceKind.HIDDEN_FROM_WAF: "BYPASS",
    DivergenceKind.REWRITTEN: "rewritten",
    DivergenceKind.DEAD_END: "dead-end",
    DivergenceKind.NO_GAP: "no-gap",
}


def _safe(data: bytes, limit: int = 96) -> str:
    """Render bytes for a terminal without mangling control characters.

    Only printable ASCII is passed through. Everything else is escaped as
    ``\\xNN``: bytes 0x80-0x9F decode to C1 control characters under Latin-1,
    and a cp1252 console raises ``UnicodeEncodeError`` on them. Escaping is also
    more honest for a tool that reasons about bytes — the report shows exactly
    what was sent, not a best-effort rendering of it.
    """
    text = data.decode("latin-1")
    out = []
    for char in text[:limit]:
        if char == "\r":
            out.append("\\r")
        elif char == "\n":
            out.append("\\n")
        elif char == "\t":
            out.append("\\t")
        elif 32 <= ord(char) < 127:
            out.append(char)
        else:
            out.append(f"\\x{ord(char):02x}")
    if len(text) > limit:
        out.append("…")
    return "".join(out)


def console(divergences: List[Divergence], waf: Optional[Stack] = None,
            backend: Optional[Stack] = None, limit: int = 10) -> str:
    """Render the human view for one stack pair."""
    lines: List[str] = []

    if waf and backend:
        lines.append("")
        lines.append(f"  waf      {waf.name}")
        lines.append(f"           {waf.pipeline}")
        lines.append(f"  backend  {backend.name}")
        lines.append(f"           {backend.pipeline}")

    bypasses = [d for d in divergences if d.kind is DivergenceKind.HIDDEN_FROM_WAF]
    rewritten = [d for d in divergences if d.kind is DivergenceKind.REWRITTEN]

    lines.append("")
    if bypasses:
        lines.append(f"  GAP  {len(bypasses)} witness(es) reach the backend "
                     f"without tripping the WAF")
    elif rewritten:
        lines.append(f"  GAP  no executable bypass; {len(rewritten)} "
                     f"rewritten witness(es)")
    else:
        lines.append("  GAP  none — the two pipelines agree on every witness tried")

    shown = (bypasses or rewritten)[:limit]
    if shown:
        lines.append("")
        lines.append("  witnesses")
        for divergence in shown:
            label = _KIND_LABEL[divergence.kind]
            lines.append(f"    [{label}] {_safe(divergence.witness)}")
            lines.append(f"       waf sees    {_safe(divergence.left_view)}")
            lines.append(f"       backend sees {_safe(divergence.right_view)}")
            if divergence.differing_steps:
                lines.append(f"       cause       "
                             f"{', '.join(divergence.differing_steps)}")
            lines.append("")

    lines.append("")
    return "\n".join(lines)


def matrix(rows: List[Dict[str, object]], limit: int = 20) -> str:
    """Render the pair-by-pair summary used by ``--matrix``."""
    lines = ["", f"  {'waf':<18} {'backend':<16} {'bypass':>7} {'rewritten':>10}",
             "  " + "-" * 54]
    for row in rows[:limit]:
        lines.append(
            f"  {row['waf']:<18} {row['backend']:<16} "
            f"{row['bypass']:>7} {row['rewritten']:>10}")
    lines.append("")
    return "\n".join(lines)


def profile_console(profile: Profile) -> str:
    """Render an inferred live-target profile."""
    lines = ["", f"  target   {profile.target}",
             f"  best fit {profile.vendor or 'unknown'}"]
    if profile.detected:
        lines.append("  detected")
        for name, confidence in sorted(profile.detected.items(),
                                       key=lambda item: -item[1]):
            bar = "#" * int(confidence * 10)
            lines.append(f"    {name:<20} {confidence:>4.2f}  {bar}")
    else:
        lines.append("  detected  (nothing conclusive)")
    if profile.warnings:
        lines.append("  notes")
        for warning in profile.warnings:
            lines.append(f"    {warning}")
    lines.append("")
    return "\n".join(lines)


def identity_console(identity: "identity.Identity") -> str:
    """Render a WAF/application identity with its evidence and caveats."""
    lines = [
        "",
        f"  target   {identity.target}",
        f"  type     {identity.kind}",
        f"  label    {identity.label}",
        f"  fit      {identity.fit:.2f}",
    ]
    if identity.evidence:
        lines.append("  evidence")
        for item in identity.evidence:
            lines.append(f"    + {item}")
    if identity.alternatives:
        lines.append(f"  also     {', '.join(identity.alternatives)}")
    if identity.warnings:
        lines.append("  caveats")
        for warning in identity.warnings:
            lines.append(f"    ! {warning}")
    lines.append("")
    return "\n".join(lines)


def findings_console(findings: List["finding.Finding"], limit: int = 10) -> str:
    """Render the evidence chain: entry, verdict, payload and response."""
    lines = ["", "  findings"]
    if not findings:
        lines.append("    (none)")
        lines.append("")
        return "\n".join(lines)

    for item in findings[:limit]:
        cause = ", ".join(item.cause) or "modelled divergence"
        lines.append(
            f"    {item.verdict.upper():<10} {item.entry:<16} "
            f"{item.status:>3} {item.size:>6}B  "
            f"reflected={'yes' if item.reflected else 'no'}")
        lines.append(f"      payload  {_safe(item.payload, 120)}")
        lines.append(f"      cause    {cause}")
        lines.append(f"      request  {item.url[:100]}")
    if len(findings) > limit:
        lines.append(f"    ... {len(findings) - limit} more")
    lines.append("")
    return "\n".join(lines)


def plan_console(plan: Plan, limit: int = 6) -> str:
    """Render a measured plan: evidence, hypotheses, and the first witnesses.

    The ordering is the product. An operator should be able to read the top line
    and decide whether to make the first request, without re-reading the whole
    profile.
    """
    best_fit = plan.profile.vendor or plan.measured_stack or "unknown"
    lines = ["", f"  target   {plan.target}",
             f"  best fit {best_fit}",
             f"  side     {plan.measured_side}"]

    positive = [(name, value) for name, value in plan.profile.detected.items()
                if value >= 0.45
                and not name.startswith(("no:", "best_fit:", "also:"))]
    absent = sorted(name[3:] for name, value in plan.profile.detected.items()
                    if name.startswith("no:") and value >= 0.45)
    if positive or absent:
        lines.append("  evidence")
        for name, value in sorted(positive, key=lambda item: -item[1])[:8]:
            lines.append(f"    + {name:<20} {value:>4.2f}")
        if absent:
            lines.append(f"    - {', '.join(absent[:8])}"
                         + ("…" if len(absent) > 8 else ""))

    hypotheses = list(plan.hypotheses)
    if any(h.bypasses for h in hypotheses):
        # A plan is for acting on. Once at least one hypothesis has a witness,
        # "no gap" rows are footnotes, not options — the closing note covers
        # them, and JSON still contains every searched pair.
        hypotheses = [h for h in hypotheses if h.bypasses]

    lines.append("")
    if not hypotheses:
        lines.append("  plan  none — no hypothesis fits the measurement")
    else:
        lines.append("  plan")
        for index, hypothesis in enumerate(hypotheses[:limit], start=1):
            bypasses = hypothesis.bypasses
            marker = f"{len(bypasses)} bypass" if bypasses else "no gap"
            lines.append(
                f"    {index}. {hypothesis.waf.name} vs "
                f"{hypothesis.backend.name:<15} fit {hypothesis.fit:>4.2f}  "
                f"{marker}")
            for divergence in bypasses[:2]:
                lines.append(f"       [BYPASS] {_safe(divergence.witness, 64)}")
                if divergence.differing_steps:
                    lines.append(f"          cause: "
                                 f"{', '.join(divergence.differing_steps)}")
                lines.append(f"          waf sees     "
                             f"{_safe(divergence.left_view, 54)}")
                lines.append(f"          backend sees "
                             f"{_safe(divergence.right_view, 54)}")

    if plan.notes:
        lines.append("  notes")
        for note in plan.notes:
            lines.append(f"    {note}")
    lines.append("")
    return "\n".join(lines)


def crs_console(results: List["crs.CanaryResult"], limit: int = 99) -> str:
    """Render live CRS sandbox measurements: canary, decision, rule IDs."""
    from wafharness import crs

    lines = [""]
    for result in results[:limit]:
        ids = ", ".join(dict.fromkeys(
            rule.id for rule in result.rules[:5])) or "-"
        marker = "DETECTED" if result.detected else "allowed"
        lines.append(f"    {result.canary.name:<16} {marker:<9} {ids}")

    info = crs.summary(results)
    lines.append("")
    lines.append(f"  {info['detected']}/{info['canaries']} canaries triggered "
                 f"CRS; {info['rules']} unique rules")
    if info["rule_ids"]:
        lines.append(f"  rule ids: {', '.join(info['rule_ids'])}")
    lines.append("")
    return "\n".join(lines)


def compare_console(report: "live.ComparisonReport", limit: int = 99) -> str:
    """Render a direct live comparison: status, reflection and body verdict."""
    lines = [
        "",
        f"  front    {report.front}",
        f"  origin   {report.origin}",
        f"  control  front {report.control_front.status} / "
        f"origin {report.control_origin.status}",
        "",
    ]
    for note in report.notes:
        lines.append(f"  ! {note}")
    if report.notes:
        lines.append("")

    for item in report.comparisons[:limit]:
        flag = "*" if item.divergent else " "
        detail = f"  {item.detail}" if item.detail else ""
        lines.append(
            f"  {flag} {item.canary.name:<18} "
            f"{item.front.status:>3} / {item.origin.status:<3} "
            f"{item.verdict}{detail}")

    lines.append("")
    lines.append(f"  {len(report.divergences)}/{len(report.comparisons)} "
                 f"live divergences")
    lines.append("")
    return "\n".join(lines)


def as_json(divergences: List[Divergence],
            waf: Optional[Stack] = None,
            backend: Optional[Stack] = None) -> str:
    payload: Dict[str, object] = {
        "waf": waf.to_dict() if waf else None,
        "backend": backend.to_dict() if backend else None,
        "divergences": [d.to_dict() for d in divergences],
        "summary": {
            "total": len(divergences),
            "bypass": sum(1 for d in divergences
                          if d.kind is DivergenceKind.HIDDEN_FROM_WAF),
            "rewritten": sum(1 for d in divergences
                             if d.kind is DivergenceKind.REWRITTEN),
        },
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def as_markdown(divergences: List[Divergence], waf: Stack,
                backend: Stack) -> str:
    """A report suitable for a ticket or a write-up."""
    bypasses = [d for d in divergences if d.kind is DivergenceKind.HIDDEN_FROM_WAF]
    lines = [
        f"# WAF divergence — {waf.name} vs {backend.name}",
        "",
        f"- WAF pipeline: `{waf.pipeline}`",
        f"- Backend pipeline: `{backend.pipeline}`",
        f"- Witnesses that bypass: **{len(bypasses)}**",
        "",
    ]

    if not bypasses:
        lines += ["No executable bypass was found for this pair.", ""]

    for index, divergence in enumerate(bypasses[:20], 1):
        lines += [
            f"## {index}. {', '.join(divergence.tokens) or 'witness'}",
            "",
            f"| | |",
            f"| --- | --- |",
            f"| Kind | `{divergence.kind.value}` |",
            f"| Cause | `{', '.join(divergence.differing_steps)}` |",
            f"| Witness | `{_safe(divergence.witness, 200)}` |",
            f"| WAF sees | `{_safe(divergence.left_view, 200)}` |",
            f"| Backend sees | `{_safe(divergence.right_view, 200)}` |",
            "",
        ]

    lines += ["---", "",
              "Generated by wafharness. Validated against modelled stacks; "
              "confirm on the live target before reporting.", ""]
    return "\n".join(lines)


def save(divergences: List[Divergence], waf: Stack, backend: Stack,
         directory: Path, stem: Optional[str] = None) -> Dict[str, str]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stem = stem or f"wafharness_{waf.name}_vs_{backend.name}"
    json_path = directory / f"{stem}.json"
    md_path = directory / f"{stem}.md"
    json_path.write_text(as_json(divergences, waf, backend), encoding="utf-8")
    md_path.write_text(as_markdown(divergences, waf, backend), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}
