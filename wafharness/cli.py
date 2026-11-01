"""Command line interface.

The verbs form a chain, from hypothesis to measurement to request:

    wafharness find     --waf cloudflare --backend php
    wafharness matrix
    wafharness explain  --waf cloudflare --backend php --witness '%253C'
    wafharness frames   --pair multipart-strict multipart-lenient
    wafharness crs      --engine apache
    wafharness profile  --simulate cloudflare
    wafharness plan     --simulate cloudflare
    wafharness identify --url https://your-own-target
    wafharness verify   --url https://your-own-target --param q --yes
    wafharness compare  --front https://target --origin http://origin --yes
    wafharness confirm  --url https://your-own-target --yes
    wafharness stacks | list-frames | canaries

The search verbs are offline. ``crs`` uses the public OWASP sandbox by default;
``identify``, ``profile --url`` and ``plan --url`` send canary probes. ``compare``
sends the same canaries to a front door and an origin; ``confirm`` fingerprints
one URL and sends a small witness list; ``verify`` does that for several entry
points and saves the evidence. The last three require ``--yes``. ``send``
remains the low-level witness sender and also refuses without ``--yes``.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from wafharness import crs, engine, report, stacks
from wafharness.models import Divergence, DivergenceKind

BANNER = "wafharness 0.1.0 - bypass as divergence between rewriting systems"

NOTICE = (
    "Search is offline by default. crs uses the public CRS sandbox; identify, "
    "profile/plan with --url and compare send canaries (compare requires "
    "--yes); confirm, verify and send transmit witnesses and require --yes. "
    "Use findings only against systems you are authorised to test."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wafharness", description=BANNER, epilog=NOTICE)

    sub = parser.add_subparsers(dest="command")

    find = sub.add_parser("find", help="search one WAF/backend pair")
    find.add_argument("--waf", required=True, help="WAF stack name")
    find.add_argument("--backend", required=True, help="backend stack name")
    find.add_argument("--depth", type=int, default=2,
                      help="max encoders chained in one witness (default 2)")
    find.add_argument("--max", type=int, default=25,
                      help="max divergences to report (default 25)")
    find.add_argument("--json", action="store_true", help="emit JSON")
    find.add_argument("--markdown", action="store_true", help="emit Markdown")
    find.add_argument("--save", metavar="DIR",
                      help="write both JSON and Markdown into DIR")
    find.add_argument("-v", "--verbose", action="store_true",
                      help="show every witness, not just the first ten")

    matrix = sub.add_parser("matrix",
                            help="search every WAF against every backend")
    matrix.add_argument("--depth", type=int, default=1,
                        help="max chain depth; 1 keeps the matrix fast")
    matrix.add_argument("--json", action="store_true")
    matrix.add_argument("--top", type=int, default=20,
                        help="rows to display (default 20)")

    explain = sub.add_parser("explain", help="classify one witness by hand")
    explain.add_argument("--waf", required=True)
    explain.add_argument("--backend", required=True)
    explain.add_argument("--witness", required=True,
                         help="raw bytes, latin-1 or percent escapes")

    frames = sub.add_parser("frames",
                            help="search divergences between message frames")
    frames.add_argument("--pair", nargs=2, metavar=("LEFT", "RIGHT"),
                        help="compare two frames (default: every declared pair)")
    frames.add_argument("--json", action="store_true")
    frames.add_argument("-v", "--verbose", action="store_true")

    sub.add_parser("stacks", help="list the known stacks")
    sub.add_parser("list-frames", help="list the known message frames")
    sub.add_parser("canaries", help="list the fingerprint canaries")

    crs_parser = sub.add_parser(
        "crs",
        help="measure canaries against a live OWASP CRS sandbox "
             "(default: the public sandbox)")
    crs_parser.add_argument(
        "--url", default="https://sandbox.coreruleset.org/",
        help="CRS sandbox URL (default: the OWASP public sandbox)")
    crs_parser.add_argument(
        "--engine", default="apache",
        help="x-backend value: apache, nginx, coraza, ... (default apache)")
    crs_parser.add_argument(
        "--crs-version", help="x-crs-version value, e.g. v4-lts")
    crs_parser.add_argument(
        "--paranoia", type=int, help="x-paranoia-level value (1-4)")
    crs_parser.add_argument("--method", default="GET")
    crs_parser.add_argument("--param", default="q",
                            help="query parameter carrying the canary (default q)")
    crs_parser.add_argument("--timeout", type=float, default=20.0)
    crs_parser.add_argument(
        "--delay", type=float, default=0.2,
        help="seconds between requests (default 0.2; the sandbox limit is 10/s)")
    crs_parser.add_argument("--json", action="store_true")

    compare = sub.add_parser(
        "compare",
        help="send the same canaries to a front door and an origin and "
             "compare the live responses (requires --yes)")
    compare.add_argument("--front", required=True,
                         help="URL of the WAF-fronted endpoint")
    compare.add_argument("--origin", required=True,
                         help="URL of the direct/origin endpoint")
    compare.add_argument("--method", default="GET")
    compare.add_argument("--param", default="q",
                         help="query parameter carrying the canary (default q)")
    compare.add_argument("--timeout", type=float, default=8.0)
    compare.add_argument("--delay", type=float, default=0.3,
                         help="seconds between requests to each endpoint "
                              "(default 0.3)")
    compare.add_argument("--yes", action="store_true",
                         help="required confirmation; without it nothing is sent")
    compare.add_argument("--json", action="store_true")

    confirm_parser = sub.add_parser(
        "confirm",
        help="one URL: measure it, pick the best hypothesis, and send its "
             "witnesses (requires --yes)")
    confirm_parser.add_argument("--url", required=True,
                                help="your own authorised target URL")
    confirm_parser.add_argument("--waf", help="pin the WAF model (optional)")
    confirm_parser.add_argument("--backend",
                                help="pin the backend model (optional)")
    confirm_parser.add_argument("--method", default="GET")
    confirm_parser.add_argument("--param", default="q",
                                help="query parameter carrying the witness "
                                     "(default q)")
    confirm_parser.add_argument("--probe-delay", type=float, default=0.15,
                                help="seconds between fingerprint canaries "
                                     "(default 0.15)")
    confirm_parser.add_argument("--delay", type=float, default=3.0,
                                help="seconds between witness requests "
                                     "(default 3.0)")
    confirm_parser.add_argument("--max-witnesses", type=int, default=3,
                                help="witness budget after the control "
                                     "(default 3, max 10)")
    confirm_parser.add_argument("--timeout", type=float, default=10.0)
    confirm_parser.add_argument("--yes", action="store_true",
                                help="required confirmation; without it "
                                     "nothing is sent")
    confirm_parser.add_argument("--json", action="store_true")

    identify = sub.add_parser(
        "identify",
        help="name the measured WAF/application type from canary responses")
    identify.add_argument("--url",
                          help="target URL; 14 canary probes are sent")
    identify.add_argument("--simulate", metavar="STACK",
                          help="pretend the target runs this stack, offline")
    identify.add_argument("--method", default="GET")
    identify.add_argument("--param", default="q",
                          help="query parameter carrying the canary (default q)")
    identify.add_argument("--timeout", type=float, default=8.0)
    identify.add_argument("--delay", type=float, default=0.15,
                          help="seconds between live requests (default 0.15)")
    identify.add_argument("--json", action="store_true")

    verify_parser = sub.add_parser(
        "verify",
        help="identify the target, test named entry points, and save the "
             "payload that confirmed each result (requires --yes)")
    verify_parser.add_argument("--url", required=True,
                               help="your own authorised target URL")
    verify_parser.add_argument("--param", action="append",
                               help="query parameter entry point; repeat for "
                                    "several (default q)")
    verify_parser.add_argument("--waf", help="pin the WAF model (optional)")
    verify_parser.add_argument("--backend",
                               help="pin the backend model (optional)")
    verify_parser.add_argument("--method", default="GET")
    verify_parser.add_argument("--probe-delay", type=float, default=0.15,
                               help="seconds between fingerprint canaries")
    verify_parser.add_argument("--delay", type=float, default=3.0,
                               help="seconds between witness requests")
    verify_parser.add_argument("--max-witnesses", type=int, default=3,
                               help="witnesses per entry point (default 3)")
    verify_parser.add_argument("--max-entries", type=int, default=8,
                               help="hard cap on entry points (default 8)")
    verify_parser.add_argument("--timeout", type=float, default=10.0)
    verify_parser.add_argument("--save", metavar="DIR",
                               help="write the evidence chain to DIR")
    verify_parser.add_argument("--yes", action="store_true",
                               help="required confirmation; without it "
                                    "nothing is sent")
    verify_parser.add_argument("--json", action="store_true")

    profile = sub.add_parser(
        "profile",
        help="infer a live target's cascade from canary responses "
             "(simulated unless --url is given)")
    profile.add_argument("--url", help="target URL; omit to simulate")
    profile.add_argument("--method", default="GET")
    profile.add_argument("--param", default="q",
                         help="query parameter to carry the canary (default q)")
    profile.add_argument("--timeout", type=float, default=8.0)
    profile.add_argument("--delay", type=float, default=0.15,
                         help="seconds between live requests (default 0.15)")
    profile.add_argument("--simulate", metavar="STACK",
                         help="pretend the target runs this stack, offline")
    profile.add_argument("--json", action="store_true")

    plan = sub.add_parser(
        "plan",
        help="measure a target, then rank the stack pairs worth searching "
             "(and the requests worth making)")
    plan.add_argument("--url", help="target URL; canary probes are sent")
    plan.add_argument("--simulate", metavar="STACK",
                      help="measure this modelled stack offline")
    plan.add_argument("--profile", metavar="FILE",
                      help="reuse a profile saved as JSON instead of measuring")
    plan.add_argument("--waf", help="pin the WAF model (optional)")
    plan.add_argument("--backend", help="pin the backend model (optional)")
    plan.add_argument("--method", default="GET")
    plan.add_argument("--param", default="q",
                      help="query parameter carrying the canary (default q)")
    plan.add_argument("--timeout", type=float, default=8.0)
    plan.add_argument("--delay", type=float, default=0.15,
                      help="seconds between live requests (default 0.15)")
    plan.add_argument("--depth", type=int, default=2,
                      help="max encoders chained in one witness (default 2)")
    plan.add_argument("--max", dest="max_divergences", type=int, default=8,
                      help="max divergences per pair (default 8)")
    plan.add_argument("--top", type=int, default=6,
                      help="hypotheses to display (default 6)")
    plan.add_argument("--json", action="store_true")

    # The only verb that sends witnesses. Every safety limit is a flag so it is
    # visible in the command line rather than buried in a config file.
    send = sub.add_parser(
        "send",
        help="send witnesses to a target you are authorised to test "
             "(sequential, rate-limited, with a circuit breaker)")
    send.add_argument("--url", required=True,
                      help="base URL of the authorised target")
    send.add_argument("--waf", required=True, help="WAF stack to model")
    send.add_argument("--backend", required=True, help="backend stack to model")
    send.add_argument("--param", default="q",
                      help="query parameter carrying the witness (default q)")
    send.add_argument("--method", default="GET")
    send.add_argument("--delay", type=float, default=3.0,
                      help="seconds between requests (default 3.0)")
    send.add_argument("--max-requests", type=int, default=10,
                      help="hard request budget (default 10)")
    send.add_argument("--breaker", type=int, default=5,
                      help="consecutive blocks before stopping (default 5)")
    send.add_argument("--timeout", type=float, default=10.0)
    send.add_argument("--dry-run", action="store_true",
                      help="show what would be sent, send nothing")
    send.add_argument("--yes", action="store_true",
                      help="required confirmation; without it nothing is sent")
    send.add_argument("--json", action="store_true")

    parser.add_argument("--version", action="version", version=BANNER)
    return parser


def _stack_names_or_die(kind: str) -> None:
    print(f"known {kind} stacks: {', '.join(stacks.names(kind))}", file=sys.stderr)


def _resolve(name: str):
    try:
        return stacks.get(name)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)


def cmd_find(args) -> int:
    waf = _resolve(args.waf)
    backend = _resolve(args.backend)

    budget = engine.Budget(max_divergences=args.max, max_depth=args.depth)
    divergences = engine.search_pair(waf, backend, budget=budget)

    if args.json:
        print(report.as_json(divergences, waf, backend))
    elif args.markdown:
        print(report.as_markdown(divergences, waf, backend))
    else:
        print(report.console(divergences, waf, backend,
                             limit=99 if args.verbose else 10))

    if args.save:
        from pathlib import Path
        written = report.save(divergences, waf, backend, Path(args.save))
        print(f"saved: {written['json']}")
        print(f"saved: {written['markdown']}")

    return 0 if divergences else 1


def cmd_matrix(args) -> int:
    budget = engine.Budget(max_depth=args.depth, max_divergences=15)
    rows = []
    for waf, backend in stacks.default_pairs():
        found = engine.search_pair(waf, backend, budget=budget)
        rows.append({
            "waf": waf.name,
            "backend": backend.name,
            "bypass": sum(1 for d in found
                          if d.kind is DivergenceKind.HIDDEN_FROM_WAF),
            "rewritten": sum(1 for d in found
                             if d.kind is DivergenceKind.REWRITTEN),
        })

    rows.sort(key=lambda row: (-row["bypass"], -row["rewritten"]))
    if args.json:
        import json
        print(json.dumps(rows, indent=2))
    else:
        print(report.matrix(rows, limit=args.top))
    return 0


def cmd_explain(args) -> int:
    waf = _resolve(args.waf)
    backend = _resolve(args.backend)

    witness = args.witness.encode("latin-1", "backslashreplace")
    divergence = engine.classify(waf, backend, witness)
    print(engine.explain(divergence))
    return 0 if divergence.kind is DivergenceKind.HIDDEN_FROM_WAF else 1


def cmd_stacks(_args) -> int:
    print("\n  WAF stacks")
    for name in stacks.names("waf"):
        stack = stacks.get(name)
        print(f"    {name:<18} {stack.pipeline}")
    print("\n  backend stacks")
    for name in stacks.names("backend"):
        stack = stacks.get(name)
        print(f"    {name:<18} {stack.pipeline}")
    print("")
    return 0


def cmd_frames(args) -> int:
    """Search framing divergences, either one pair or every declared pair."""
    from wafharness import framing

    pairs = [tuple(args.pair)] if args.pair else engine.framing_pairs()
    total = 0
    rows = []

    for pair in pairs:
        found = engine.framing_search(pair)
        total += len(found)
        bypass = [d for d in found if d.kind is DivergenceKind.HIDDEN_FROM_WAF]
        rows.append({"pair": " vs ".join(pair), "bypass": len(bypass),
                     "total": len(found), "witnesses": found})

    if args.json:
        import json
        print(json.dumps([{k: v for k, v in row.items() if k != "witnesses"}
                          for row in rows], indent=2))
        return 0 if total else 1

    print("")
    for row in rows:
        print(f"  {row['pair']:<42} {row['bypass']:>3} bypass  "
              f"{row['total']:>3} total")
        shown = row["witnesses"] if args.verbose else row["witnesses"][:2]
        for divergence in shown:
            label = report._KIND_LABEL[divergence.kind]
            print(f"     [{label}] "
                  f"{report._safe(divergence.witness, 68)}")
            print(f"        left : {report._safe(divergence.left_view, 56)}")
            print(f"        right: {report._safe(divergence.right_view, 56)}")
    print(f"\n  framing divergences: {total}\n")
    return 0 if total else 1


def cmd_list_frames(_args) -> int:
    from wafharness import framing

    print("")
    for name in framing.names():
        frame = framing.get(name)
        rule = "last wins" if frame.last_wins else "first wins"
        print(f"    {name:<22} duplicates: {rule}")
    print("")
    return 0


def cmd_canaries(_args) -> int:
    from wafharness import canaries

    def printable(data: bytes, limit: int = 44) -> str:
        """ASCII-safe rendering: a cp1252 console cannot encode ＜ or \x9c."""
        out = []
        for byte in data[:limit]:
            if 32 <= byte < 127:
                out.append(chr(byte))
            else:
                out.append(f"\\x{byte:02x}")
        return "".join(out) + ("…" if len(data) > limit else "")

    print("")
    for canary in canaries.CANARIES:
        print(f"    {canary.name:<16} {printable(canary.payload):<46} "
              f"detects {canary.detects}")
    print("")
    return 0


def cmd_profile(args) -> int:
    """Fingerprint a target — simulated offline, or measured over HTTP."""
    from wafharness import fingerprint
    from wafharness import report as report_module

    if bool(args.simulate) == bool(args.url):
        print("give exactly one of --url (measure) or --simulate (offline)",
              file=sys.stderr)
        return 2

    if args.simulate:
        transport = _simulated_transport(args.simulate)
        if transport is None:
            return 2
        profile = fingerprint.probe(transport, target=f"simulated:{args.simulate}")
    else:
        transport = _http_transport(args.url, args.method, args.param,
                                    args.timeout, args.delay)
        profile = fingerprint.probe(transport, target=args.url)

    if args.json:
        import json
        print(json.dumps(profile.to_dict(), indent=2))
    else:
        print(report_module.profile_console(profile))
        print(f"  {fingerprint.summarise(profile)}\n")

    return 0 if profile.detected else 1


def cmd_crs(args) -> int:
    """Measure the canaries against a live CRS sandbox, in detection mode.

    This is a measurement, not a model: the sandbox is an actual CRS deployment
    and the response is its actual audit output. The OWASP policy permits
    automated payload testing at ten requests per second or less.
    """
    if args.paranoia is not None and not 1 <= args.paranoia <= 4:
        print("--paranoia must be between 1 and 4", file=sys.stderr)
        return 2

    transport = _crs_transport(
        args.url, args.method, args.param, args.timeout, args.delay,
        args.engine, args.crs_version, args.paranoia)
    results = crs.measure(transport)

    if results and all(result.status == 0 for result in results):
        print("sandbox unreachable; no measurements were taken", file=sys.stderr)
        return 1

    if args.json:
        import json
        print(json.dumps([result.to_dict() for result in results], indent=2))
    else:
        print("")
        print(f"  sandbox  {args.url}")
        print(f"  engine   {args.engine}")
        print(report.crs_console(results))

    return 0


def cmd_compare(args) -> int:
    """Send the same canaries to a front door and an origin, then compare.

    Unlike ``plan``, this does not consult the stack matrix: the verdicts come
    from the two live endpoints. A ``front-blocked`` row is the direct evidence
    the offline search can only predict.
    """
    from wafharness import live

    if not args.yes:
        print(
            "\n  Refusing to compare.\n\n"
            "  This command sends canaries to two live hosts. Confirm that you\n"
            "  hold explicit authorisation for both the front door and the\n"
            "  origin, then re-run with --yes.\n",
            file=sys.stderr)
        return 2

    front = _http_transport(args.front, args.method, args.param,
                            args.timeout, args.delay)
    origin = _http_transport(args.origin, args.method, args.param,
                             args.timeout, args.delay)
    result = live.compare(front, origin, front_name=args.front,
                          origin_name=args.origin)

    if args.json:
        import json
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(report.compare_console(result))

    return 0 if result.divergences else 1


def cmd_confirm(args) -> int:
    """Measure one URL, choose the best hypothesis, and send its witnesses.

    This is the shortest authorised path from a domain to evidence: 14 canary
    probes, an offline hypothesis, then a control plus at most ten witnesses.
    A reflection is reported as ``CONFIRMED``; a pass without reflection is a
    ``CANDIDATE``, because a single URL cannot prove backend execution.
    """
    from wafharness import confirm, fingerprint, plan as planner, sender

    if not args.yes:
        print(
            "\n  Refusing to confirm.\n\n"
            "  This command fingerprints a live host and then sends its\n"
            "  witnesses. Confirm that you own or are explicitly authorised\n"
            "  to test the target, then re-run with --yes.\n",
            file=sys.stderr)
        return 2

    if not 1 <= args.max_witnesses <= 10:
        print("--max-witnesses must be between 1 and 10", file=sys.stderr)
        return 2
    if args.delay < 0 or args.probe_delay < 0:
        print("--delay and --probe-delay must be non-negative",
              file=sys.stderr)
        return 2

    waf = _resolve(args.waf) if args.waf else None
    backend = _resolve(args.backend) if args.backend else None

    transport = _http_transport(args.url, args.method, args.param,
                                args.timeout, args.probe_delay)
    profile = fingerprint.probe(transport, target=args.url)

    budget = engine.Budget(max_depth=2, max_divergences=args.max_witnesses)
    result = planner.build(profile, waf=waf, backend=backend, budget=budget)
    hypothesis = next(
        (item for item in result.hypotheses if item.bypasses), None)
    if hypothesis is None:
        if args.json:
            import json
            print(json.dumps({
                "target": args.url,
                "verdict": confirm.NO_WITNESSES,
                "notes": ["no modelled witness is available for this target"],
                "plan": result.to_dict(),
            }, indent=2))
        else:
            print(report.plan_console(result, limit=3))
            print("  no modelled witness is available for this target; "
                  "nothing was sent beyond the canaries\n")
        return 1

    if not args.json:
        print(f"  profile     {profile.vendor or 'unidentified'} "
              f"(side {result.measured_side})")
        if result.best is not None and result.best is not hypothesis:
            print("  note        the best-fitting hypothesis has no modelled "
                  "witness; testing the next one")
        for note in result.notes:
            print(f"  note        {note}")

    witnesses = list(hypothesis.bypasses[:args.max_witnesses])
    limits = sender.Limits(
        delay=args.delay,
        max_requests=len(witnesses) + 1,
        breaker_threshold=5,
        timeout=args.timeout,
    )
    run = sender.send(args.url, witnesses, limits=limits,
                      method=args.method, parameter=args.param)
    confirmation = confirm.assess(hypothesis, run)

    if args.json:
        import json
        print(json.dumps(confirmation.to_dict(), indent=2))
    else:
        print(confirm.summarise(confirmation))

    return 0 if confirmation.verdict == confirm.CONFIRMED else 1


def cmd_identify(args) -> int:
    """Name the measured side and label without sending witnesses.

    The label is a modelled fit, not a vendor certificate: the output always
    carries the evidence, alternatives and the fingerprint's own caveats.

    ``--simulate`` mirrors ``profile`` and ``plan`` so the whole identification
    path can be exercised — and its output reviewed — with no network at all.
    """
    from wafharness import fingerprint, identity
    from wafharness import plan as planner

    if getattr(args, "simulate", None):
        transport = _simulated_transport(args.simulate)
        if transport is None:
            return 2
        target = f"simulated:{args.simulate}"
        profile = fingerprint.probe(transport, target=target)
    elif args.url:
        transport = _http_transport(args.url, args.method, args.param,
                                    args.timeout, args.delay)
        profile = fingerprint.probe(transport, target=args.url)
    else:
        print("give --url to identify a live target or --simulate to run offline",
              file=sys.stderr)
        return 2

    budget = engine.Budget(max_depth=1, max_divergences=1)
    result = planner.build(profile, budget=budget, max_pairs=1)
    ident = identity.identify(profile, result.measured_side)

    if args.json:
        import json
        payload = ident.to_dict()
        payload["profile"] = profile.to_dict()
        print(json.dumps(payload, indent=2))
    else:
        print(report.identity_console(ident))

    return 0 if ident.label != "unknown" and bool(ident.evidence) else 1


def cmd_verify(args) -> int:
    """Identify the target, test named entry points, and retain the evidence.

    The fingerprint runs once. The chosen hypothesis is then sent to every
    requested query parameter, so the report can distinguish "the WAF is
    bypassable" from "this entry point is bypassable". Each sent witness is
    bound to its exact bytes, URL, status and reflection result in a finding.
    """
    from wafharness import confirm, finding, fingerprint, identity
    from wafharness import plan as planner
    from wafharness import sender

    if not args.yes:
        print(
            "\n  Refusing to verify.\n\n"
            "  This command fingerprints a live host and sends witnesses to\n"
            "  each named entry point. Confirm that you own or are explicitly\n"
            "  authorised to test the target, then re-run with --yes.\n",
            file=sys.stderr)
        return 2

    if not 1 <= args.max_witnesses <= 10:
        print("--max-witnesses must be between 1 and 10", file=sys.stderr)
        return 2
    if not 1 <= args.max_entries <= 20:
        print("--max-entries must be between 1 and 20", file=sys.stderr)
        return 2
    if args.delay < 0 or args.probe_delay < 0:
        print("--delay and --probe-delay must be non-negative",
              file=sys.stderr)
        return 2

    params = list(dict.fromkeys(args.param or ["q"]))[:args.max_entries]
    waf = _resolve(args.waf) if args.waf else None
    backend = _resolve(args.backend) if args.backend else None

    transport = _http_transport(args.url, args.method, params[0],
                                args.timeout, args.probe_delay)
    profile = fingerprint.probe(transport, target=args.url)

    budget = engine.Budget(max_depth=2, max_divergences=args.max_witnesses)
    result = planner.build(profile, waf=waf, backend=backend, budget=budget)
    hypothesis = next(
        (item for item in result.hypotheses if item.bypasses), None)
    if hypothesis is None:
        if args.json:
            import json
            print(json.dumps({
                "target": args.url,
                "verdict": confirm.NO_WITNESSES,
                "notes": ["no modelled witness is available for this target"],
                "plan": result.to_dict(),
            }, indent=2))
        else:
            print(report.plan_console(result, limit=3))
            print("  no modelled witness is available for this target; "
                  "nothing was sent beyond the canaries\n")
        return 1

    ident = identity.identify(profile, result.measured_side)
    witnesses = list(hypothesis.bypasses[:args.max_witnesses])
    entries = []
    all_findings = []

    for parameter in params:
        limits = sender.Limits(
            delay=args.delay,
            max_requests=len(witnesses) + 1,
            breaker_threshold=5,
            timeout=args.timeout,
        )
        run = sender.send(args.url, witnesses, limits=limits,
                          method=args.method, parameter=parameter)
        confirmation = confirm.assess(hypothesis, run)
        findings = finding.from_confirmation(
            confirmation, f"query:{parameter}", target=args.url)
        entries.append({
            "entry": f"query:{parameter}",
            "verdict": confirmation.verdict,
            "notes": list(confirmation.notes),
            "findings": [item.to_dict() for item in findings],
        })
        all_findings.extend(findings)

    payload = {
        "target": args.url,
        "identity": ident.to_dict(),
        "hypothesis": hypothesis.to_dict(),
        "entries": entries,
        "summary": {
            "entries": len(entries),
            "confirmed_entries": sum(
                1 for entry in entries if entry["verdict"] == confirm.CONFIRMED),
            "findings": len(all_findings),
            "confirmed_findings": sum(
                1 for item in all_findings if item.verdict == "confirmed"),
        },
    }

    if args.save:
        from pathlib import Path
        try:
            paths = finding.save(all_findings, Path(args.save), extra={
                "identity": ident.to_dict(),
                "hypothesis": hypothesis.to_dict(),
                "entries": entries,
            }, stem="wafharness_verify")
        except OSError as exc:
            print(f"cannot save findings to {args.save!r}: {exc}",
                  file=sys.stderr)
            return 2
        payload["saved"] = paths
        if not args.json:
            print(f"  saved    {paths['json']}")
            print(f"  saved    {paths['markdown']}")

    if args.json:
        import json
        print(json.dumps(payload, indent=2))
    else:
        print(report.identity_console(ident))
        print(f"  hypothesis  {hypothesis.waf.name} vs "
              f"{hypothesis.backend.name} (fit {hypothesis.fit:.2f})")
        if result.best is not None and result.best is not hypothesis:
            print("  note        the best-fitting hypothesis has no modelled "
                  "witness; testing the next one")
        print("  entries")
        for entry in entries:
            print(f"    {entry['entry']:<18} {entry['verdict'].upper()}")
            for note in entry["notes"]:
                print(f"      note  {note}")
        print(report.findings_console(all_findings))

    return 0 if payload["summary"]["confirmed_findings"] else 1


def cmd_plan(args) -> int:
    """Measure (or simulate), then rank hypotheses and witnesses.

    With ``--url`` this sends canaries only. Witnesses are still printed, never
    sent: ``send`` remains the one place where that decision is made.
    """
    from wafharness import fingerprint
    from wafharness import plan as planner
    from wafharness import report as report_module

    sources = [bool(args.url), bool(args.simulate), bool(args.profile)]
    if sum(sources) != 1:
        print("give exactly one of --url (measure), --simulate (offline), "
              "or --profile (reuse a saved profile)", file=sys.stderr)
        return 2

    # Resolve pinned models before any canary is sent: a typo in --waf must not
    # cost the target fourteen requests.
    waf = _resolve(args.waf) if args.waf else None
    backend = _resolve(args.backend) if args.backend else None

    if args.profile:
        import json
        from pathlib import Path

        from wafharness.models import Profile

        try:
            payload = json.loads(
                Path(args.profile).read_text(encoding="utf-8"))
            profile = Profile.from_dict(payload)
        except (OSError, ValueError, TypeError) as exc:
            print(f"cannot read profile {args.profile!r}: {exc}",
                  file=sys.stderr)
            return 2
    elif args.simulate:
        transport = _simulated_transport(args.simulate)
        if transport is None:
            return 2
        profile = fingerprint.probe(
            transport, target=f"simulated:{args.simulate}")
    else:
        transport = _http_transport(args.url, args.method, args.param,
                                    args.timeout, args.delay)
        profile = fingerprint.probe(transport, target=args.url)

    budget = engine.Budget(max_depth=args.depth,
                           max_divergences=args.max_divergences)
    result = planner.build(profile, waf=waf, backend=backend, budget=budget)

    if args.json:
        import json
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(report_module.plan_console(result, limit=args.top))

    return 0 if result.bypasses else 1


def _simulated_transport(stack_name: str):
    """A transport that behaves like the named stack — no network at all."""
    from wafharness import stacks

    try:
        stack = stacks.get(stack_name)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return None

    def transport(payload: bytes):
        view, rejection = stack.run(payload)
        if rejection:
            return 403, b"blocked"
        return 200, b"<html>echo:" + view + b"</html>"

    return transport


def _http_transport(url: str, method: str, param: str, timeout: float,
                    delay: float = 0.15):
    """A real transport for canaries: one of the CLI's live entry points."""
    import time
    import urllib.parse
    import urllib.request

    first = [True]

    def transport(payload: bytes):
        if not first[0]:
            time.sleep(max(delay, 0.0))
        first[0] = False

        encoded = urllib.parse.quote_from_bytes(payload, safe="")
        separator = "&" if "?" in url else "?"
        target = f"{url}{separator}{param}={encoded}"
        request = urllib.request.Request(target, method=method.upper())
        request.add_header("User-Agent", "wafharness/0.1 (authorised testing)")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read(65536)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(4096)
        except Exception:
            return 0, b""

    return transport


def _crs_transport(url: str, method: str, param: str, timeout: float,
                   delay: float = 0.2, engine: Optional[str] = None,
                   crs_version: Optional[str] = None,
                   paranoia: Optional[int] = None):
    """A live transport for a CRS sandbox.

    Detection mode is requested so the sandbox returns audit JSON instead of a
    generic block page. ``json-matched-rules`` makes the result attributable to
    rule IDs, which is what the report shows. The public sandbox permits this
    at ten requests per second or less; the default delay is well inside that.
    """
    import time
    import urllib.parse
    import urllib.request

    first = [True]

    def transport(payload: bytes):
        if not first[0]:
            time.sleep(max(delay, 0.0))
        first[0] = False

        encoded = urllib.parse.quote_from_bytes(payload, safe="")
        separator = "&" if "?" in url else "?"
        target = f"{url}{separator}{param}={encoded}"
        request = urllib.request.Request(target, method=method.upper())
        request.add_header("User-Agent",
                           "wafharness/0.1 (authorised CRS sandbox testing)")
        request.add_header("x-format-output", "json-matched-rules")
        request.add_header("x-crs-mode", "detection")
        if engine:
            request.add_header("x-backend", engine)
        if crs_version:
            request.add_header("x-crs-version", crs_version)
        if paranoia is not None:
            request.add_header("x-paranoia-level", str(paranoia))
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read(65536)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(4096)
        except Exception:
            return 0, b""

    return transport


def cmd_send(args) -> int:
    """Measure, search, then send — with two independent confirmations."""
    from wafharness import fingerprint, sender

    if not args.yes and not args.dry_run:
        print(
            "\n  Refusing to send.\n\n"
            "  This command makes real requests to a real host. Confirm that you\n"
            "  hold explicit authorisation for it, then re-run with --yes.\n"
            "  Use --dry-run to see what would be sent without sending it.\n",
            file=sys.stderr)
        return 2

    waf = _resolve(args.waf)
    backend = _resolve(args.backend)

    divergences = engine.search_pair(waf, backend)
    bypasses = [d for d in divergences
                if d.kind is DivergenceKind.HIDDEN_FROM_WAF]
    if not bypasses:
        print("no bypass witnesses for this pair; nothing to send", file=sys.stderr)
        return 1

    limits = sender.Limits(
        delay=args.delay,
        max_requests=args.max_requests,
        breaker_threshold=args.breaker,
        timeout=args.timeout,
    )

    if args.dry_run:
        print("")
        print(f"  would send {len(bypasses[:limits.max_requests])} request(s) "
              f"to {args.url}")
        print(f"  delay {limits.delay}s   budget {limits.max_requests}   "
              f"breaker {limits.breaker_threshold}")
        print("")
        for index, divergence in enumerate(
                bypasses[:limits.max_requests], start=1):
            url = sender.build_request(args.url, divergence.witness,
                                       method=args.method,
                                       parameter=args.param)
            print(f"    {index:>2}. {url[:96]}")
        print("")
        return 0

    report = sender.send(
        args.url, bypasses, limits=limits, method=args.method,
        parameter=args.param,
    )

    if args.json:
        import json
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(sender.summarise(report))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    handlers = {
        "find": cmd_find,
        "matrix": cmd_matrix,
        "explain": cmd_explain,
        "stacks": cmd_stacks,
        "frames": cmd_frames,
        "list-frames": cmd_list_frames,
        "canaries": cmd_canaries,
        "crs": cmd_crs,
        "compare": cmd_compare,
        "confirm": cmd_confirm,
        "identify": cmd_identify,
        "verify": cmd_verify,
        "profile": cmd_profile,
        "plan": cmd_plan,
        "send": cmd_send,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
