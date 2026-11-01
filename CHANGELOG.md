# Changelog

## 0.1.0 — 2026-11-01

First public release.

- Cascade model: 16 WAF stacks and 18 backend stacks, all data-driven and
  editable.
- Divergence search over decoding, normalisation and message framing, including
  multipart, JSON, query, headers and cookies.
- Empirical fingerprinting from thirteen canaries, with honest ties and
  runner-up reporting.
- `plan` joins a measured profile to the offline divergence search and ranks the
  pairs worth testing.
- Live OWASP CRS Sandbox measurement (`crs`), in detection mode, with a default
  request rate inside the sandbox policy.
- Direct live front-door vs origin comparison (`compare`), gated by `--yes`.
- Single-URL confirmation (`confirm`): fingerprint, pick the best hypothesis,
  then send a control plus a bounded witness list. Reports `CONFIRMED`,
  `CANDIDATE`, `BLOCKED`, `INCONCLUSIVE` or `NO-WITNESSES`, not a guarantee.
- Professional identity labels (`identify`): WAF-like vs application-like,
  modelled fit, evidence, alternatives and caveats.
- Multi-entry verification (`verify`): tests named query parameters and saves a
  JSON/Markdown evidence chain with the exact payload, hex, URL, cause, status
  and reflection result.
- Rate-limited witness sender with a request budget and circuit breaker
  (`send`), also gated by `--yes`.
- 226 offline tests; no test opens a socket.
- `identify --simulate` joins `profile` and `plan` as an offline path, so a
  label and its caveats can be reviewed without aiming the tool at a host.
- `list-frames` documented, so the fourteen message frames and their
  duplicate-key precedence are discoverable without reading the source.
