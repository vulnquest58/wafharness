"""Known interpretation stacks.

Every entry is a *model* of how a component rewrites a request before deciding.
Two kinds ship here:

* **waf** stacks — the inspection side. Their job is to block.
* **backend** stacks — the execution side. Their job is to act.

A bypass lives in the gap between one of each.

Honesty about provenance
------------------------

None of these were derived by reverse-engineering a live appliance for this
project. Each is built from public documentation, vendor advisories and the
published behaviour of the underlying parser, and every entry carries a
``notes`` field saying exactly that. Where a behaviour is contested or
version-dependent, the model deliberately takes the *simpler* form and says so,
because an over-modelled stack produces divergences that do not exist — which is
worse than a missing one.

The :attr:`Stack.verified` flag distinguishes the two: ``False`` means "modelled,
not measured". A divergence found between two unverified stacks is a *hypothesis*
until the fingerprint step confirms the stack is really there.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from wafharness.models import Stack
from wafharness.transforms import resolve

# ══════════════════════════════════════════════════════════════════════════════
#  WAF side
# ══════════════════════════════════════════════════════════════════════════════

_MODEL_NOTE = "modelled from public documentation; not empirically verified here"


def _waf(name: str, decode, normalize, forbidden=(), notes: str = "") -> Stack:
    return Stack(
        name=name,
        decode=resolve(decode),
        normalize=resolve(normalize),
        forbidden=tuple(forbidden),
        notes=notes or _MODEL_NOTE,
    )


WAF_STACKS: Dict[str, Stack] = {
    # Most managed rulesets decode percent-encoding once and stop. The double
    # decode is the application's job, which is the whole reason %253C works.
    "cloudflare": _waf(
        "cloudflare",
        decode=["url_decode", "html_entity"],
        normalize=["nfkc", "lowercase"],
        notes="decodes once then normalises; assumed no recursive decode "
              + _MODEL_NOTE,
    ),

    # CRS performs a documented multi-pass normalisation and strips SQL comments
    # before matching (paranoia-level dependent).
    "modsecurity-crs": _waf(
        "modsecurity-crs",
        decode=["url_decode"],
        normalize=["strip_sql_comments", "collapse_ws", "lowercase"],
        notes="CRS normalisation pipeline at default paranoia; " + _MODEL_NOTE,
    ),

    # F5 ASM is widely reported to normalise more than once. Modelled with a
    # second decode because that is the behaviour that makes it stricter, and
    # being stricter here means fewer claimed bypasses, not more.
    "f5-asm": _waf(
        "f5-asm",
        decode=["url_decode_twice"],
        normalize=["nfkc", "lowercase"],
        notes="assumes recursive decoding (reported, version dependent); "
              + _MODEL_NOTE,
    ),

    "aws-waf": _waf(
        "aws-waf",
        decode=["url_decode_plus"],
        normalize=["lowercase"],
        notes="form-encoding semantics assumed for body inspection; "
              + _MODEL_NOTE,
    ),

    "imperva": _waf(
        "imperva",
        decode=["url_decode", "unicode_escape"],
        normalize=["nfkc", "lowercase"],
        notes="decodes percent and unicode escapes; " + _MODEL_NOTE,
    ),

    "akamai": _waf(
        "akamai",
        decode=["url_decode"],
        normalize=["lowercase"],
        notes="minimal normalisation assumed; " + _MODEL_NOTE,
    ),

    "azure-frontdoor": _waf(
        "azure-frontdoor",
        decode=["url_decode", "html_entity"],
        normalize=["lowercase"],
        notes="percent and HTML entities; " + _MODEL_NOTE,
    ),

    "fastly": _waf(
        "fastly",
        decode=["url_decode"],
        normalize=["collapse_ws", "lowercase"],
        notes="VCL-driven, so behaviour is per-tenant; minimal model assumed; "
              + _MODEL_NOTE,
    ),

    # Coraza is a CRS-compatible engine: the rule language and normalisation
    # family are shared, so it is modelled with the CRS pipeline.
    "coraza": _waf(
        "coraza",
        decode=["url_decode"],
        normalize=["strip_sql_comments", "collapse_ws", "lowercase"],
        notes="CRS-compatible engine; assumed same pipeline as "
              "modsecurity-crs; " + _MODEL_NOTE,
    ),

    # Google documents Cloud Armor's preconfigured WAF rules as derived from
    # ModSecurity CRS. The managed-rule subset is not identical, so this is a
    # family model, not a rule-for-rule copy.
    "google-cloud-armor": _waf(
        "google-cloud-armor",
        decode=["url_decode"],
        normalize=["strip_sql_comments", "collapse_ws", "lowercase"],
        notes="preconfigured rules derived from CRS; CRS-like pipeline "
              "assumed; " + _MODEL_NOTE,
    ),

    "sucuri": _waf(
        "sucuri",
        decode=["url_decode", "html_entity"],
        normalize=["lowercase"],
        notes="percent and HTML-entity decoding assumed; " + _MODEL_NOTE,
    ),

    "fortiweb": _waf(
        "fortiweb",
        decode=["url_decode_plus", "html_entity"],
        normalize=["lowercase"],
        notes="form decoding plus entity decoding assumed; " + _MODEL_NOTE,
    ),

    "wallarm": _waf(
        "wallarm",
        decode=["url_decode", "unicode_escape", "html_entity"],
        normalize=["nfkc", "lowercase"],
        notes="multi-encoding normalisation assumed; " + _MODEL_NOTE,
    ),

    "radware": _waf(
        "radware",
        decode=["url_decode", "html_entity"],
        normalize=["lowercase"],
        notes="percent and HTML-entity decoding assumed; " + _MODEL_NOTE,
    ),

    "citrix-netscaler": _waf(
        "citrix-netscaler",
        decode=["url_decode_plus"],
        normalize=["lowercase"],
        notes="form-style decoding assumed; " + _MODEL_NOTE,
    ),

    "barracuda": _waf(
        "barracuda",
        decode=["url_decode", "html_entity"],
        normalize=["lowercase"],
        notes="percent and HTML-entity decoding assumed; " + _MODEL_NOTE,
    ),
}

# ══════════════════════════════════════════════════════════════════════════════
#  Backend side
# ══════════════════════════════════════════════════════════════════════════════


def _backend(name: str, decode, normalize, notes: str) -> Stack:
    return Stack(
        name=name,
        decode=resolve(decode),
        normalize=resolve(normalize),
        notes=notes,
    )


BACKEND_STACKS: Dict[str, Stack] = {
    # PHP's form parser turns '+' into space and percent-decodes once. It does
    # not decode a second time, and it does not touch the raw body.
    "php": _backend(
        "php",
        decode=["url_decode_plus"],
        normalize=[],
        notes="$_POST semantics: plus-as-space, single decode, no normalisation",
    ),

    # Java's Uri/MessageFormat layer accepts \uXXXX in several code paths, and
    # String handling is frequently NFKC-normalised at the framework boundary.
    "java-spring": _backend(
        "java-spring",
        decode=["url_decode", "unicode_escape"],
        normalize=["nfkc"],
        notes="Uri decoding plus MessageFormat escapes; NFKC at the string layer",
    ),

    # Express' body parsers decode the URL-encoded body and nothing else.
    "node-express": _backend(
        "node-express",
        decode=["url_decode_plus"],
        normalize=[],
        notes="qs/body-parser semantics: plus-as-space, single decode",
    ),

    # Werkzeug decodes percent-encoding; it does not interpret HTML entities and
    # does not collapse whitespace.
    "python-werkzeug": _backend(
        "python-werkzeug",
        decode=["url_decode"],
        normalize=[],
        notes="urllib.parse.unquote semantics",
    ),

    # .NET's form reader decodes percent-encoding and '+' to space, and the
    # request pipeline is case-insensitive for header and form keys.
    "dotnet": _backend(
        "dotnet",
        decode=["url_decode_plus", "html_entity"],
        normalize=["lowercase"],
        notes="HttpUtility.ParseQueryString semantics",
    ),

    # Go's net/http parses the query with url.ParseQuery: percent decode and
    # '+' to space, no further normalisation.
    "go-net-http": _backend(
        "go-net-http",
        decode=["url_decode_plus"],
        normalize=[],
        notes="net/url.ParseQuery semantics",
    ),

    # The next group are the same parser family as PHP/Node/Go: form decoding
    # with '+' as space and one percent decode. They are separate entries
    # because "which framework is on the other side" is a question the plan
    # must be able to ask, even when the rewrite rules are identical.
    "ruby-rack": _backend(
        "ruby-rack",
        decode=["url_decode_plus"],
        normalize=[],
        notes="Rack::Utils.parse_nested_query: plus-as-space, single decode",
    ),

    "rust-actix": _backend(
        "rust-actix",
        decode=["url_decode_plus"],
        normalize=[],
        notes="serde_urlencoded/form_urlencoded: plus-as-space, single decode",
    ),

    "elixir-plug": _backend(
        "elixir-plug",
        decode=["url_decode_plus"],
        normalize=[],
        notes="Plug.Conn.Query: plus-as-space, single decode",
    ),

    "perl-cgi": _backend(
        "perl-cgi",
        decode=["url_decode_plus"],
        normalize=[],
        notes="CGI.pm: plus-as-space, single decode",
    ),

    "coldfusion": _backend(
        "coldfusion",
        decode=["url_decode_plus"],
        normalize=[],
        notes="ColdFusion form scope: plus-as-space, single decode",
    ),

    "asp-classic": _backend(
        "asp-classic",
        decode=["url_decode_plus"],
        normalize=[],
        notes="classic ASP Request.Form: plus-as-space, single decode",
    ),

    "deno-bun": _backend(
        "deno-bun",
        decode=["url_decode_plus"],
        normalize=[],
        notes="WHATWG URLSearchParams: plus-as-space, single decode",
    ),

    "kotlin-ktor": _backend(
        "kotlin-ktor",
        decode=["url_decode_plus"],
        normalize=[],
        notes="Ktor form parsing: plus-as-space, single decode",
    ),

    "swift-vapor": _backend(
        "swift-vapor",
        decode=["url_decode_plus"],
        normalize=[],
        notes="Vapor URL-encoded form parsing: plus-as-space, single decode",
    ),

    # OpenResty's ngx.req.get_uri_args percent-decodes but is widely reported
    # to leave '+' literal. That is a useful contrast with the PHP family, so
    # the simpler form is modelled and the uncertainty is explicit.
    "lua-openresty": _backend(
        "lua-openresty",
        decode=["url_decode"],
        normalize=[],
        notes="ngx.req.get_uri_args: percent decode, plus kept literal "
              "(version/API dependent; verify before relying on it)",
    ),

    # A deliberately permissive stack: models the worst case where the backend
    # applies every lenient behaviour. Used to widen the search, never to claim
    # that a real target behaves this way.
    "permissive": _backend(
        "permissive",
        decode=["url_decode_twice", "percent_u", "unicode_escape",
                "html_entity", "strip_nul"],
        normalize=["nfkc"],
        notes="upper bound on leniency, for search only",
    ),

    # The identity stack: a component that does nothing. Useful as the control
    # side of a comparison.
    "identity": _backend(
        "identity",
        decode=[],
        normalize=[],
        notes="no rewriting at all",
    ),
}

# ══════════════════════════════════════════════════════════════════════════════
#  Registry
# ══════════════════════════════════════════════════════════════════════════════

ALL_STACKS: Dict[str, Stack] = {**WAF_STACKS, **BACKEND_STACKS}


def get(name: str) -> Stack:
    try:
        return ALL_STACKS[name]
    except KeyError:
        raise KeyError(
            f"unknown stack {name!r}; known: {', '.join(sorted(ALL_STACKS))}"
        ) from None


def names(kind: str = "all") -> List[str]:
    if kind == "waf":
        return sorted(WAF_STACKS)
    if kind == "backend":
        return sorted(BACKEND_STACKS)
    return sorted(ALL_STACKS)


def default_pairs() -> List[Tuple[Stack, Stack]]:
    """Every WAF against every backend, excluding the synthetic stacks.

    ``permissive`` and ``identity`` are search aids, not real targets, so they
    are left out of the default matrix. Requesting them explicitly still works.
    """
    skip = {"permissive", "identity"}
    pairs: List[Tuple[Stack, Stack]] = []
    for waf in WAF_STACKS.values():
        for backend in BACKEND_STACKS.values():
            if backend.name in skip:
                continue
            pairs.append((waf, backend))
    return pairs
