"""Coverage tests for the stack matrix.

The matrix is data, so the failure modes are different from the parser tests:
missing notes, duplicate names, and synthetic stacks leaking into the default
search. The exact vendor list is expected to grow, so these tests assert
coverage and invariants rather than a frozen count.
"""

from __future__ import annotations

from wafharness import stacks


def test_the_matrix_covers_more_than_one_backend_family():
    assert len(stacks.names("backend")) >= 18
    assert len(stacks.names("waf")) >= 16


def test_every_stack_resolves_and_explains_itself():
    for name in stacks.names():
        stack = stacks.get(name)
        assert stack.name == name
        assert stack.notes, f"{name} has no provenance note"


def test_new_backends_are_reachable_by_name():
    for name in ("ruby-rack", "rust-actix", "elixir-plug", "perl-cgi",
                 "coldfusion", "asp-classic", "deno-bun", "kotlin-ktor",
                 "swift-vapor", "lua-openresty"):
        assert stacks.get(name).name == name


def test_new_wafs_are_reachable_by_name():
    for name in ("coraza", "google-cloud-armor", "sucuri", "fortiweb",
                 "wallarm", "radware", "citrix-netscaler", "barracuda"):
        assert stacks.get(name).name == name


def test_openresty_and_php_disagree_about_plus():
    php, _ = stacks.get("php").run(b"nexus+token")
    lua, _ = stacks.get("lua-openresty").run(b"nexus+token")
    assert php == b"nexus token"
    assert lua == b"nexus+token"


def test_default_matrix_excludes_synthetic_stacks():
    pairs = stacks.default_pairs()
    names = {backend.name for _, backend in pairs}
    assert "permissive" not in names
    assert "identity" not in names
    assert len(pairs) == len(stacks.WAF_STACKS) * (
        len(stacks.BACKEND_STACKS) - 2)
