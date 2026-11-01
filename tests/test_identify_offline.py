"""Tests for the offline path of ``identify``.

``identify`` and its siblings (``profile``, ``plan``) must all be exercisable
without a network, otherwise the only way to review a label is to aim the tool at
a live host — which is exactly what a careful operator will not do while
developing.
"""

from __future__ import annotations

import contextlib
import io

import pytest

from wafharness import cli


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def test_identify_simulate_runs_offline():
    code, out, _ = run(["identify", "--simulate", "cloudflare"])
    assert code == 0
    assert "cloudflare" in out
    assert "WAF-like" in out


def test_identify_simulate_output_is_ascii_safe():
    """A Windows console cannot encode every glyph a label might carry."""
    _, out, _ = run(["identify", "--simulate", "modsecurity-crs"])
    out.encode("cp1252")


def test_identify_simulate_json_is_valid():
    import json

    code, out, _ = run(["identify", "--simulate", "f5-asm", "--json"])
    assert code == 0
    payload = json.loads(out)
    assert payload["target"].startswith("simulated:")
    assert "profile" in payload


def test_identify_requires_a_target():
    code, out, err = run(["identify"])
    assert code == 2
    assert "simulate" in err
    assert out.strip() == ""


def test_identify_unknown_stack_names_alternatives():
    code, _, err = run(["identify", "--simulate", "no-such-stack"])
    assert code == 2
    assert "cloudflare" in err


def test_identify_simulate_never_opens_a_socket(monkeypatch):
    """The offline path must stay offline even if urlopen is reachable."""
    import urllib.request

    def explode(*_args, **_kwargs):
        raise AssertionError("identify --simulate must not send")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    code, _, _ = run(["identify", "--simulate", "akamai"])
    assert code in (0, 1)
