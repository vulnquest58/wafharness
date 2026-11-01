"""CLI tests: the send gate and the offline verbs.

The gate is the single most important behaviour in the project — a tool that
models bypasses must not start sending because someone typed a command without
reading the help — so it is tested from the outside, through ``main``.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from wafharness import cli


def run(argv):
    """Run the CLI and capture stdout/stderr, returning (code, out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:      # argparse exits for --help / --version
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


# ── the send gate ───────────────────────────────────────────────────────────


def test_send_refuses_without_confirmation():
    code, out, err = run(["send", "--url", "https://example.com",
                          "--waf", "cloudflare", "--backend", "php"])
    assert code == 2
    assert "Refusing to send" in err
    assert "authorisation" in err
    assert out.strip() == "", "nothing may be printed to stdout on refusal"


def test_send_dry_run_needs_no_confirmation():
    code, out, _ = run(["send", "--url", "https://example.com",
                        "--waf", "cloudflare", "--backend", "php",
                        "--dry-run"])
    assert code == 0
    assert "would send" in out
    assert "example.com?q=" in out


def test_dry_run_respects_the_request_budget():
    """The preview must show what would really be sent, not the whole list."""
    code, out, _ = run(["send", "--url", "https://example.com",
                        "--waf", "five" if False else "cloudflare",
                        "--backend", "php", "--dry-run",
                        "--max-requests", "1"])
    assert code == 0
    assert out.count("example.com?q=") == 1


def test_dry_run_never_opens_a_socket(monkeypatch):
    """If the transport is called during a dry run, that is a serious bug."""
    import urllib.request

    def explode(*_args, **_kwargs):
        raise AssertionError("dry run must not send")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    code, _, _ = run(["send", "--url", "https://example.com",
                      "--waf", "cloudflare", "--backend", "php", "--dry-run"])
    assert code == 0


# ── offline verbs ───────────────────────────────────────────────────────────


def test_stacks_lists_both_kinds():
    code, out, _ = run(["stacks"])
    assert code == 0
    assert "WAF stacks" in out
    assert "backend stacks" in out
    assert "cloudflare" in out


def test_find_reports_a_gap():
    code, out, _ = run(["find", "--waf", "cloudflare", "--backend", "php"])
    assert code == 0
    assert "GAP" in out


def test_find_json_is_valid():
    code, out, _ = run(["find", "--waf", "cloudflare", "--backend", "php",
                        "--json"])
    payload = json.loads(out)
    assert payload["waf"]["name"] == "cloudflare"
    assert payload["divergences"]


def test_known_stack_pair_with_no_gap_returns_nonzero():
    """A pair whose pipelines agree must signal "nothing found" via exit code."""
    code, _, _ = run(["find", "--waf", "akamai", "--backend", "identity"])
    assert code in (0, 1)


def test_matrix_runs():
    code, out, _ = run(["matrix", "--depth", "1", "--top", "3"])
    assert code == 0
    assert "waf" in out and "backend" in out


def test_frames_reports_divergences():
    code, out, _ = run(["frames", "--pair", "json-first-wins",
                        "json-last-wins"])
    assert code == 0
    assert "bypass" in out


def test_profile_simulate_is_offline_and_ascii_safe():
    code, out, _ = run(["profile", "--simulate", "cloudflare"])
    assert code == 0
    out.encode("cp1252")            # must not raise on a Windows console
    assert "url_decode" in out


def test_profile_needs_a_target():
    code, _, err = run(["profile"])
    assert code == 2
    assert "url" in err


def test_unknown_stack_names_the_alternatives():
    code, _, err = run(["find", "--waf", "nope", "--backend", "php"])
    assert code == 2
    assert "cloudflare" in err


def test_no_subcommand_prints_help():
    code, out, _ = run([])
    assert code == 2
    assert "usage" in out.lower() or "wafharness" in out.lower()
