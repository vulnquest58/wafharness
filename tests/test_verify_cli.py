"""CLI coverage for identify and verify without a network."""

from __future__ import annotations

import contextlib
import io

from wafharness import cli, fingerprint
from wafharness.models import Profile


def test_identify_presents_a_professional_label(monkeypatch):
    profile = Profile(target="https://target.example", vendor="cloudflare")
    profile.add("best_fit:cloudflare", 0.85)
    profile.add("url_decode", 0.80)
    profile.add("html_entity", 0.80)
    profile.add("nfkc", 0.80)
    profile.add("lowercase", 0.80)

    monkeypatch.setattr(cli, "_http_transport", lambda *args, **kwargs: None)
    monkeypatch.setattr(fingerprint, "probe",
                        lambda transport, target="": profile)

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = cli.main(["identify", "--url", "https://target.example"])

    output = buffer.getvalue()
    assert code == 0
    assert "WAF-like" in output
    assert "cloudflare" in output
    assert "url_decode" in output


def test_identify_json_is_valid(monkeypatch):
    import json

    profile = Profile(target="https://target.example", vendor="cloudflare")
    profile.add("best_fit:cloudflare", 0.85)
    profile.add("url_decode", 0.80)
    profile.add("html_entity", 0.80)
    profile.add("nfkc", 0.80)
    profile.add("lowercase", 0.80)

    monkeypatch.setattr(cli, "_http_transport", lambda *args, **kwargs: None)
    monkeypatch.setattr(fingerprint, "probe",
                        lambda transport, target="": profile)

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main(["identify", "--url", "https://target.example", "--json"])

    payload = json.loads(buffer.getvalue())
    assert payload["kind"] == "WAF-like"
    assert payload["profile"]["target"] == "https://target.example"


def test_verify_refuses_without_confirmation(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("verify opened a socket without --yes")

    monkeypatch.setattr(cli, "_http_transport", explode)
    assert cli.main([
        "verify", "--url", "https://own.example", "--param", "q",
    ]) == 2


def test_verify_rejects_an_absurd_entry_count(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("verify opened a socket before validating")

    monkeypatch.setattr(cli, "_http_transport", explode)
    assert cli.main([
        "verify", "--url", "https://own.example", "--yes",
        "--max-entries", "100",
    ]) == 2
