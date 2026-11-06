from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_context_assistance as native
from codex_plugin_scanner.guard.cli import context_assistance_versions_commands as cli
from codex_plugin_scanner.guard.daemon import context_assistance_versions_http as http


@pytest.mark.parametrize(
    "arguments,changed",
    [
        (["pin", "exact-final-build"], {"pinned_build": "exact-final-build"}),
        (["unpin"], {"pinned_build": None}),
        (["update-policy", "--mode", "notify", "--channel", "preview"], {"mode": "notify", "allow_preview": True}),
    ],
)
def test_cli_preference_changes_preserve_other_fields_and_the_user_revision(monkeypatch, tmp_path, arguments, changed):
    parser = argparse.ArgumentParser()
    cli.configure(parser.add_subparsers())
    args = parser.parse_args([*arguments, "--revision", "sha256:" + "a" * 64])
    original = {"mode": "manual", "allow_preview": False, "retain_last_good": True, "pinned_build": "previous-build"}
    calls = []
    result = {"result": {"requested": original, "revision": "sha256:" + "b" * 64}}

    def send(**kw):
        calls.append(kw)
        return result

    monkeypatch.setattr(native, "versions", send)
    assert cli.execute(args, tmp_path) == result
    assert calls == [
        {"guard_home": tmp_path, "payload": {"action": "preferences"}},
        {
            "guard_home": tmp_path,
            "payload": {
                "action": "set_preferences",
                "expected_revision": args.revision,
                "preferences": {**original, **changed},
            },
        },
    ]
    assert original["mode"] == "manual"
    assert original["pinned_build"] == "previous-build"


@pytest.mark.parametrize("arguments", [["pin", "exact-build"], ["unpin"], ["update-policy", "--mode", "prepare"]])
def test_cli_requires_revision_and_does_not_offer_unimplemented_automatic_preparation(arguments):
    parser = argparse.ArgumentParser()
    cli.configure(parser.add_subparsers())
    with pytest.raises(SystemExit):
        parser.parse_args(arguments)


def handler(home):
    responses = []
    return SimpleNamespace(
        server=SimpleNamespace(store=SimpleNamespace(guard_home=home)),
        _header_token_is_valid=lambda **kw: True,
        _write_json=lambda body, **kw: responses.append((body, kw)),
        _write_approval_gate_error=lambda e: responses.append(e.code),
    ), responses


def test_preference_reads_need_operator_auth_but_no_expansion_proof(monkeypatch, tmp_path):
    h, answers = handler(tmp_path)

    def forbidden(*a, **kw):
        raise AssertionError("Passive preferences reached the settings-write gate")

    monkeypatch.setattr(http, "require_high_risk", forbidden)
    monkeypatch.setattr(http, "versions", lambda **kw: {"result": {"revision": "sha256:unit"}})
    http.respond(h, "versions", {"input": {"action": "preferences"}})
    assert answers == [({"result": {"revision": "sha256:unit"}}, {"extra_headers": {"Cache-Control": "no-store"}})]
    h._header_token_is_valid = lambda **kw: False
    http.respond(h, "versions", {"input": {"action": "preferences"}})
    assert answers[-1] == ({"error": "unauthorized"}, {"status": 401})


def test_preference_writes_keep_the_existing_approval_gate_and_conflict_status(monkeypatch, tmp_path):
    h, answers = handler(tmp_path)
    calls = []
    grant = object()
    monkeypatch.setattr(http, "require_high_risk", lambda *a, **kw: calls.append("gate") or grant)
    monkeypatch.setattr(http, "require_settings_write", lambda *a, **kw: calls.append(("write", kw)))

    def stale(**kw):
        calls.append(("native", kw))
        raise native.ContextAssistanceError("native_context_assistance_update_preferences_conflict")

    monkeypatch.setattr(http, "versions", stale)
    body = {"action": "set_preferences", "expected_revision": "sha256:unit", "preferences": {"mode": "manual"}}
    http.respond(h, "versions", {"input": body, "approval_password": "unit-proof"})
    assert calls == [
        "gate",
        ("write", {"approval_gate_grant": grant}),
        ("native", {"guard_home": tmp_path, "payload": body}),
    ]
    assert answers[0][1]["status"] == 409
    assert "unit-proof" not in repr(calls)
