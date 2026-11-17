"""Frozen Codex transport-authentication errors must not count as policy protection."""

from __future__ import annotations

import json

import pytest

from ci.gauntlet.installed_replay import replay_case


@pytest.mark.parametrize(
    "reason",
    [
        "HOL Guard could not authenticate the local daemon. Run `hol-guard daemon repair` from a terminal, then retry.",
        "HOL Guard could not authenticate the local daemon (daemon_unavailable). Run `hol-guard daemon repair`.",
    ],
)
def test_codex_transport_authentication_denial_is_not_attack_protection(tmp_path, monkeypatch, reason):
    """A frozen Codex hook that cannot authenticate never evaluated the secret-read policy."""
    import subprocess

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 2, json.dumps(response), "")
    )
    result = replay_case(
        ["registered-codex-hook"],
        {"id": "synthetic-key-copy", "expect": "not-allow", "payload": {}},
        home=tmp_path,
        guard_home=tmp_path / ".hol-guard",
        workspace=tmp_path,
        repeat=2,
    )
    assert any("infrastructure failed" in failure for failure in result["failures"])
    assert all(run["decision"] == "deny" for run in result["runs"])


def test_an_explicit_secret_read_policy_denial_still_counts_as_protection(tmp_path, monkeypatch):
    import subprocess

    response = {
        "reason_code": "native_secret_read_denied",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Protected credential path denied by policy.",
        },
    }
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 2, json.dumps(response), "")
    )
    result = replay_case(
        ["registered-codex-hook"],
        {"id": "synthetic-key-copy", "expect": "not-allow", "payload": {}},
        home=tmp_path,
        guard_home=tmp_path / ".hol-guard",
        workspace=tmp_path,
        repeat=2,
    )
    assert result["failures"] == []

