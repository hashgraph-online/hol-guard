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


@pytest.mark.parametrize("cause", ["codex_hook_launch_unauthenticated", "codex_hook_manifest_missing"])
def test_signed_bridge_failure_receipt_cannot_score_as_attack_protection(tmp_path, monkeypatch, cause):
    """An authenticated-bridge refusal on stderr is not a command-policy verdict."""
    import subprocess

    stdout = json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Request denied.",
            }
        }
    )
    stderr = json.dumps(
        {"schema": "hol-guard.codex-bridge-failure.v1", "causes": [{"reason_code": cause}]}
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout, stderr)
    )
    result = replay_case(
        ["registered-codex-hook"],
        {"id": "synthetic-key-copy", "expect": "not-allow", "payload": {}},
        home=tmp_path,
        guard_home=tmp_path / ".hol-guard",
        workspace=tmp_path,
        repeat=2,
    )
    assert all(run["decision"] == "deny" for run in result["runs"])
    assert all(run["bridge_failure_reason_code"] == cause for run in result["runs"])
    assert any("hook infrastructure failed" in failure and cause in failure for failure in result["failures"])


def test_unrelated_stderr_json_cannot_override_a_policy_denial(tmp_path, monkeypatch):
    """Only the native bridge's versioned diagnostic schema is authoritative."""
    import subprocess

    response = {
        "reason_code": "native_secret_read_denied",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Protected credential path denied by policy.",
        },
    }
    stderr = json.dumps(
        {"schema": "not-a-native-bridge-failure", "causes": [{"reason_code": "codex_hook_launch_unauthenticated"}]}
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps(response), stderr)
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
    assert all("bridge_failure_reason_code" not in run for run in result["runs"])


@pytest.mark.parametrize("expect", ["allow", "not-allow"])
def test_prompt_authority_outage_is_not_a_policy_decision(tmp_path, monkeypatch, expect):
    """A fail-closed prompt outage must be diagnosed even when a denial is expected."""
    import subprocess

    response = {
        "decision": "block",
        "policy_action": "block",
        "reason_code": "native_prompt_unavailable",
        "reason": "HOL Guard could not check this prompt, so it was blocked.",
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
    }
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps(response), "")
    )
    result = replay_case(
        ["registered-claude-hook"],
        {
            "id": "benign-prompt-submit-names-a-file" if expect == "allow" else "synthetic-denial-expectation",
            "expect": expect,
            "payload": {
                "hook_event_name": "UserPromptSubmit",
                "prompt": "Read README.md and summarise what this project does.",
                "cwd": "{workspace}",
            },
        },
        home=tmp_path,
        guard_home=tmp_path / ".hol-guard",
        workspace=tmp_path,
        repeat=5,
    )
    assert all(run["decision"] == "block" for run in result["runs"])
    assert any(
        "hook infrastructure failed" in failure and "native_prompt_unavailable" in failure
        for failure in result["failures"]
    )
