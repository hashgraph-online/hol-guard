"""The installed-acceptance lane reads every hook envelope the way its harness does.

A replayed hook answers in one of several per-harness envelopes. These tests pin how the
lane turns each one into a verdict, that an envelope it cannot read is recorded by field
name only, that the replay cap outlasts every registered hook timeout, and that the aged
home's Codex seed is one Guard attributes to itself.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.installed_replay import verdict
from ci.gauntlet.installed_store import STALE_COMMAND, age_home


def _verdict_of(stdout: str, returncode: int = 0) -> dict[str, object]:
    return verdict(subprocess.CompletedProcess(args=["hook"], returncode=returncode, stdout=stdout, stderr=""))


def test_an_unreadable_envelope_records_its_field_names_but_no_values() -> None:
    result = _verdict_of('{"continue": true, "hookSpecificOutput": {"n": "/private/x"}}\n')
    assert result["decision"] == "unknown"
    assert result["envelope_shape"] == ["continue", "hookSpecificOutput", "hookSpecificOutput.n"]
    assert "/private/x" not in json.dumps(result)


@pytest.mark.parametrize(
    "stdout",
    [
        # Codex's answer to an ordinary tool call and to an ordinary prompt.
        '{"continue": true, "hookSpecificOutput": {"hookEventName": "PreToolUse"}}',
        '{"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}',
        # zcode's answer to an ordinary prompt, with Guard's non-blocking action beside it.
        '{"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}, "policy_action": "warn", "reason_code": "c"}',
    ],
)
def test_an_envelope_naming_only_its_event_is_the_harness_allow(stdout: str) -> None:
    result = _verdict_of(stdout + "\n")
    assert result["decision"] == "allow"
    assert "envelope_shape" not in result


@pytest.mark.parametrize(
    ("stdout", "decision"),
    [
        ('{"continue": false, "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}', "deny"),
        ('{"decision": "block", "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}', "block"),
        ('{"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}, "policy_action": "block"}', "block"),
        (
            '{"hookSpecificOutput": {"hookEventName": "PreToolUse"}, "policy_action": "require-reapproval"}',
            "require-reapproval",
        ),
    ],
)
def test_an_event_only_envelope_with_any_blocking_signal_is_not_an_allow(stdout: str, decision: str) -> None:
    assert _verdict_of(stdout + "\n")["decision"] == decision


def test_a_warn_envelope_records_its_field_names() -> None:
    result = _verdict_of('{"policy_action": "warn", "reason_code": "c"}\n')
    assert result["decision"] == "warn"
    assert result["envelope_shape"] == ["policy_action", "reason_code"]


def test_a_readable_envelope_carries_no_shape() -> None:
    completed = subprocess.CompletedProcess(
        args=["hook"],
        returncode=0,
        stdout='{"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": "r"}}\n',
        stderr="",
    )
    assert "envelope_shape" not in verdict(completed)


def test_the_replay_cap_outlasts_every_registered_hook_timeout() -> None:
    from ci.gauntlet import installed_replay

    # Codex registers PreToolUse at 125 s and holds a reviewed call for approval until
    # then; the lane must hear that hook's own deny rather than score it as a hang.
    assert installed_replay._REPLAY_TIMEOUT > 125


def test_the_aged_codex_handler_is_one_guard_attributes_to_itself(tmp_path: Path) -> None:
    """The seed must be a handler an older Guard wrote, not an unattributable third party's.

    Guard leaves a Codex handler it cannot attribute to itself in place, so a seed the
    product rightly keeps would fail the lane for honouring that boundary.
    """

    from tests.codex_hook_publication_helpers import remove_unlaunchable_guard_hook_events

    age_home(tmp_path)
    hooks = json.loads((tmp_path / ".codex" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    remaining, changed = remove_unlaunchable_guard_hook_events(
        hooks, legacy_status_messages={"HOL Guard checking Bash command"}, windows=False
    )
    assert changed is True
    assert STALE_COMMAND not in json.dumps(remaining)


@pytest.mark.parametrize("returncode", [1, 2])
def test_an_event_only_envelope_from_a_failing_hook_is_not_an_allow(returncode: int) -> None:
    stdout = '{"continue": true, "hookSpecificOutput": {"hookEventName": "PreToolUse"}}\n'
    result = _verdict_of(stdout, returncode=returncode)
    assert result["decision"] == "unknown"
    assert result["envelope_shape"] == ["continue", "hookSpecificOutput", "hookSpecificOutput.hookEventName"]
