"""Cursor post-observer trust tests for command activity."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.cursor_native_approval import (
    compute_cursor_after_observer_proof,
    ensure_cursor_hook_attestation_secret,
)
from codex_plugin_scanner.guard.runtime.command_activity_cursor import (
    cursor_command_activity_observer_trusted,
)


@pytest.mark.parametrize("event", ("afterShellExecution", "afterMCPExecution"))
def test_managed_cursor_observer_is_trusted_without_pending_approval(tmp_path: Path, event: str) -> None:
    guard_home = tmp_path / "guard-home"
    conversation_id = "conversation_abcdef1234567890"
    generation_id = "generation_abcdef1234567890"
    command = "git status"
    secret = ensure_cursor_hook_attestation_secret(guard_home)
    proof = compute_cursor_after_observer_proof(
        secret=secret,
        conversation_id=conversation_id,
        command=command,
        approval_binding=generation_id,
        observer_event=event,
    )
    payload: dict[str, object] = {
        "hook_event_name": event,
        "generation_id": generation_id,
        "conversation_id": conversation_id,
        "command": command,
    }
    env = {
        "HOL_GUARD_MANAGED_CURSOR_HOOK": "1",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF": proof,
        "HOL_GUARD_CURSOR_APPROVAL_BINDING": generation_id,
        "CURSOR_VERSION": "test",
    }

    assert cursor_command_activity_observer_trusted(
        guard_home=guard_home,
        payload=payload,
        conversation_id=conversation_id,
        command=command,
        env=env,
    )


def test_cursor_observer_rejects_forged_or_unmanaged_proof(tmp_path: Path) -> None:
    payload: dict[str, object] = {
        "hook_event_name": "afterShellExecution",
        "generation_id": "generation_abcdef1234567890",
    }
    base_env = {
        "HOL_GUARD_MANAGED_CURSOR_HOOK": "1",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF": "0" * 64,
        "HOL_GUARD_CURSOR_APPROVAL_BINDING": "generation_abcdef1234567890",
        "CURSOR_VERSION": "test",
    }
    assert not cursor_command_activity_observer_trusted(
        guard_home=tmp_path / "guard-home",
        payload=payload,
        conversation_id="conversation_abcdef1234567890",
        command="git status",
        env=base_env,
    )
    assert not cursor_command_activity_observer_trusted(
        guard_home=tmp_path / "guard-home",
        payload=payload,
        conversation_id="conversation_abcdef1234567890",
        command="git status",
        env={key: value for key, value in base_env.items() if key != "HOL_GUARD_MANAGED_CURSOR_HOOK"},
    )
