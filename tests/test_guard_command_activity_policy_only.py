"""Policy-only activity remains correlated when native rule evidence is unavailable."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_support_command_activity as activity_support
from codex_plugin_scanner.guard.native_command_control_authority_io import NativeCommandControlMutationRequiredError
from codex_plugin_scanner.guard.store import GuardStore


def test_native_authority_error_does_not_claim_policy_only_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutation_required(*_args: object, **_kwargs: object) -> None:
        raise NativeCommandControlMutationRequiredError()

    monkeypatch.setattr(activity_support, "_evaluate_payload_command", mutation_required)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    assert not activity_support.record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload={"tool_name": "Shell", "tool_input": {"command": "git diff --stat"}},
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )
    assert store.count_command_activities() == 0
    assert store.get_command_activity_persistence_health().last_error_code == "pre_native_control_unavailable"
