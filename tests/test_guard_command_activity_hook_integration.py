"""Hook-boundary integration and non-interference tests for command activity."""

# pyright: reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
)
from codex_plugin_scanner.guard.store import GuardStore


def _command_payload(*, request_id: str | None = "toolcall_abcdef1234567890") -> dict[str, object]:
    payload: dict[str, object] = {
        "tool_name": "Shell",
        "tool_input": {"command": "git push origin release/2.2 --force"},
    }
    if request_id is not None:
        payload["tool_call_id"] = request_id
    return payload


def _store(guard_home: Path) -> GuardStore:
    return GuardStore(guard_home, prime_policy_integrity=False)


def test_unsupported_post_is_explicitly_unpaired(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = _store(guard_home)

    assert record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="kimi",
        event="PostToolUse",
        payload=_command_payload(request_id=None),
        succeeded=True,
    )
    with sqlite3.connect(store.path) as connection:
        row = cast(
            tuple[str, str, int] | None,
            connection.execute("select execution_status, proof_level, match_count from command_activity").fetchone(),
        )
    assert row is not None
    assert tuple(row) == ("unpaired_post", "unpaired_post", 0)


@pytest.mark.parametrize(
    ("event", "payload", "expected"),
    (
        ("PostToolUse", {}, True),
        ("PostToolUseFailure", {}, False),
        ("PostToolUse", {"is_error": True}, False),
        ("postToolUse", {"success": False}, False),
        ("afterShellExecution", {"exitCode": 7}, False),
    ),
)
def test_post_success_interpretation_is_closed(
    event: str,
    payload: dict[str, object],
    expected: bool,
) -> None:
    assert hook_post_succeeded(event, payload) is expected
