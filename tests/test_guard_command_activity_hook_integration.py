"""How a post-tool hook payload reports a failed tool call."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cli.commands_support_command_activity import hook_post_succeeded


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
