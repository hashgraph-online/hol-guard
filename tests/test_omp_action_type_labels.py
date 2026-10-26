"""Oh My Pi tool names map to their own action labels, not the generic fallback."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload


def _envelope(harness: str, tool_name: str, tool_input: dict[str, object]):
    payload = {"hook_event_name": "PreToolUse", "tool_name": tool_name, "tool_input": tool_input}
    return normalize_harness_payload(harness, "PreToolUse", payload, workspace=".", home_dir="/home/user")


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "expected"),
    [
        ("task", {"prompt": "summarize the open review threads"}, "prompt"),
        ("eval", {"code": "display(1)", "language": "js"}, "shell_command"),
        ("todo_write", {"todos": []}, "harness_start"),
        ("ls", {"path": "."}, "file_read"),
        ("find", {"path": "."}, "file_read"),
    ],
)
def test_omp_tool_action_types(tool_name: str, tool_input: dict[str, object], expected: str) -> None:
    assert _envelope("omp", tool_name, tool_input).action_type == expected


def test_omp_labels_do_not_apply_to_other_harnesses() -> None:
    assert _envelope("pi", "task", {"prompt": "x"}).action_type == "config_change"
