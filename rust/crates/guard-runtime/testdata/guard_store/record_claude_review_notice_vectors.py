#!/usr/bin/env python3
"""Record Claude Code review-notice vectors from the Python implementation.

When `pause_native_pre_tool_for_approval` pauses a Claude Code review for the
approval inbox, the daemon worker (`hook_worker_native.py`) also calls
`record_claude_permission_notice_for_native_review`, which builds the notice
in `_record_claude_permission_notice` and hands it to the resident's
`hook_authority_state` op (`claude_record_notice`). The resident signs and
stores whatever it is sent, so these vectors pin what Python sends: the op,
its clock, the session, the tool name and the notice payload.

The review binding comes from the resident's exact-action op and is supplied
per scenario. The clock and the random approval code are pinned. Run from a
checkout; no native runtime is needed:

    cd <checkout>
    PYTHONPATH=$PWD/src python3 <this-file> <output claude_review_notice_vectors.json>
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

from codex_plugin_scanner.guard.cli import commands_support_hook_state
from codex_plugin_scanner.guard.daemon import hook_native_review_approval

PINNED_CLOCK = "2026-03-01T13:00:00.654321+00:00"
PINNED_CODE = "0a1b2c3d4e5f"
GUARD_HOME = "/home/user/.hol-guard"
WORKSPACE = "/work/space"
BASH = {"tool_name": "Bash", "tool_input": {"command": "rm -rf build"}}

SCENARIOS: list[dict[str, object]] = [
    {"name": "bash_command", "payload": {"session_id": "sess-1", **BASH}, "binding": "rb-1"},
    {
        "name": "stripped_session_and_tool",
        "payload": {"session_id": "  sess-2 \n", "tool_name": " Bash ", "tool_input": {"command": "  ls -la  "}},
        "binding": "rb-2",
    },
    {"name": "no_session", "payload": dict(BASH), "binding": "rb-1"},
    {"name": "blank_session", "payload": {"session_id": " \t ", **BASH}, "binding": "rb-1"},
    {"name": "numeric_session", "payload": {"session_id": 7, **BASH}, "binding": "rb-1"},
    {
        "name": "no_command",
        "payload": {"session_id": "sess-3", "tool_name": "Write", "tool_input": {"file_path": "/work/space/a.txt"}},
        "binding": "rb-3",
    },
    {"name": "no_binding", "payload": {"session_id": "sess-4", **BASH}, "binding": None},
    {"name": "empty_binding", "payload": {"session_id": "sess-4", **BASH}, "binding": ""},
    {
        "name": "default_reason",
        "payload": {"session_id": "sess-5", **BASH},
        "binding": "rb-5",
        "reason": None,
    },
    {
        "name": "empty_reason",
        "payload": {"session_id": "sess-5", **BASH},
        "binding": "rb-5",
        "reason": "",
    },
    {
        "name": "camel_tool_name",
        "payload": {"session_id": "sess-6", "toolName": "Bash", "tool_input": {"command": "make"}},
        "binding": "rb-6",
    },
    {
        "name": "blank_tool_name_falls_back",
        "payload": {"session_id": "sess-7", "tool_name": "  ", "tool": "Shell", "arguments": {"cmd": "make test"}},
        "binding": "rb-7",
    },
    {
        "name": "command_from_payload",
        "payload": {"session_id": "sess-8", "tool_name": "Bash", "shellCommand": "git push"},
        "binding": "rb-8",
    },
    {
        "name": "unicode_text",
        "payload": {
            "session_id": "sess-9",
            "tool_name": "Bash",
            "tool_input": {"command": "echo café — 日本 \U0001f512"},
        },
        "binding": "rb-9",
        "reason": "Review café — 日本 \U0001f512.",
    },
    {
        "name": "no_tool_name",
        "payload": {"session_id": "sess-10", "tool_input": {"command": "make"}},
        "binding": "rb-10",
    },
]


def run(scenario: dict[str, object]) -> dict[str, object]:
    calls: list[dict[str, object]] = []

    def hook_authority_state(store: object, op: str, *, now: str, create_key: bool = False, **fields: object) -> None:
        calls.append({"op": op, "now": now, "create_key": create_key, **fields})

    binding = scenario["binding"]
    commands_support_hook_state.hook_authority_state = hook_authority_state  # type: ignore[assignment]
    hook_native_review_approval.native_review_binding = lambda *args, **kwargs: binding  # type: ignore[assignment]
    native_result: dict[str, object] = {"decision": "review", "minimum_action": "require-reapproval"}
    reason = scenario.get("reason", "Deletes files.")
    if reason is not None:
        native_result["reason"] = reason
    hook_native_review_approval.record_claude_permission_notice_for_native_review(
        object(),  # type: ignore[arg-type]
        harness="claude-code",
        payload=scenario["payload"],  # type: ignore[arg-type]
        native_result=native_result,
        native_receipt=None,
        workspace=Path(WORKSPACE),
        guard_home=Path(GUARD_HOME),
    )
    return {
        "name": scenario["name"],
        "harness": "claude-code",
        "payload": scenario["payload"],
        "result": native_result,
        "binding": binding,
        "workspace": WORKSPACE,
        "calls": calls,
    }


def main(output: Path) -> None:
    originals = (
        commands_support_hook_state.hook_authority_state,
        commands_support_hook_state._now,
        hook_native_review_approval.native_review_binding,
        secrets.token_hex,
    )
    commands_support_hook_state._now = lambda: PINNED_CLOCK  # type: ignore[assignment]
    secrets.token_hex = lambda nbytes=None: PINNED_CODE  # type: ignore[assignment]
    try:
        scenarios = [run(scenario) for scenario in SCENARIOS]
    finally:
        (
            commands_support_hook_state.hook_authority_state,
            commands_support_hook_state._now,
            hook_native_review_approval.native_review_binding,
            secrets.token_hex,
        ) = originals
    document = {
        "schema": "guard-claude-review-notice-vectors.v1",
        "now": PINNED_CLOCK,
        "approval_code": PINNED_CODE,
        "guard_home": GUARD_HOME,
        "scenarios": scenarios,
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
