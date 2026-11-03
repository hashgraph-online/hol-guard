#!/usr/bin/env python3
"""Record ZCode hook-settings vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `ZCodeHarnessAdapter`'s
`_sync_managed_hook_groups`, `_prune_managed_hook_groups` and
`_recorded_enabled_for` (the base of the commit that introduced the native
`zcode_hook_settings` runner-authority kind), never from Rust output:

    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case records the request the native kind receives (the `hooks` mapping
as JSON text so its key order survives) and what the original Python did with
it: the pre-install `enabled` record, whether user handlers were present, and
the `hooks` mapping it left behind, again as order-preserving JSON text.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters import zcode
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode_config import GUARD_MANAGED_MARKER, ZCODE_PRETOOL_MATCHERS

if not hasattr(ZCodeHarnessAdapter, "_sync_managed_hook_groups"):
    sys.exit("refusing to record: the original Python ZCode hook settings are gone")

PATH = "/home/user/.zcode/cli/config.json"
OTHER = "/home/user/.zcode/cli/setting.json"
COMMAND = "guard-hook-bridge --harness zcode"
GUARD = f"{COMMAND} # {GUARD_MANAGED_MARKER}"
STALE = f"old-guard-hook --harness zcode # {GUARD_MANAGED_MARKER}"
LEGACY_GUARD = "python -m codex_plugin_scanner.cli ['guard', 'hook', '--harness', 'zcode']"


def user(command: str, matcher: object = None, **extra: object) -> dict[str, object]:
    entry: dict[str, object] = {}
    if matcher is not None:
        entry["matcher"] = matcher
    entry["hooks"] = [{"type": "command", "command": command}]
    entry.update(extra)
    return entry


def guard_group(matcher: object = None, command: str = STALE) -> dict[str, object]:
    return user(command, matcher)


def handlers() -> dict[str, dict[str, object]]:
    def handler(timeout: int) -> dict[str, object]:
        return {
            "type": "command",
            "command": GUARD,
            "timeout": timeout,
            "statusMessage": zcode._GUARD_HOOK_STATUS_MESSAGE,
        }

    return {
        "PreToolUse": handler(zcode._ZCODE_PRETOOL_TIMEOUT_SECONDS),
        "UserPromptSubmit": handler(zcode._ZCODE_PROMPT_TIMEOUT_SECONDS),
    }


HOOKS_CASES: list[tuple[str, dict[str, object]]] = [
    ("empty", {}),
    ("settings_only", {"enabled": True, "timeoutMs": 1000, "maxOutputBytes": 2048}),
    (
        "events_user_bash",
        {"events": {"PreToolUse": [user("echo bash", "Bash")], "Stop": [user("echo stop")]}, "enabled": True},
    ),
    (
        "legacy_and_events_duplicate",
        {
            "PreToolUse": [user("echo same", "Bash"), user("echo legacy-only", "Read")],
            "events": {"PreToolUse": [user("echo same", "Bash")]},
        },
    ),
    (
        "legacy_only_no_events_key",
        {
            "enabled": True,
            "Stop": [user("echo stop")],
            "timeoutMs": 1000,
            "SessionStart": [user("echo start"), user("echo start")],
        },
    ),
    (
        "stale_guard_entries",
        {
            "events": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": "echo mine"},
                            {"type": "command", "command": STALE, "timeout": 5},
                        ],
                    },
                    guard_group("Read"),
                    guard_group("Grep", LEGACY_GUARD),
                ],
                "UserPromptSubmit": [guard_group(), user("echo prompt")],
            }
        },
    ),
    (
        "top_level_managed_command",
        {
            "events": {
                "PreToolUse": [
                    {"matcher": "Bash", "command": STALE},
                    {"matcher": "Edit", "command": "echo user-top-level"},
                ]
            }
        },
    ),
    (
        "junk_entries",
        {
            "events": {
                "PreToolUse": [
                    5,
                    "string-entry",
                    None,
                    [1, 2],
                    {"matcher": " Bash ", "hooks": "not-a-list"},
                    {"matcher": 7, "hooks": [{"type": "command", "command": "echo seven"}]},
                    {"matcher": "Read", "note": "no hooks key"},
                    {"hooks": [5, "x", {"command": STALE}, {"command": 9}]},
                ],
                "UserPromptSubmit": [{"matcher": "   ", "hooks": [{"command": "echo blank-matcher"}]}],
            }
        },
    ),
    ("events_value_junk", {"events": {"PreToolUse": "junk", "Stop": {"not": "a list"}}}),
    ("events_not_a_dict", {"events": [user("echo list")], "PreToolUse": [user("echo legacy", "Bash")]}),
    (
        "legacy_non_list_and_unknown",
        {"PreToolUse": "not-a-list", "CustomEvent": [user("echo custom")], "Stop": [user("echo stop")]},
    ),
    (
        "events_internal_duplicates_migrated",
        {
            "events": {"Stop": [user("echo a"), user("echo a")], "PostToolUse": [user("echo p"), user("echo p")]},
            "Stop": [user("echo b"), user("echo a")],
        },
    ),
    (
        "unicode",
        {
            "events": {
                "PreToolUse": [
                    {"hooks": [{"command": "écho ✓ 日本"}], "matcher": "Bash", "ñote": "ü"},
                    {"matcher": "　Read　", "hooks": [{"command": "echo ideographic-space"}]},
                ]
            },
            "Stop": [{"hooks": [{"command": "echo 🛑"}], "ключ": "значение"}],
        },
    ),
    (
        "number_types_not_merged",
        {
            "events": {"Stop": [{"x": 1, "hooks": []}, {"x": 1.0, "hooks": []}, {"x": True, "hooks": []}]},
            "Stop": [{"hooks": [], "x": 1}, {"x": 2.5, "hooks": []}],
        },
    ),
    (
        "key_order_preserved",
        {
            "maxOutputBytes": 10,
            "events": {
                "Stop": [user("echo stop")],
                "PreToolUse": [{"hooks": [{"command": "echo w"}], "matcher": "Write", "z": 1, "a": 2}],
            },
            "enabled": False,
            "PostToolUse": [user("echo post")],
        },
    ),
    (
        "only_guard_everywhere",
        {
            "enabled": True,
            "events": {"PreToolUse": [guard_group("Bash")], "UserPromptSubmit": [guard_group()]},
            "PreToolUse": [guard_group("Read")],
        },
    ),
    ("empty_event_lists", {"events": {"PreToolUse": [], "Stop": []}, "custom": [], "SessionStart": []}),
    (
        "disabled_with_user_handlers",
        {"enabled": False, "events": {"Stop": [user("echo stop")]}},
    ),
]

STATES: list[tuple[str, dict[str, object]]] = [
    ("no_state", {}),
    ("history_present_true", {"hooks_enabled_before": {PATH: {"present": True, "value": True}}}),
    ("history_present_false", {"hooks_enabled_before": {PATH: {"present": True, "value": False}}}),
    (
        "history_absent_object_value",
        {"hooks_enabled_before": {PATH: {"present": False, "value": {"b": 1, "a": [2, "ü"]}}}},
    ),
    ("history_invalid_present", {"hooks_enabled_before": {PATH: {"present": 1, "value": True}}}),
    ("history_invalid_value", {"hooks_enabled_before": {PATH: {"present": True, "value": "yes"}}}),
    ("history_missing_value", {"hooks_enabled_before": {PATH: {"present": False}}}),
    ("history_other_path", {"hooks_enabled_before": {OTHER: {"present": True, "value": False}}}),
    ("history_not_dict", {"hooks_enabled_before": [1, 2]}),
    (
        "legacy_record_this_path",
        {"managed_config_path": PATH, "hooks_enabled_before": {"present": True, "value": False}},
    ),
    (
        "legacy_record_other_path",
        {"managed_config_path": OTHER, "hooks_enabled_before": {"present": False, "value": None}},
    ),
    ("legacy_path_not_str", {"managed_config_path": 5, "hooks_enabled_before": {"present": True, "value": True}}),
    (
        "history_wins_over_legacy",
        {
            "managed_config_path": PATH,
            "hooks_enabled_before": {PATH: {"present": False, "value": None}, "present": True, "value": True},
        },
    ),
]

INSTALL_STATES = ("no_state", "history_present_false", "legacy_record_this_path")

MANAGED_HOOKS: list[tuple[str, dict[str, object]]] = [
    ("managed_events", {"enabled": True, "events": {"PreToolUse": [guard_group("Bash")]}}),
    ("managed_legacy_only", {"PreToolUse": [guard_group("Bash")]}),
    ("managed_absent_enabled", {"events": {"UserPromptSubmit": [guard_group()]}}),
    ("top_level_command_not_counted", {"enabled": True, "events": {"PreToolUse": [{"command": STALE}]}}),
    ("unmanaged", {"enabled": False, "events": {"Stop": [user("echo stop")]}}),
]


def text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def record(op: str, name: str, hooks: dict[str, object], state: dict[str, object]) -> dict[str, object]:
    adapter = ZCodeHarnessAdapter()
    request: dict[str, object] = {
        "op": op,
        "hooks": text(hooks),
        "path": PATH,
        "history": state.get("hooks_enabled_before"),
        "managed_config_path": state.get("managed_config_path"),
    }
    if op == "install":
        request["matchers"] = list(ZCODE_PRETOOL_MATCHERS)
    working = copy.deepcopy(hooks)
    enabled = adapter._recorded_enabled_for(state, Path(PATH), working)
    expected: dict[str, object] = {"enabled": enabled}
    if op == "install":
        expected["has_handlers"] = adapter._hooks_have_handlers(working)
        adapter._sync_managed_hook_groups(working, GUARD)
    else:
        adapter._prune_managed_hook_groups(working)
    expected["after"] = text(working)
    return {"name": f"{op}:{name}", "request": request, "expected": expected}


def main() -> None:
    cases: list[dict[str, object]] = []
    for op in ("install", "uninstall"):
        for name, hooks in HOOKS_CASES:
            cases.append(record(op, name, hooks, {}))
        for hooks_name, hooks in MANAGED_HOOKS:
            for state_name, state in STATES:
                # The enabled record is op-independent; install's rewritten
                # hooks do not depend on the state, so it samples three.
                if op == "uninstall" or state_name in INSTALL_STATES:
                    cases.append(record(op, f"{hooks_name}+{state_name}", hooks, state))
    # A second install over the first one's output must change nothing.
    first = copy.deepcopy(HOOKS_CASES[5][1])
    ZCodeHarnessAdapter()._sync_managed_hook_groups(first, GUARD)
    cases.append(record("install", "reinstall_is_idempotent", first, {}))
    cases.append(record("uninstall", "uninstall_after_install", first, {}))
    payload = {
        "handlers": {event: text(handler) for event, handler in handlers().items()},
        "cases": cases,
    }
    with open(sys.argv[1], "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=1)
        stream.write("\n")


if __name__ == "__main__":
    main()
