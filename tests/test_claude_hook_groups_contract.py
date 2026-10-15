"""The shared Claude hook-group contract must reproduce the legacy settings bytes."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters import claude_hook_argv
from codex_plugin_scanner.guard.adapters import claude_hook_config as config
from codex_plugin_scanner.guard.adapters.base import HarnessContext

_LEGACY_TOOL_MATCHER = "Bash|Read|Grep|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*"
_LEGACY_POST_TOOL_MATCHER = f"{_LEGACY_TOOL_MATCHER}|AskUserQuestion"
_LEGACY_GROUPS = (
    ("PreToolUse", _LEGACY_TOOL_MATCHER, 30, "HOL Guard is checking this tool use"),
    ("PermissionRequest", _LEGACY_TOOL_MATCHER, 10, "HOL Guard is reviewing this approval prompt"),
    ("PostToolUse", _LEGACY_POST_TOOL_MATCHER, 30, None),
    ("Notification", "permission_prompt", 10, None),
    ("Stop", None, 10, None),
)
_ARGV = ("/opt/guard/native", "claude-hook-bridge", "HOL_GUARD_CLAUDE_DAEMON_HOOK", '{"query":"guard-home=x"}')
_STALE_GUARD = {
    "type": "command",
    "command": "/old/python",
    "args": ["-c", "HOL_GUARD_CLAUDE_DAEMON_HOOK", "{}"],
    "timeout": 5,
}
_USER_HOOK = {"type": "command", "command": "/usr/bin/true", "args": [], "timeout": 3}


def _legacy_sync(hooks: dict[str, object], argv: tuple[str, ...]) -> None:
    for key, matcher, timeout, status_message in _LEGACY_GROUPS:
        existing = hooks.get(key)
        hooks[key] = config.merge_hook_group(
            config.prune_guard_hook_entries(existing if isinstance(existing, list) else []),
            matcher,
            config.guard_command_handler(argv, timeout=timeout, status_message=status_message),
        )
    for key in ("PermissionDenied", "UserPromptSubmit"):
        entries = hooks.get(key)
        if not isinstance(entries, list):
            continue
        remaining = config.prune_guard_hook_entries(entries)
        if remaining:
            hooks[key] = remaining
        else:
            hooks.pop(key, None)


def _contract_sync(hooks: dict[str, object], argv: tuple[str, ...]) -> None:
    config.sync_runtime_hook_groups(hooks, argv)
    config.remove_unsupported_guard_hook_groups(hooks)


_FIXTURES: tuple[dict[str, object], ...] = (
    {},
    {"PreToolUse": [{"matcher": _LEGACY_TOOL_MATCHER, "hooks": [_STALE_GUARD, _USER_HOOK]}]},
    {
        "Stop": [{"hooks": [_STALE_GUARD]}],
        "UserPromptSubmit": [{"hooks": [_STALE_GUARD]}],
        "PermissionDenied": [{"hooks": [_STALE_GUARD, _USER_HOOK]}],
        "SessionStart": [{"matcher": "startup", "hooks": [_USER_HOOK]}],
    },
    {"Notification": "not-a-list", "PostToolUse": [{"matcher": "Bash", "hooks": [_USER_HOOK]}, "junk"]},
)


@pytest.mark.parametrize("fixture", _FIXTURES)
def test_contract_builder_matches_legacy_settings_bytes(fixture: dict[str, object]) -> None:
    legacy_hooks = copy.deepcopy(fixture)
    current_hooks = copy.deepcopy(fixture)
    _legacy_sync(legacy_hooks, _ARGV)
    _contract_sync(current_hooks, _ARGV)
    legacy = {"model": "x", "hooks": legacy_hooks}
    current = {"model": "x", "hooks": current_hooks}
    assert json.dumps(current, indent=2).encode() == json.dumps(legacy, indent=2).encode()


def test_contract_constants_match_legacy_values() -> None:
    assert config.CLAUDE_GUARD_TOOL_MATCHER == _LEGACY_TOOL_MATCHER
    assert config.CLAUDE_GUARD_POST_TOOL_MATCHER == _LEGACY_POST_TOOL_MATCHER
    assert config.CLAUDE_GUARD_NOTIFICATION_MATCHER == "permission_prompt"
    assert config.CLAUDE_GUARD_SESSION_START_MATCHERS == ("startup", "resume", "clear", "compact")
    assert config.CLAUDE_GUARD_TOOL_TIMEOUT_SECONDS == 30
    assert config.CLAUDE_GUARD_NOTIFICATION_TIMEOUT_SECONDS == 10
    assert config.CLAUDE_GUARD_SESSION_START_TIMEOUT_SECONDS == 10
    assert config.CLAUDE_GUARD_STOP_TIMEOUT_SECONDS == 10
    assert config.CLAUDE_GUARD_DAEMON_HOOK_MARKER == "HOL_GUARD_CLAUDE_DAEMON_HOOK"
    assert config.CLAUDE_GUARD_SESSION_START_HOOK_MARKER == "HOL_GUARD_CLAUDE_SESSION_START_HOOK"
    assert config.CLAUDE_GUARD_SESSION_START_CONTEXT == "HOL Guard protection is active for this workspace."


def test_bridge_config_keys_match_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_hook_argv, "_native_bridge_executable", lambda: None)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    argv = claude_hook_argv.daemon_hook_command_parts(context, fallback_daemon_url="http://127.0.0.1:1")
    keys = tuple(json.loads(argv[-1]))
    assert keys == config.CLAUDE_BRIDGE_CONFIG_REQUIRED_KEYS
    assert set(config.CLAUDE_BRIDGE_CONFIG_OPTIONAL_KEYS) == {"recovery_command"}


@pytest.mark.parametrize(
    "mutation",
    (
        lambda doc: doc.update(schema="other"),
        lambda doc: doc["runtime_groups"][0].update(timeout_seconds=0),
        lambda doc: doc["runtime_groups"][0].update(timeout_seconds=True),
        lambda doc: doc["runtime_groups"][1].pop("matcher"),
        lambda doc: doc["runtime_groups"].append(dict(doc["runtime_groups"][0])),
        lambda doc: doc["markers"].update(daemon_hook=""),
        lambda doc: doc["session_start"].update(matchers="startup"),
        lambda doc: doc.pop("bridge_config"),
    ),
)
def test_contract_parser_rejects_malformed_documents(mutation: Callable[[dict[str, Any]], object]) -> None:
    document = json.loads(config.CLAUDE_HOOK_GROUPS_CONTRACT_PATH.read_text(encoding="utf-8"))
    mutation(document)
    with pytest.raises(ValueError, match="claude_hook_groups_contract_invalid"):
        config.parse_claude_hook_groups_contract(document)
