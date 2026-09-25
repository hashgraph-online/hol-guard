"""Exact repair commands that may start while hook review cannot authenticate."""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from pathlib import Path

from .hook_availability_floor import (
    _BLOCKED_SOURCE_EVENTS,
    _MUTATING_TOOLS,
    _UNSAFE_SHELL_MARKERS,
    _flag_name,
    _payload_command,
    _payload_is_mcp,
    _payload_source_events,
    _tool_name,
    hook_action_is_emergency_safe,
)
from .hook_request_parsing import runtime_hook_event_name

_LAUNCHER_REPAIR_BINARIES = frozenset({"hol-guard", "plugin-guard"})
_LAUNCHER_REPAIR_FLAGS = frozenset({"--dry-run", "--force-pypi-reinstall", "--json"})
_LAUNCHER_REPAIR_HARNESSES = frozenset(
    {
        "antigravity",
        "claude-code",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "devin",
        "gemini",
        "grok",
        "hermes",
        "kimi",
        "omp",
        "openclaw",
        "opencode",
        "paseo",
        "pi",
        "zcode",
    }
)


def hook_action_is_launcher_recovery_safe(
    payload: Mapping[str, object],
    *,
    workspace: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    """Allow inspection, or the exact bare command that restores a managed launcher.

    A path-qualified executable is never treated as the managed launcher. An
    unauthenticated payload reference is not evidence of the tool that will run.
    Every other action stays blocked.
    """

    if "guard_payload_ref" in payload:
        return False
    if hook_action_is_emergency_safe(payload, workspace=workspace, home_dir=home_dir):
        return True
    if runtime_hook_event_name(payload) != "PreToolUse":
        return False
    tool_name = _tool_name(payload)
    if tool_name in _MUTATING_TOOLS and tool_name not in {"bash", "shell"}:
        return False
    if _payload_source_events(payload) & _BLOCKED_SOURCE_EVENTS:
        return False
    if _payload_is_mcp(payload) or tool_name.startswith("plugin-"):
        return False
    command = _payload_command(payload)
    if command is None:
        return False
    return _command_is_launcher_repair(command)


def _command_is_launcher_repair(command: str) -> bool:
    stripped = command.strip()
    if not stripped or len(stripped) > 4096:
        return False
    if any(marker in stripped for marker in _UNSAFE_SHELL_MARKERS):
        return False
    try:
        tokens = shlex.split(stripped, posix=True, comments=False)
    except ValueError:
        return False
    if len(tokens) < 2 or tokens[0] not in _LAUNCHER_REPAIR_BINARIES:
        return False
    positional: list[str] = []
    for token in tokens[1:]:
        if token.startswith("-"):
            if _flag_name(token) not in _LAUNCHER_REPAIR_FLAGS or "=" in token:
                return False
            continue
        positional.append(token)
    if positional[:1] == ["install"]:
        return len(positional) == 2 and positional[1] in _LAUNCHER_REPAIR_HARNESSES
    if positional[:1] == ["update"]:
        return len(positional) == 1
    if positional[:1] == ["daemon"]:
        return positional[1:] in (["repair"], ["status"])
    return False


__all__ = ["hook_action_is_launcher_recovery_safe"]
