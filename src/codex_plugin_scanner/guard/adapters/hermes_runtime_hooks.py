"""Local Hermes shell-hook registration and native hook responses.

Hermes only intercepts tools through ``hooks.pre_tool_call`` in config.yaml.
The managed ``pretool-hook.json`` file is unused until that entry exists.
"""

from __future__ import annotations

import json
import shlex
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from codex_plugin_scanner.safe_output import write_text_atomic_no_follow

from .hermes_file_inspection import HERMES_CONFIG_MAX_BYTES, inspect_hermes_config, inspect_hermes_text_file

_PRETOOL_EVENT = "pre_tool_call"
_GUARD_HOOK_ID = "hol-guard-pretool"
_GUARD_HOOK_MARKERS = ("__guard-bounded-hook", "bounded_cli_hook_bridge")
_ALLOWLIST_NAME = "shell-hooks-allowlist.json"
_BLOCK_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_LAUNCH_REVIEW_ONLY_LABEL = "launch-review only"
_MALFORMED_ALLOWLIST = (
    "Hermes shell-hooks-allowlist.json is malformed; repair the file so Guard can allowlist its pre_tool_call command."
)
_MISSING_HOOK_COMMAND = "Hermes Guard hook command is missing; runtime protection was not registered."
_UNSAFE_ALLOWLIST = "Hermes shell-hooks-allowlist.json must be a regular file directly under the selected Hermes home."


def hermes_hook_command_string(command: Sequence[str]) -> str:
    """Return the exact command string Hermes will shlex.split."""

    return shlex.join([str(part) for part in command])


def is_guard_pretool_entry(entry: object, *, expected_command: str | None = None) -> bool:
    if not isinstance(entry, Mapping):
        return False
    if entry.get("id") == _GUARD_HOOK_ID:
        return True
    command = entry.get("command")
    return isinstance(expected_command, str) and bool(expected_command) and command == expected_command


def _legacy_guard_pretool_command(command: object) -> bool:
    return isinstance(command, str) and all(marker in command for marker in _GUARD_HOOK_MARKERS)


def guard_pretool_hook_entry(*, command: Sequence[str], timeout_seconds: int) -> dict[str, object]:
    return {
        "id": _GUARD_HOOK_ID,
        "matcher": ".*",
        "command": hermes_hook_command_string(command),
        "timeout": timeout_seconds,
        "fail_closed": True,
    }


def _pretool_entries(hooks: Mapping[str, object]) -> list[object]:
    entries = hooks.get(_PRETOOL_EVENT)
    if isinstance(entries, list):
        return list(entries)
    return []


def guard_pretool_hook_registered(
    config: Mapping[str, object] | None,
    *,
    expected_command: str | None = None,
    allowlist_path: Path | None = None,
) -> bool:
    if not isinstance(config, Mapping):
        return False
    hooks = config.get("hooks")
    if not isinstance(hooks, Mapping):
        return False
    for entry in _pretool_entries(hooks):
        if not isinstance(entry, Mapping):
            continue
        if entry.get("fail_closed") is not True and entry.get("failClosed") is not True:
            continue
        if entry.get("matcher") != ".*":
            continue
        if not is_guard_pretool_entry(entry, expected_command=expected_command):
            continue
        command = entry.get("command")
        if not isinstance(command, str) or not command.strip():
            continue
        if allowlist_path is not None and not _allowlist_has_command(allowlist_path, command):
            continue
        return True
    return False


def merge_guard_pretool_hook(
    config: dict[str, Any],
    *,
    command: Sequence[str],
    timeout_seconds: int,
) -> tuple[bool, list[str]]:
    """Insert or replace Guard's pre_tool_call entry. Preserve user hooks.

    Returns ``(False, [])`` when an existing ``hooks`` value is not a mapping,
    so the caller can leave the file unchanged rather than destroy user config.
    """

    hooks = config.get("hooks")
    if hooks is None:
        hooks = {}
        config["hooks"] = hooks
    if not isinstance(hooks, dict):
        return False, []
    expected = hermes_hook_command_string(command)
    preserved: list[object] = []
    removed: list[str] = []
    for entry in _pretool_entries(hooks):
        if is_guard_pretool_entry(entry, expected_command=expected) or (
            isinstance(entry, Mapping) and _legacy_guard_pretool_command(entry.get("command"))
        ):
            old_command = entry.get("command") if isinstance(entry, Mapping) else None
            if isinstance(old_command, str) and old_command.strip():
                removed.append(old_command)
            continue
        preserved.append(entry)
    preserved.append(guard_pretool_hook_entry(command=command, timeout_seconds=timeout_seconds))
    hooks[_PRETOOL_EVENT] = preserved
    return True, removed


def remove_guard_pretool_hooks(config: dict[str, Any]) -> list[str]:
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        return []
    removed: list[str] = []
    preserved: list[object] = []
    for entry in _pretool_entries(hooks):
        if is_guard_pretool_entry(entry) or (
            isinstance(entry, Mapping) and _legacy_guard_pretool_command(entry.get("command"))
        ):
            command = entry.get("command") if isinstance(entry, Mapping) else None
            if isinstance(command, str) and command.strip():
                removed.append(command)
            continue
        preserved.append(entry)
    if preserved:
        hooks[_PRETOOL_EVENT] = preserved
    else:
        hooks.pop(_PRETOOL_EVENT, None)
        if not hooks:
            config.pop("hooks", None)
    return removed


def merge_guard_hook_allowlist(
    hermes_home: Path,
    *,
    command: Sequence[str],
    retire_commands: Sequence[str] = (),
) -> None:
    """Approve only Guard's (event, command) pair without auto-accepting other hooks."""

    allowlist_path = _allowlist_destination(hermes_home)
    command_string = hermes_hook_command_string(command)
    payload = _read_allowlist(allowlist_path)
    if payload is None:
        raise ValueError(_MALFORMED_ALLOWLIST)
    retired = {item for item in retire_commands if item and item != command_string}
    approvals = [
        item
        for item in payload.get("approvals", [])
        if isinstance(item, dict) and not (item.get("event") == _PRETOOL_EVENT and item.get("command") in retired)
    ]
    if not any(item.get("event") == _PRETOOL_EVENT and item.get("command") == command_string for item in approvals):
        approvals.append({"event": _PRETOOL_EVENT, "command": command_string})
    _atomic_write_allowlist(
        allowlist_path,
        json.dumps({**payload, "approvals": approvals}, indent=2) + "\n",
    )


def remove_guard_hook_allowlist(hermes_home: Path, *, command_string: str) -> None:
    allowlist_path = _allowlist_destination(hermes_home)
    if not allowlist_path.is_file():
        return
    payload = _read_allowlist(allowlist_path)
    if payload is None:
        return
    approvals = [
        item
        for item in payload.get("approvals", [])
        if isinstance(item, dict)
        and not (item.get("event") == _PRETOOL_EVENT and item.get("command") == command_string)
    ]
    _atomic_write_allowlist(
        allowlist_path,
        json.dumps({**payload, "approvals": approvals}, indent=2) + "\n",
    )


def hermes_allowlist_path(hermes_home: Path) -> Path:
    """Return the fixed allowlist slot under the selected Hermes authority root.

    Resolving the root itself deliberately preserves custom and symlinked
    ``HERMES_HOME`` values while ensuring no caller-controlled suffix reaches a
    filesystem write.
    """

    return hermes_home.expanduser().resolve(strict=False) / _ALLOWLIST_NAME


def prepare_hermes_hook_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Normalize Hermes stdin onto Guard envelope keys."""

    normalized = dict(payload)
    event_name = normalized.get("hook_event_name")
    if isinstance(event_name, str) and event_name.replace("_", "").replace("-", "").lower() == "pretoolcall":
        normalized["hook_event_name"] = "PreToolUse"
    if not isinstance(normalized.get("tool_input"), Mapping):
        args = normalized.get("args")
        if isinstance(args, Mapping):
            normalized["tool_input"] = dict(args)
    return normalized


def hermes_native_decision(*, policy_action: str, reason: str) -> dict[str, object]:
    if policy_action in {"allow", "warn"}:
        return {"decision": "allow", "reason": reason}
    return {"decision": "block", "reason": reason or "HOL Guard blocked this action"}


def hermes_should_exit_block(policy_action: str) -> bool:
    return policy_action in _BLOCK_ACTIONS


def hermes_bridge_response(
    daemon_response: Mapping[str, object],
    *,
    event_name: str,
) -> tuple[str, str, int]:
    """Turn a daemon or CLI payload into Hermes stdout JSON plus exit code."""

    del event_name
    policy_action, reason = _policy_from_response(daemon_response)
    payload = hermes_native_decision(policy_action=policy_action, reason=reason)
    stdout = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return stdout, "", 2 if hermes_should_exit_block(policy_action) else 0


def emit_hermes_hook_response(
    *,
    policy_action: str,
    reason: str,
    output_stream: TextIO | None = None,
) -> None:
    stream = output_stream if output_stream is not None else sys.stdout
    payload = hermes_native_decision(policy_action=policy_action, reason=reason)
    stream.write(json.dumps(payload, separators=(",", ":")) + "\n")
    stream.flush()


def apply_hermes_doctor_protection_label(payload: dict[str, object]) -> None:
    probe = payload.get("runtime_probe")
    if not isinstance(probe, dict):
        return
    present = probe.get("managed_install_present") is True
    registered = probe.get("runtime_hook_registered") is True
    if present and not registered:
        payload["runtime_protection_label"] = _LAUNCH_REVIEW_ONLY_LABEL


def hermes_runtime_hook_registered(config_yaml_path: Path) -> bool:
    if not config_yaml_path.is_file():
        return False
    inspection = inspect_hermes_config(config_yaml_path, syntax="yaml")
    if not inspection.complete or inspection.payload is None:
        return False
    return guard_pretool_hook_registered(
        inspection.payload,
        allowlist_path=hermes_allowlist_path(config_yaml_path.parent),
    )


def hermes_runtime_hook_warning(runtime_probe: dict[str, object] | None) -> str | None:
    if runtime_probe is None:
        return None
    present = runtime_probe.get("managed_install_present") is True
    registered = runtime_probe.get("runtime_hook_registered") is True
    if present and not registered:
        return (
            "Hermes runtime hook is not registered. Shell and tool calls are launch-review only. "
            "Run `hol-guard install hermes` to write a fail-closed hooks.pre_tool_call entry."
        )
    return None


def sync_guard_runtime_hooks(
    config: dict[str, Any],
    *,
    command: object,
    timeout_seconds: int,
    hermes_home: Path,
) -> None:
    if not isinstance(command, list):
        raise ValueError(_MISSING_HOOK_COMMAND)
    hook_command = [str(part) for part in command if isinstance(part, str)]
    if not hook_command:
        raise ValueError(_MISSING_HOOK_COMMAND)
    merged, removed = merge_guard_pretool_hook(config, command=hook_command, timeout_seconds=timeout_seconds)
    if not merged:
        raise ValueError("Hermes hooks config is not a mapping; runtime protection was not registered.")
    merge_guard_hook_allowlist(
        hermes_home,
        command=hook_command,
        retire_commands=removed,
    )


def unsync_guard_runtime_hooks(config: dict[str, Any], *, hermes_home: Path) -> None:
    for command_string in remove_guard_pretool_hooks(config):
        remove_guard_hook_allowlist(hermes_home, command_string=command_string)


def _policy_from_response(response: Mapping[str, object]) -> tuple[str, str]:
    decision = response.get("decision")
    if isinstance(decision, str) and decision.strip().lower() in {"block", "deny"}:
        return "block", _reason_from_response(response)
    if isinstance(decision, str) and decision.strip().lower() == "allow":
        return "allow", _reason_from_response(response)
    action = response.get("action")
    if isinstance(action, str) and action.strip().lower() == "block":
        return "block", _reason_from_response(response)
    hook_specific = response.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        permission = hook_specific.get("permissionDecision")
        if isinstance(permission, str) and permission.strip().lower() in {"deny", "ask"}:
            return "block", _reason_from_response(response)
        if isinstance(permission, str) and permission.strip().lower() == "allow":
            return "allow", _reason_from_response(response)
    policy_action = response.get("policy_action")
    if isinstance(policy_action, str) and policy_action.strip():
        return policy_action.strip(), _reason_from_response(response)
    return "block", _reason_from_response(response)


def _reason_from_response(response: Mapping[str, object]) -> str:
    for key in ("reason", "message", "permission_decision_reason"):
        value = response.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    hook_specific = response.get("hookSpecificOutput")
    if isinstance(hook_specific, Mapping):
        value = hook_specific.get("permissionDecisionReason")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "HOL Guard blocked this action"


def _read_allowlist(path: Path) -> dict[str, Any] | None:
    if path.is_symlink():
        return None
    if not path.exists():
        return {"approvals": []}
    inspection = inspect_hermes_text_file(
        path,
        scope_root=path.parent,
        content_limit_bytes=HERMES_CONFIG_MAX_BYTES,
    )
    if not inspection.complete or inspection.content is None:
        return None
    try:
        raw = json.loads(inspection.content)
    except (json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(raw, dict):
        return None
    approvals = raw.get("approvals")
    if approvals is None:
        raw["approvals"] = []
        return raw
    if not isinstance(approvals, list):
        return None
    return raw


def _allowlist_has_command(path: Path, command: str) -> bool:
    payload = _read_allowlist(path)
    if payload is None:
        return False
    return any(
        isinstance(item, dict) and item.get("event") == _PRETOOL_EVENT and item.get("command") == command
        for item in payload.get("approvals", [])
    )


def _allowlist_destination(hermes_home: Path) -> Path:
    path = hermes_allowlist_path(hermes_home)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(_UNSAFE_ALLOWLIST)
    return path


def _atomic_write_allowlist(path: Path, content: str) -> None:
    """Atomically replace the allowlist through the shared no-follow writer."""

    if path.name != _ALLOWLIST_NAME or path.parent != path.parent.resolve(strict=False):
        raise ValueError(_UNSAFE_ALLOWLIST)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(_UNSAFE_ALLOWLIST)
    write_text_atomic_no_follow(path, content)  # NOSONAR - fixed name under the selected Hermes authority root
