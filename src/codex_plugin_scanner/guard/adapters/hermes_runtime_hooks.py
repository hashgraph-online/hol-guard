"""Local Hermes shell-hook registration and native hook responses.

Hermes only intercepts tools through ``hooks.pre_tool_call`` in config.yaml.
The managed ``pretool-hook.json`` file is unused until that entry exists.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .hermes_file_inspection import inspect_hermes_config

_PRETOOL_EVENT = "pre_tool_call"
_GUARD_HOOK_MARKERS = ("__guard-bounded-hook", "bounded_cli_hook_bridge")
_ALLOWLIST_NAME = "shell-hooks-allowlist.json"
_BLOCK_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_LAUNCH_REVIEW_ONLY_LABEL = "launch-review only"


def hermes_hook_command_string(command: Sequence[str]) -> str:
    """Return the exact command string Hermes will shlex.split."""

    return shlex.join([str(part) for part in command])


def is_guard_pretool_command(command: object) -> bool:
    if not isinstance(command, str) or not command.strip():
        return False
    return any(marker in command for marker in _GUARD_HOOK_MARKERS)


def guard_pretool_hook_entry(*, command: Sequence[str], timeout_seconds: int) -> dict[str, object]:
    return {
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


def guard_pretool_hook_registered(config: Mapping[str, object] | None) -> bool:
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
        if is_guard_pretool_command(entry.get("command")):
            return True
    return False


def merge_guard_pretool_hook(
    config: dict[str, Any],
    *,
    command: Sequence[str],
    timeout_seconds: int,
) -> bool:
    """Insert or replace Guard's pre_tool_call entry. Preserve user hooks.

    Returns False when an existing ``hooks`` value is not a mapping, so the
    caller can leave the file unchanged rather than destroy user config.
    """

    hooks = config.get("hooks")
    if hooks is None:
        hooks = {}
        config["hooks"] = hooks
    if not isinstance(hooks, dict):
        return False
    preserved = [
        entry
        for entry in _pretool_entries(hooks)
        if not (isinstance(entry, Mapping) and is_guard_pretool_command(entry.get("command")))
    ]
    preserved.append(guard_pretool_hook_entry(command=command, timeout_seconds=timeout_seconds))
    hooks[_PRETOOL_EVENT] = preserved
    return True


def remove_guard_pretool_hooks(config: dict[str, Any]) -> list[str]:
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        return []
    removed: list[str] = []
    preserved: list[object] = []
    for entry in _pretool_entries(hooks):
        if isinstance(entry, Mapping) and is_guard_pretool_command(entry.get("command")):
            command = entry.get("command")
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


def merge_guard_hook_allowlist(allowlist_path: Path, *, command: Sequence[str]) -> None:
    """Approve only Guard's (event, command) pair without auto-accepting other hooks."""

    command_string = hermes_hook_command_string(command)
    payload = _read_allowlist(allowlist_path)
    if payload is None:
        return
    approvals = [item for item in payload.get("approvals", []) if isinstance(item, dict)]
    if any(item.get("event") == _PRETOOL_EVENT and item.get("command") == command_string for item in approvals):
        return
    approvals.append({"event": _PRETOOL_EVENT, "command": command_string})
    allowlist_path.parent.mkdir(parents=True, exist_ok=True)
    allowlist_path.write_text(
        json.dumps({**payload, "approvals": approvals}, indent=2) + "\n",
        encoding="utf-8",
    )


def remove_guard_hook_allowlist(allowlist_path: Path, *, command_string: str) -> None:
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
    allowlist_path.write_text(
        json.dumps({**payload, "approvals": approvals}, indent=2) + "\n",
        encoding="utf-8",
    )


def hermes_allowlist_path(hermes_home: Path) -> Path:
    return hermes_home / _ALLOWLIST_NAME


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
    if hermes_should_exit_block(policy_action):
        return stdout, reason, 2
    return stdout, "", 0


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
    return guard_pretool_hook_registered(inspection.payload)


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
        return
    hook_command = [str(part) for part in command if isinstance(part, str)]
    if not hook_command:
        return
    if merge_guard_pretool_hook(config, command=hook_command, timeout_seconds=timeout_seconds):
        merge_guard_hook_allowlist(hermes_allowlist_path(hermes_home), command=hook_command)


def unsync_guard_runtime_hooks(config: dict[str, Any], *, hermes_home: Path) -> None:
    for command_string in remove_guard_pretool_hooks(config):
        remove_guard_hook_allowlist(hermes_allowlist_path(hermes_home), command_string=command_string)


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
    if not path.exists():
        return {"approvals": []}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
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
