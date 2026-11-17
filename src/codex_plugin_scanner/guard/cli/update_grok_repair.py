"""Refresh managed Grok hooks after a Guard package update."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..adapters.base import HarnessContext
from ..adapters.native_harness import ask
from ..store import GuardStore
from .install_commands import apply_managed_install
from .managed_install_context import managed_install_context as repair_context_from_managed_install
from .native_install_checks import grok_protection


def repair_grok_install(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[dict[str, object] | None, str | None]:
    """Rewrite Grok PreToolUse hooks when the baked launcher is stale."""

    try:
        managed_install = store.get_managed_install("grok")
    except (json.JSONDecodeError, sqlite3.Error):
        return None, None
    if managed_install is None or not bool(managed_install.get("active")):
        return None, None
    try:
        repair_context, repair_workspace = repair_context_from_managed_install(context, managed_install)
        if _grok_hooks_are_current(repair_context):
            return None, None
        payload = apply_managed_install(
            "install",
            "grok",
            False,
            repair_context,
            store,
            repair_workspace or workspace,
            now,
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, sqlite3.Error) as error:
        return None, f"Could not refresh Grok protection during update: {error}"
    repaired = payload.get("managed_install")
    if not isinstance(repaired, dict):
        return None, "Could not refresh Grok protection during update: managed install was not recorded"
    return repaired, None


def _grok_hooks_are_current(context: HarnessContext) -> bool:
    from ..adapters import get_adapter
    from ..adapters.native_harness import NativeHarnessAdapter

    protection = grok_protection(context)
    hook_path = Path(protection["pretool_hook_path"])
    if not hook_path.is_file():
        return False
    try:
        payload = json.loads(hook_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if _pretool_timeout(payload) != protection["pretool_timeout_seconds"]:
        return False
    command = _pretool_command(payload)
    prompt_path = Path(protection["prompt_hook_path"])
    try:
        prompt_hooks = json.loads(prompt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    expected = json.loads(ask("observe_hook", context, harness="grok", command=command)["hook"])
    if not _prompt_hook_entries_are_current(prompt_hooks, expected):
        return False
    adapter = get_adapter("grok")
    return isinstance(adapter, NativeHarnessAdapter) and command == adapter.current_hook_command(context)


def _prompt_hook_entries_are_current(payload: object, expected: dict[str, object]) -> bool:
    hooks = payload.get("hooks") if isinstance(payload, dict) else None
    expected_hooks = expected.get("hooks")
    if not isinstance(hooks, dict) or not isinstance(expected_hooks, dict):
        return False
    for event, required_groups in expected_hooks.items():
        groups = hooks.get(event)
        if not isinstance(groups, list):
            return False
        expected_hook = required_groups[0]["hooks"][0]
        if not any(
            isinstance(group, dict)
            and not group.get("matcher")
            and isinstance(group.get("hooks"), list)
            and any(
                isinstance(hook, dict) and all(hook.get(key) == value for key, value in expected_hook.items())
                for hook in group["hooks"]
            )
            for group in groups
        ):
            return False
    return True


def _pretool_timeout(payload: object) -> int | None:
    command = _pretool_entry(payload)
    timeout = command.get("timeout") if command is not None else None
    return timeout if isinstance(timeout, int) else None


def _pretool_command(payload: object) -> str:
    command = _pretool_entry(payload)
    value = command.get("command") if command is not None else None
    return value if isinstance(value, str) else ""


def _pretool_entry(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return None
    pretool = hooks.get("PreToolUse")
    if not isinstance(pretool, list) or not pretool:
        return None
    first = pretool[0]
    if not isinstance(first, dict):
        return None
    inner = first.get("hooks")
    if isinstance(inner, list) and inner and isinstance(inner[0], dict):
        return inner[0]
    return first


def append_grok_repair(
    repaired_installs: list[dict[str, object]],
    repair_notes: list[str],
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> None:
    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
    )
    if repaired is not None:
        repaired_installs.append(repaired)
    if warning is not None:
        repair_notes.append(warning)


__all__ = ["append_grok_repair", "repair_grok_install"]
