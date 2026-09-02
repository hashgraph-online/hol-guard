"""Refresh managed Grok hooks after a Guard package update."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

from ..adapters.base import HarnessContext
from ..adapters.grok import GrokHarnessAdapter
from ..adapters.grok_config import (
    GROK_HOOK_INTERNAL_TIMEOUT_SECONDS,
    GROK_PRETOOL_HOOK_TIMEOUT_SECONDS,
    GUARD_HOOK_PRETOOL_FILE,
)
from ..store import GuardStore
from .install_commands import apply_managed_install
from .managed_install_context import managed_install_context as repair_context_from_managed_install


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
    hook_path = GrokHarnessAdapter._hooks_dir(context) / GUARD_HOOK_PRETOOL_FILE
    if not hook_path.is_file():
        return False
    try:
        payload = json.loads(hook_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    timeout = _pretool_timeout(payload)
    command = _pretool_command(payload)
    marker = f'"timeout_seconds":{GROK_HOOK_INTERNAL_TIMEOUT_SECONDS}'
    if timeout != GROK_PRETOOL_HOOK_TIMEOUT_SECONDS or marker not in command.replace(" ", ""):
        return False
    hook_config = _hook_config_from_command(command)
    if hook_config is None:
        return False
    executable = hook_config.get("python_executable")
    cli_args = hook_config.get("cli_args")
    if not isinstance(executable, str) or not executable.strip():
        return False
    executable_path = Path(executable)
    if not executable_path.exists():
        return False
    try:
        if executable_path.resolve() != Path(sys.executable).resolve():
            return False
    except OSError:
        return False
    return isinstance(cli_args, list) and "--json" in cli_args


def _hook_config_from_command(command: str) -> dict[str, object] | None:
    start = command.find("{")
    end = command.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(command[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


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
