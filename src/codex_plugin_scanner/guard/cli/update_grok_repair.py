"""Refresh managed Grok hooks after a Guard package update."""

from __future__ import annotations

import json
import sqlite3

from ..harness.base import HarnessContext
from ..harness.native_harness import ask
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
    """Whether both Grok hook files already hold what an install would write now."""

    return ask("hooks_current", context, harness="grok")["current"] is True


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
