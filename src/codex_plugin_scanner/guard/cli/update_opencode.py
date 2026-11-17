"""Refresh managed OpenCode support after an installed Guard update."""

from __future__ import annotations

import json
import sqlite3

from ..harness.base import HarnessContext
from ..harness.native_harness import ask
from ..store import GuardStore
from .managed_install_context import managed_install_context as _repair_context_from_managed_install

_INSPECT_FAILED = "Could not inspect OpenCode pretool plugin during update: "


def _refresh_opencode_pretool_plugin(
    *,
    context: HarnessContext,
    store: GuardStore,
) -> str | None:
    """Refresh the companion launchers and the pretool plugin; return the note to show.

    The native runtime holds the OpenCode config lock, refreshes the launchers,
    rewrites a stale plugin and words the note.
    """
    try:
        managed_install = store.get_managed_install("opencode")
    except (json.JSONDecodeError, sqlite3.Error):
        return None
    if managed_install is None or not bool(managed_install.get("active")):
        return None
    try:
        repair_context, _ = _repair_context_from_managed_install(context, managed_install)
        answer = ask("update_refresh", repair_context, harness="opencode")
    except (OSError, RuntimeError, ValueError) as error:
        return f"{_INSPECT_FAILED}{error}"
    note = answer["note"]
    return note if isinstance(note, str) else None
