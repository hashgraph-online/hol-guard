"""Refresh managed OpenCode support after an installed Guard update."""

from __future__ import annotations

from ..harness_context import HarnessContext
from ..native_harness_client import ask
from ..store import GuardStore

_INSPECT_FAILED = "Could not inspect OpenCode pretool plugin during update: "


def _refresh_opencode_pretool_plugin(
    *,
    context: HarnessContext,
    store: GuardStore,
) -> str | None:
    """Refresh the companion launchers and the pretool plugin; return the note to show.

    The native runtime reads the OpenCode install record, holds the config
    lock, refreshes the launchers, rewrites a stale plugin and words the note.
    """
    try:
        answer = ask("update_refresh", context, harness="opencode", store_home=str(store.guard_home))
    except (OSError, RuntimeError, ValueError) as error:
        return f"{_INSPECT_FAILED}{error}"
    note = answer["note"]
    return note if isinstance(note, str) else None
