"""The repairs ``hol-guard update`` makes to harness installs the previous release left behind.

The native runtime reads each install record, rebinds the install's own workspace, reinstalls under its own
installation transaction and answers the row each repair recorded and the warning for each one that could not
finish. This module shapes that answer for the update command.
"""

from __future__ import annotations

from pathlib import Path

from ..harness.base import HarnessContext
from ..store import GuardStore
from .managed_install_payload import managed_install_payload
from .native_managed_install import ask_managed, native_row

# Every harness an update repair may reinstall.
_REPAIRED = ("grok", "zcode", "devin", "kimi", "copilot", "openclaw", "hermes", "muse")

# What an update says when the runtime could not be asked at all.
_UNAVAILABLE = {
    "grok": "Could not refresh Grok protection during update",
    "bounded": "Could not check bounded hook clients for the native runtime during update",
}


def _install_workspaces(store: GuardStore, workspace: str | None) -> dict[str, Path | None]:
    """The workspace each active install is reinstalled into: its record's own, else the update's.

    Only a Windows walk of workspace skills needs them, so the runtime is handed what that walk finds there.
    """
    try:
        rows = store.list_managed_installs()
    except (OSError, RuntimeError, ValueError):
        return {}
    workspaces: dict[str, Path | None] = {}
    for row in rows:
        harness = str(row.get("harness"))
        if harness not in _REPAIRED or not row.get("active"):
            continue
        recorded = row.get("workspace")
        if isinstance(recorded, str) and recorded.strip():
            path = Path(recorded).expanduser()
            workspaces[harness] = path if path.is_absolute() else Path.cwd() / path
        else:
            workspaces[harness] = None if workspace is None else Path(workspace)
    return workspaces


def native_update_repair(
    update: str,
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[list[dict[str, object]], list[str]]:
    """The installs ``update`` ("grok" or "bounded") reinstalled, and the warnings for those it could not."""

    try:
        answer = ask_managed(
            "managed_update",
            context,
            _REPAIRED,
            actor="managed.install",
            workspaces=_install_workspaces(store, workspace),
            update=update,
            workspace=workspace,
            now=now,
            source=store.guard_source,
        )
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        # An unavailable, old or slow resident must not stop the repairs after this one.
        return [], [f"{_UNAVAILABLE[update]}: {error}"]
    installs: list[dict[str, object]] = []
    for row in answer["installs"]:
        decoded = native_row(row)
        # A row the install just recorded is summarized as an install's payload; one it already held is not.
        installs.append(managed_install_payload(decoded) if "manifest_json" in row else decoded)
    return installs, [str(note) for note in answer["notes"]]
