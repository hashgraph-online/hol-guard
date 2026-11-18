"""The repairs ``hol-guard update`` makes to harness installs the previous release left behind.

The native runtime reads each install record, rebinds the install's own workspace, reinstalls under its own
installation transaction and answers the row each repair recorded and the warning for each one that could not
finish. This module shapes that answer for the update command.
"""

from __future__ import annotations

from ..harness_context import HarnessContext
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
