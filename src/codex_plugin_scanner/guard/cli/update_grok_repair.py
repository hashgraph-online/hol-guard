"""Refresh managed Grok hooks after a Guard package update."""

from __future__ import annotations

from ..harness_context import HarnessContext
from ..store import GuardStore
from .native_managed_update import native_update_repair


def repair_grok_install(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[dict[str, object] | None, str | None]:
    """Rewrite Grok PreToolUse hooks when the baked launcher is stale.

    The native runtime reads the install record, checks whether both hook files already hold what an install
    would write now, and reinstalls under its own installation transaction when they do not.
    """

    installs, notes = native_update_repair("grok", context=context, store=store, workspace=workspace, now=now)
    return (installs[0] if installs else None), (notes[0] if notes else None)


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
