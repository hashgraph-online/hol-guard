"""Compatibility transport for Claude approval-question hooks.

The Rust resident owns question matching, persistence, integrity finalization,
and pending-row consumption. This module remains only for callers that still
import the historical helper name.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..native_hook_direct import native_hook_direct

if TYPE_CHECKING:
    from ..store import GuardStore


def _settle_claude_guard_question(
    store: GuardStore, payload: dict[str, object], *, deadline: float | None = None
) -> bool | None:
    """Ask the Rust resident to settle one Claude approval question."""

    response = native_hook_direct(
        harness="claude-code",
        guard_home=store.guard_home,
        payload=payload,
        workspace=None,
        home_dir=Path(store.guard_home),
        deadline=deadline,
    )
    if response is None:
        return None
    if "outcome" in response:
        return None
    return False


__all__ = ["_settle_claude_guard_question"]
