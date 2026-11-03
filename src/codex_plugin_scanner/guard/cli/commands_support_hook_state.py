"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

from ..native_hook_authority_state import hook_authority_state

if TYPE_CHECKING:
    from ._commands_shared import (
        _now,
    )


from ._commands_shared import *
from .commands_parser_helpers import *


def _remove_claude_pending_permission(
    store: GuardStore,
    *,
    session_id: str,
    artifact_id: str,
) -> None:
    hook_authority_state(
        store,
        "claude_remove_pending",
        now=_now(),
        session_id=session_id,
        artifact_id=artifact_id,
    )


__all__ = ["_remove_claude_pending_permission"]
