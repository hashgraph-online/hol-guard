"""Best-effort AIBOM inventory context persistence during daemon startup."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from ..store import GuardStore

RecordDiagnostic = Callable[..., object]


def persist_aibom_inventory_context(
    *,
    store: GuardStore,
    cached_workspace_id: str | None,
    workspace_dir: Path | None,
    home_dir: Path | None,
    now: str,
    record_diagnostic: RecordDiagnostic,
) -> None:
    try:
        workspace_id = store.get_cloud_workspace_id()
        if workspace_id is None or workspace_id != cached_workspace_id or workspace_dir is None:
            return
        payload: dict[str, object] = {
            "workspace_dir": str(workspace_dir),
            "workspace_id": workspace_id,
        }
        if home_dir is not None:
            payload["home_dir"] = str(home_dir)
        store.set_sync_payload("aibom_inventory_context", payload, now)
    except sqlite3.DatabaseError as error:
        with suppress(Exception):
            record_diagnostic(
                "aibom_inventory_context_persist_failed",
                detail=type(error).__name__,
            )


__all__ = ["persist_aibom_inventory_context"]
