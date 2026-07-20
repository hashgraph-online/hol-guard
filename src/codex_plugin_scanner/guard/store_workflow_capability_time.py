"""Monotonic workflow-capability time high-water persistence."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from typing import Protocol

from .store_workflow_capabilities_schema import ensure_workflow_capability_schema
from .store_workflow_capability_control import load_validate_and_observe_control
from .store_workflow_capability_lock import serialized_workflow_capability_authority
from .workflow_capabilities import WorkflowCapabilityError


class _WorkflowCapabilityTimeBoundary(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def _load_workflow_capability_control(self) -> str | None: ...

    def _store_workflow_capability_control(self, encoded: str) -> bool: ...


@serialized_workflow_capability_authority
def record_workflow_capability_time_high_water(
    store: _WorkflowCapabilityTimeBoundary,
    capability_id: str,
    *,
    now: str,
    key: bytes,
    key_id: str,
) -> None:
    with store._connect() as connection:
        connection.execute("begin immediate")
        ensure_workflow_capability_schema(connection, applied_at=now)
        load_validate_and_observe_control(
            store,
            connection,
            key=key,
            key_id=key_id,
            now=now,
            create=False,
        )
        row = connection.execute(
            "select 1 from guard_workflow_capabilities where capability_id = ?",
            (capability_id,),
        ).fetchone()
        if row is None:
            raise WorkflowCapabilityError("capability_not_found")
