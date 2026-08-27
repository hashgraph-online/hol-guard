"""Atomic persistence boundary for Cloud Review policy memory."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from typing import Protocol

from .approval_gate import ApprovalGateGrant
from .models import PolicyDecision


class _PolicyMemoryStore(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def _prepared_remote_policy_rows(
        self,
        decisions: Sequence[PolicyDecision],
        now: str,
        *,
        approval_gate_grant: ApprovalGateGrant | None,
        remote_write_authorized: bool,
    ) -> tuple[str, list[tuple[object, ...]]]: ...

    def _replace_remote_policy_rows_locked(
        self,
        connection: sqlite3.Connection,
        rows: Sequence[tuple[object, ...]],
    ) -> None: ...


class StoreReviewPolicyMemoryMixin:
    def apply_review_policy_memory_state(
        self: _PolicyMemoryStore,
        decisions: Sequence[PolicyDecision],
        *,
        registry: Sequence[Mapping[str, object]],
        version: Mapping[str, object],
        acknowledgement: Mapping[str, object],
        now: str,
    ) -> None:
        """Atomically publish policy-memory rows and their durable cursor state."""

        normalized_now, rows = self._prepared_remote_policy_rows(
            decisions,
            now,
            approval_gate_grant=None,
            remote_write_authorized=True,
        )
        encoded_state = {
            "guard_review_memory_registry": json.dumps(list(registry), allow_nan=False),
            "guard_review_memory_policy_version": json.dumps(dict(version), allow_nan=False),
            "guard_review_memory_last_ack": json.dumps(dict(acknowledgement), allow_nan=False),
        }
        with self._connect() as connection:
            connection.execute("begin immediate")
            self._replace_remote_policy_rows_locked(connection, rows)
            connection.executemany(
                """
                insert into sync_state (state_key, payload_json, updated_at)
                values (?, ?, ?)
                on conflict(state_key) do update set
                  payload_json = excluded.payload_json,
                  updated_at = excluded.updated_at
                """,
                [(key, payload, normalized_now) for key, payload in encoded_state.items()],
            )


__all__ = ["StoreReviewPolicyMemoryMixin"]
