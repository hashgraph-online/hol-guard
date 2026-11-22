"""Persistence entry points for command activity evidence.

Writes run in the native resident (``guard_store`` op), which owns the SQL, the
rollups and the replay arbitration. Python validates inputs and serializes the
evidence; it never recomputes what the resident persists.
"""

# pyright: reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Any, Protocol, cast

from .runtime.command_activity_contract import CommandActivityEvidence
from .runtime.command_shadow_evaluation import CommandShadowObservation
from .store_command_activity_wire import evidence_wire, shadow_wire


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...


class StoreCommandActivityMixin:
    def probe_command_activity_persistence(
        self: _ConnectionOwner,
        evidence: CommandActivityEvidence,
        *,
        shadow: CommandShadowObservation | None = None,
        shadow_evaluation_succeeded: bool = True,
    ) -> None:
        """Exercise and roll back the real command and shadow write path."""

        _validate_command_activity_write(evidence, shadow)
        self._native_store_call(
            "probe_command_activity_persistence",
            {
                "evidence": evidence_wire(evidence),
                "shadow": shadow_wire(shadow),
                "shadow_evaluation_succeeded": shadow_evaluation_succeeded,
            },
        )

    def count_command_activities(self: _ConnectionOwner) -> int:
        count = self._native_store_call("count_command_activities", {})
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise RuntimeError("native count_command_activities returned no answer")
        return count


def _validate_command_activity_write(
    evidence: CommandActivityEvidence,
    shadow: CommandShadowObservation | None,
) -> None:
    if not isinstance(cast(object, evidence), CommandActivityEvidence):
        raise ValueError("evidence must be a CommandActivityEvidence")
    if shadow is None:
        return
    if not isinstance(cast(object, shadow), CommandShadowObservation):
        raise ValueError("shadow must be a CommandShadowObservation")
    if shadow.activity_id != evidence.activity.activity_id:
        raise ValueError("shadow activity_id must match command evidence")
    if shadow.occurred_at != evidence.activity.occurred_at:
        raise ValueError("shadow occurred_at must match command evidence")
