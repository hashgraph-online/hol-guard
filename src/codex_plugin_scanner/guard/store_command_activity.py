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
from .runtime.command_activity_display import INVOCATION_PREVIEW_MAX_CHARS
from .runtime.command_shadow_evaluation import CommandShadowObservation
from .store_command_activity_wire import evidence_wire, shadow_wire


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...


class StoreCommandActivityMixin:
    def record_command_activity(
        self: _ConnectionOwner,
        evidence: CommandActivityEvidence,
        *,
        shadow: CommandShadowObservation | None = None,
        shadow_evaluation_succeeded: bool = False,
        invocation_preview: str | None = None,
    ) -> bool:
        """Persist one logical command and its rule hits; return false for an exact replay."""

        _validate_command_activity_write(evidence, shadow)
        preview = _validated_invocation_preview(invocation_preview)
        return bool(
            self._native_store_call(
                "record_command_activity",
                {
                    "evidence": evidence_wire(evidence),
                    "shadow": shadow_wire(shadow),
                    "shadow_evaluation_succeeded": shadow_evaluation_succeeded,
                    "invocation_preview": preview,
                },
            )
        )

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
        with self._connect() as connection:
            row = cast(
                tuple[int] | None,
                connection.execute("select count(*) from command_activity").fetchone(),
            )
        return int(row[0]) if row is not None else 0

    def count_command_activity_rule_hits(self: _ConnectionOwner, rule_id: str | None = None) -> int:
        with self._connect() as connection:
            if rule_id is None:
                row = cast(
                    tuple[int] | None,
                    connection.execute("select count(*) from command_activity_matches").fetchone(),
                )
            else:
                row = cast(
                    tuple[int] | None,
                    connection.execute(
                        "select count(*) from command_activity_matches where rule_id = ?",
                        (rule_id,),
                    ).fetchone(),
                )
        return int(row[0]) if row is not None else 0


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


def _validated_invocation_preview(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("invalid_invocation_preview")
    stripped = value.strip()
    if not stripped or len(stripped) > INVOCATION_PREVIEW_MAX_CHARS:
        raise ValueError("invalid_invocation_preview")
    return stripped
