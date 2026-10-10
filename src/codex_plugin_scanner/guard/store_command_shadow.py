"""Bounded reads for command shadow evidence; shadow writes run in the native resident."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Protocol, cast

from .models import GuardAction
from .runtime.command_shadow_evaluation import (
    CommandShadowCohort,
    CommandShadowComparison,
    CommandShadowObservation,
)
from .runtime.effect_decision import FinalDisposition


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


class StoreCommandShadowMixin:
    def count_command_shadow_observations(self: _ConnectionOwner) -> int:
        with self._connect() as connection:
            row = connection.execute("select count(*) from command_activity_shadow_evaluations").fetchone()
        return int(row[0]) if row is not None else 0

    def list_command_shadow_observations(
        self: _ConnectionOwner,
        *,
        limit: int = 10_000,
    ) -> tuple[CommandShadowObservation, ...]:
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        with self._connect() as connection:
            connection.execute("begin")
            rows = cast(
                list[sqlite3.Row],
                connection.execute(
                    """
                    select * from command_activity_shadow_evaluations
                    order by occurred_at, activity_id limit ?
                    """,
                    (limit,),
                ).fetchall(),
            )
            return tuple(_observation_from_row(connection, row) for row in rows)


def _row_values(row: sqlite3.Row) -> tuple[object, ...]:
    return tuple(cast(Sequence[object], row))


def _cohort_values(connection: sqlite3.Connection, activity_id: str) -> tuple[tuple[object, ...], ...]:
    rows = cast(
        list[sqlite3.Row],
        connection.execute(
            "select * from command_activity_shadow_cohorts where activity_id = ? order by ordinal",
            (activity_id,),
        ).fetchall(),
    )
    return tuple(_row_values(row) for row in rows)


def _observation_from_row(connection: sqlite3.Connection, row: sqlite3.Row) -> CommandShadowObservation:
    cohort_rows = _cohort_values(connection, str(row["activity_id"]))
    return CommandShadowObservation(
        activity_id=str(row["activity_id"]),
        occurred_at=datetime.fromisoformat(str(row["occurred_at"])),
        cohorts=tuple(CommandShadowCohort(str(item[2])) for item in cohort_rows),
        authoritative_action=cast(GuardAction, row["authoritative_action"]),
        current_action=cast(GuardAction, row["current_action"]),
        current_disposition=FinalDisposition(str(row["current_disposition"])),
        proposed_action=cast(GuardAction, row["proposed_action"]),
        proposed_disposition=FinalDisposition(str(row["proposed_disposition"])),
        comparison=CommandShadowComparison(str(row["comparison"])),
        proposal_version=str(row["proposal_version"]),
        evaluator_schema_version=str(row["evaluator_schema_version"]),
        control_generation=int(row["control_generation"]),
        sample_basis_points=int(row["sample_basis_points"]),
        schema_version=str(row["schema_version"]),
    )


__all__: Sequence[str] = ("StoreCommandShadowMixin",)
