"""Bounded reads for command shadow evidence; shadow reads and writes run in the native resident."""

# pyright: reportAny=false, reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Protocol, cast

from .models import GuardAction
from .runtime.command_shadow_evaluation import (
    CommandShadowCohort,
    CommandShadowComparison,
    CommandShadowObservation,
)
from .runtime.effect_decision import FinalDisposition


class _NativeOwner(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...


class StoreCommandShadowMixin:
    def count_command_shadow_observations(self: _NativeOwner) -> int:
        return int(self._native_store_call("count_command_shadow_observations", {}))

    def list_command_shadow_observations(
        self: _NativeOwner,
        *,
        limit: int = 10_000,
    ) -> tuple[CommandShadowObservation, ...]:
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        rows = cast(
            Sequence[Mapping[str, Any]],
            self._native_store_call("list_command_shadow_observations", {"limit": limit}),
        )
        return tuple(_observation_from_wire(row) for row in rows)


def _observation_from_wire(row: Mapping[str, Any]) -> CommandShadowObservation:
    return CommandShadowObservation(
        activity_id=str(row["activity_id"]),
        occurred_at=datetime.fromisoformat(str(row["occurred_at"])),
        cohorts=tuple(CommandShadowCohort(str(cohort)) for cohort in row["cohorts"]),
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
