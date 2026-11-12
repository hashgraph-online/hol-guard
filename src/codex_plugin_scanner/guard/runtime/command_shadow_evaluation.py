"""Privacy-safe shadow comparison for the central command decision plane."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Final, cast

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from codex_plugin_scanner.guard.models import GuardAction

from .effect_decision import EFFECT_DECISION_SCHEMA_VERSION, FinalDisposition

COMMAND_SHADOW_SCHEMA_VERSION: Final = "guard.command-shadow.v1"
COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION: Final = "guard.command-shadow-proposal.baseline.v1"
COMMAND_SHADOW_CONTROL_GENERATION: Final = 1

_ACTIVITY_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_PROPOSAL_VERSION: Final = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*")
_BASIS_POINTS_MAX: Final = 10_000
_EVALUATOR_SCHEMA_VERSIONS: Final = frozenset(("1.0.0", EFFECT_DECISION_SCHEMA_VERSION))


class CommandShadowCohort(str, Enum):
    BASELINE = "baseline"
    VERIFIED_READS = "cdx-060-verified-reads"
    CONTAINED_CHECKS = "cdx-061-contained-checks"
    CONTAINED_WRITES = "cdx-062-contained-writes"
    TASK_CAPABILITIES = "cdx-063-task-capabilities"
    REMOTE_MUTATION_FLOORS = "cdx-064-remote-mutation-floors"
    PACKAGE_PROVENANCE_FLOORS = "cdx-065-package-provenance-floors"
    CRITICAL_BLOCK_FLOORS = "cdx-066-critical-block-floors"


class CommandShadowComparison(str, Enum):
    LOWERED = "lowered"
    UNCHANGED = "unchanged"
    STRENGTHENED = "strengthened"


@dataclass(frozen=True, slots=True)
class CommandShadowObservation:
    activity_id: str
    occurred_at: datetime
    cohorts: tuple[CommandShadowCohort, ...]
    authoritative_action: GuardAction
    current_action: GuardAction
    current_disposition: FinalDisposition
    proposed_action: GuardAction
    proposed_disposition: FinalDisposition
    comparison: CommandShadowComparison
    proposal_version: str
    evaluator_schema_version: str
    control_generation: int
    sample_basis_points: int
    schema_version: str = COMMAND_SHADOW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.activity_id), str) or _ACTIVITY_ID.fullmatch(self.activity_id) is None:
            raise ValueError("activity_id must be an opaque identifier")
        if not isinstance(cast(object, self.occurred_at), datetime) or self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if self.occurred_at.utcoffset() != timezone.utc.utcoffset(self.occurred_at):
            raise ValueError("occurred_at must be UTC")
        if not isinstance(cast(object, self.cohorts), tuple) or not self.cohorts:
            raise ValueError("cohorts must be a non-empty tuple")
        if tuple(sorted(set(self.cohorts), key=lambda item: item.value)) != self.cohorts:
            raise ValueError("cohorts must be unique and canonically ordered")
        if any(not isinstance(item, CommandShadowCohort) for item in cast(tuple[object, ...], self.cohorts)):
            raise ValueError("cohorts must contain exact CommandShadowCohort values")
        if not is_guard_action(self.authoritative_action):
            raise ValueError("authoritative_action must be a canonical GuardAction")
        if not is_guard_action(self.current_action) or not is_guard_action(self.proposed_action):
            raise ValueError("shadow actions must be canonical GuardAction values")
        if not isinstance(cast(object, self.current_disposition), FinalDisposition):
            raise ValueError("current_disposition must be a FinalDisposition")
        if not isinstance(cast(object, self.proposed_disposition), FinalDisposition):
            raise ValueError("proposed_disposition must be a FinalDisposition")
        if not isinstance(cast(object, self.comparison), CommandShadowComparison):
            raise ValueError("comparison must be a CommandShadowComparison")
        if not _disposition_matches(self.current_action, self.current_disposition):
            raise ValueError("current disposition does not match current action")
        if not _disposition_matches(self.proposed_action, self.proposed_disposition):
            raise ValueError("proposed disposition does not match proposed action")
        if self.comparison is not _comparison(self.current_action, self.proposed_action):
            raise ValueError("comparison does not match the action lattice")
        if (
            not isinstance(cast(object, self.proposal_version), str)
            or len(self.proposal_version) > 128
            or _PROPOSAL_VERSION.fullmatch(self.proposal_version) is None
        ):
            raise ValueError("proposal_version must be a stable identifier")
        if self.evaluator_schema_version not in _EVALUATOR_SCHEMA_VERSIONS:
            raise ValueError("unsupported evaluator schema version")
        if self.control_generation != COMMAND_SHADOW_CONTROL_GENERATION:
            raise ValueError("unsupported shadow control generation")
        if type(self.sample_basis_points) is not int or not 1 <= self.sample_basis_points <= _BASIS_POINTS_MAX:
            raise ValueError("recorded sample_basis_points must be between 1 and 10000")
        if self.schema_version != COMMAND_SHADOW_SCHEMA_VERSION:
            raise ValueError("unsupported command shadow schema version")


def _comparison(current: GuardAction, proposed: GuardAction) -> CommandShadowComparison:
    current_rank = guard_action_severity(current)
    proposed_rank = guard_action_severity(proposed)
    if proposed_rank < current_rank:
        return CommandShadowComparison.LOWERED
    if proposed_rank > current_rank:
        return CommandShadowComparison.STRENGTHENED
    return CommandShadowComparison.UNCHANGED


def _disposition_matches(action: GuardAction, disposition: FinalDisposition) -> bool:
    if action == "allow":
        return disposition in {
            FinalDisposition.SILENT_VERIFIED,
            FinalDisposition.SILENT_CONTAINED,
            FinalDisposition.WORKFLOW_AUTHORIZED,
        }
    return disposition.value == action


__all__ = (
    "COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION",
    "COMMAND_SHADOW_CONTROL_GENERATION",
    "COMMAND_SHADOW_SCHEMA_VERSION",
    "CommandShadowCohort",
    "CommandShadowComparison",
    "CommandShadowObservation",
)
