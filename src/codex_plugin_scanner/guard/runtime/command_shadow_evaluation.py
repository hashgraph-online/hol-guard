"""Privacy-safe shadow comparison for the central command decision plane."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Final, cast

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from codex_plugin_scanner.guard.models import GuardAction

from .command_evaluation import CompositeCommandEvaluation
from .effect_decision import EFFECT_DECISION_SCHEMA_VERSION, EffectDecision, FinalDisposition

COMMAND_SHADOW_SCHEMA_VERSION: Final = "guard.command-shadow.v1"
COMMAND_SHADOW_CONTROL_SCHEMA_VERSION: Final = "guard.command-shadow-control.v1"
COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION: Final = "guard.command-shadow-proposal.baseline.v1"
COMMAND_SHADOW_CONTROL_GENERATION: Final = 1
COMMAND_SHADOW_ENABLED_ENV: Final = "HOL_GUARD_DECISION_SHADOW_ENABLED"
COMMAND_SHADOW_KILL_SWITCH_ENV: Final = "HOL_GUARD_DECISION_SHADOW_KILL_SWITCH"
COMMAND_SHADOW_DISABLED_COHORTS_ENV: Final = "HOL_GUARD_DECISION_SHADOW_DISABLED_COHORTS"
COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV: Final = "HOL_GUARD_DECISION_SHADOW_SAMPLE_BASIS_POINTS"

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
class CommandShadowControl:
    enabled: bool
    kill_switch: bool
    release_cohorts: frozenset[CommandShadowCohort]
    disabled_cohorts: frozenset[CommandShadowCohort]
    sample_basis_points: int
    generation: int = COMMAND_SHADOW_CONTROL_GENERATION
    schema_version: str = COMMAND_SHADOW_CONTROL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or type(self.kill_switch) is not bool:
            raise ValueError("shadow enable and kill-switch controls must be booleans")
        _require_cohorts(self.release_cohorts, "release_cohorts")
        _require_cohorts(self.disabled_cohorts, "disabled_cohorts")
        if type(self.sample_basis_points) is not int or not 0 <= self.sample_basis_points <= _BASIS_POINTS_MAX:
            raise ValueError("sample_basis_points must be between 0 and 10000")
        if self.generation != COMMAND_SHADOW_CONTROL_GENERATION:
            raise ValueError("unsupported shadow control generation")
        if self.schema_version != COMMAND_SHADOW_CONTROL_SCHEMA_VERSION:
            raise ValueError("unsupported shadow control schema version")

    def selected_cohorts(
        self,
        *,
        proposal_cohorts: frozenset[CommandShadowCohort],
        activity_id: str,
    ) -> tuple[CommandShadowCohort, ...]:
        if not self.enabled or self.kill_switch or self.sample_basis_points == 0:
            return ()
        selected = proposal_cohorts & (self.release_cohorts - self.disabled_cohorts)
        return tuple(
            cohort
            for cohort in sorted(selected, key=lambda item: item.value)
            if _sample_bucket(cohort, activity_id) < self.sample_basis_points
        )


@dataclass(frozen=True, slots=True)
class CommandShadowProposal:
    decision: EffectDecision
    cohorts: frozenset[CommandShadowCohort]
    version: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.decision), EffectDecision):
            raise ValueError("decision must be an EffectDecision")
        _require_cohorts(self.cohorts, "cohorts")
        if not self.cohorts:
            raise ValueError("a shadow proposal must name at least one release cohort")
        if (
            not isinstance(cast(object, self.version), str)
            or len(self.version) > 128
            or _PROPOSAL_VERSION.fullmatch(self.version) is None
        ):
            raise ValueError("proposal version must be a stable identifier")


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


def load_command_shadow_control(environ: Mapping[str, str] | None = None) -> CommandShadowControl:
    """Load strict observation-only rollout controls; malformed input disables recording."""

    source = os.environ if environ is None else environ
    enabled = _strict_flag(source.get(COMMAND_SHADOW_ENABLED_ENV), default=True, invalid=False)
    kill_switch = _strict_flag(source.get(COMMAND_SHADOW_KILL_SWITCH_ENV), default=False, invalid=True)
    disabled_cohorts = _cohort_set(source.get(COMMAND_SHADOW_DISABLED_COHORTS_ENV), default=frozenset())
    sample_basis_points = _sample_basis_points(source.get(COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV))
    return CommandShadowControl(
        enabled=enabled,
        kill_switch=kill_switch,
        release_cohorts=frozenset({CommandShadowCohort.BASELINE}),
        disabled_cohorts=disabled_cohorts,
        sample_basis_points=sample_basis_points,
    )


def build_command_shadow_observation(
    evaluation: CompositeCommandEvaluation,
    *,
    authoritative_action: GuardAction,
    proposal: CommandShadowProposal,
    activity_id: str,
    occurred_at: datetime,
    control: CommandShadowControl,
) -> CommandShadowObservation | None:
    """Build a comparison record while binding enforcement to the current action."""

    if not isinstance(cast(object, evaluation), CompositeCommandEvaluation):
        raise ValueError("evaluation must be a CompositeCommandEvaluation")
    if not is_guard_action(authoritative_action):
        raise ValueError("authoritative_action must be a canonical GuardAction")
    if not isinstance(cast(object, proposal), CommandShadowProposal):
        raise ValueError("proposal must be a CommandShadowProposal")
    if not isinstance(cast(object, control), CommandShadowControl):
        raise ValueError("control must be a CommandShadowControl")
    selected_cohorts = control.selected_cohorts(proposal_cohorts=proposal.cohorts, activity_id=activity_id)
    if not evaluation.matches or not selected_cohorts:
        return None
    current = evaluation.decision_plane
    proposed = proposal.decision
    return CommandShadowObservation(
        activity_id=activity_id,
        occurred_at=occurred_at,
        cohorts=selected_cohorts,
        authoritative_action=authoritative_action,
        current_action=current.action,
        current_disposition=current.disposition,
        proposed_action=proposed.action,
        proposed_disposition=proposed.disposition,
        comparison=_comparison(current.action, proposed.action),
        proposal_version=proposal.version,
        evaluator_schema_version=proposed.schema_version,
        control_generation=control.generation,
        sample_basis_points=control.sample_basis_points,
    )


def baseline_command_shadow_proposal(evaluation: CompositeCommandEvaluation) -> CommandShadowProposal:
    """Return the release baseline proposal without changing the current evaluator."""

    if not isinstance(cast(object, evaluation), CompositeCommandEvaluation):
        raise ValueError("evaluation must be a CompositeCommandEvaluation")
    return CommandShadowProposal(
        decision=evaluation.decision_plane,
        cohorts=frozenset({CommandShadowCohort.BASELINE}),
        version=COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
    )


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


def _sample_bucket(cohort: CommandShadowCohort, activity_id: str) -> int:
    if not isinstance(cast(object, activity_id), str) or _ACTIVITY_ID.fullmatch(activity_id) is None:
        raise ValueError("activity_id must be an opaque identifier")
    framed = f"{len(cohort.value)}:{cohort.value}{len(activity_id)}:{activity_id}".encode("ascii")
    return int.from_bytes(hashlib.sha256(framed).digest(), "big") % _BASIS_POINTS_MAX


def _strict_flag(raw: str | None, *, default: bool, invalid: bool) -> bool:
    if raw is None:
        return default
    if raw == "1":
        return True
    if raw == "0":
        return False
    return invalid


def _cohort_set(raw: str | None, *, default: frozenset[CommandShadowCohort]) -> frozenset[CommandShadowCohort]:
    if raw is None:
        return default
    values = raw.split(",") if raw else []
    try:
        return frozenset(CommandShadowCohort(value) for value in values)
    except ValueError:
        return frozenset(CommandShadowCohort)


def _sample_basis_points(raw: str | None) -> int:
    if raw is None:
        return _BASIS_POINTS_MAX
    try:
        parsed = int(raw)
    except ValueError:
        return 0
    return parsed if 0 <= parsed <= _BASIS_POINTS_MAX else 0


def _require_cohorts(value: object, field_name: str) -> None:
    if not isinstance(value, frozenset) or any(not isinstance(item, CommandShadowCohort) for item in value):
        raise ValueError(f"{field_name} must contain exact CommandShadowCohort values")


__all__ = (
    "COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION",
    "COMMAND_SHADOW_CONTROL_GENERATION",
    "COMMAND_SHADOW_CONTROL_SCHEMA_VERSION",
    "COMMAND_SHADOW_SCHEMA_VERSION",
    "CommandShadowCohort",
    "CommandShadowComparison",
    "CommandShadowControl",
    "CommandShadowObservation",
    "CommandShadowProposal",
    "baseline_command_shadow_proposal",
    "build_command_shadow_observation",
    "load_command_shadow_control",
)
