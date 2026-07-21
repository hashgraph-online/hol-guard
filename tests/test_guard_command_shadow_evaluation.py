"""Deterministic command shadow evaluation and rollout-control tests."""

# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUntypedFunctionDecorator=false

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION,
    COMMAND_SHADOW_DISABLED_COHORTS_ENV,
    COMMAND_SHADOW_ENABLED_ENV,
    COMMAND_SHADOW_KILL_SWITCH_ENV,
    COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV,
    CommandShadowCohort,
    CommandShadowComparison,
    CommandShadowProposal,
    baseline_command_shadow_proposal,
    build_command_shadow_observation,
    load_command_shadow_control,
)
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition

_OCCURRED_AT = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _evaluation():
    evaluation = evaluate_command("git push origin release/2.2 --force")
    assert evaluation.matches
    return evaluation


def test_baseline_records_distinct_authoritative_current_and_proposed_facts() -> None:
    evaluation = _evaluation()
    observation = build_command_shadow_observation(
        evaluation,
        authoritative_action="allow",
        proposal=baseline_command_shadow_proposal(evaluation),
        activity_id="activity:baseline",
        occurred_at=_OCCURRED_AT,
        control=load_command_shadow_control({}),
    )

    assert observation is not None
    assert observation.authoritative_action == "allow"
    assert observation.current_action == evaluation.decision_plane.action
    assert observation.proposed_action == evaluation.decision_plane.action
    assert observation.comparison is CommandShadowComparison.UNCHANGED
    assert observation.proposal_version == COMMAND_SHADOW_BASELINE_PROPOSAL_VERSION
    assert observation.cohorts == (CommandShadowCohort.BASELINE,)


@pytest.mark.parametrize(
    ("action", "disposition", "comparison"),
    [
        ("allow", FinalDisposition.SILENT_VERIFIED, CommandShadowComparison.LOWERED),
        ("block", FinalDisposition.BLOCK, CommandShadowComparison.STRENGTHENED),
    ],
)
def test_comparison_uses_canonical_action_lattice(
    action: GuardAction,
    disposition: FinalDisposition,
    comparison: CommandShadowComparison,
) -> None:
    evaluation = _evaluation()
    proposal = CommandShadowProposal(
        decision=replace(evaluation.decision_plane, action=action, disposition=disposition),
        cohorts=frozenset({CommandShadowCohort.BASELINE}),
        version="proposal.test.v1",
    )

    observation = build_command_shadow_observation(
        evaluation,
        authoritative_action="review",
        proposal=proposal,
        activity_id=f"activity:{comparison.value}",
        occurred_at=_OCCURRED_AT,
        control=load_command_shadow_control({}),
    )

    assert observation is not None
    assert observation.comparison is comparison
    assert observation.authoritative_action == "review"


@pytest.mark.parametrize(
    "environment",
    [
        {COMMAND_SHADOW_ENABLED_ENV: "0"},
        {COMMAND_SHADOW_ENABLED_ENV: "invalid"},
        {COMMAND_SHADOW_KILL_SWITCH_ENV: "1"},
        {COMMAND_SHADOW_KILL_SWITCH_ENV: "invalid"},
        {COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV: "0"},
        {COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV: "10001"},
        {COMMAND_SHADOW_DISABLED_COHORTS_ENV: "baseline"},
        {COMMAND_SHADOW_DISABLED_COHORTS_ENV: "unknown-cohort"},
    ],
)
def test_disable_controls_and_malformed_values_fail_closed(environment: dict[str, str]) -> None:
    evaluation = _evaluation()

    assert (
        build_command_shadow_observation(
            evaluation,
            authoritative_action="review",
            proposal=baseline_command_shadow_proposal(evaluation),
            activity_id="activity:disabled",
            occurred_at=_OCCURRED_AT,
            control=load_command_shadow_control(environment),
        )
        is None
    )


def test_local_controls_cannot_enable_unreleased_cohorts() -> None:
    evaluation = _evaluation()
    proposal = CommandShadowProposal(
        decision=evaluation.decision_plane,
        cohorts=frozenset({CommandShadowCohort.VERIFIED_READS}),
        version="proposal.unreleased.v1",
    )

    assert (
        build_command_shadow_observation(
            evaluation,
            authoritative_action="review",
            proposal=proposal,
            activity_id="activity:unreleased",
            occurred_at=_OCCURRED_AT,
            control=load_command_shadow_control({}),
        )
        is None
    )


def test_sampling_is_deterministic_and_bounded() -> None:
    control = load_command_shadow_control({COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV: "5000"})
    cohorts = frozenset({CommandShadowCohort.BASELINE})

    first = control.selected_cohorts(proposal_cohorts=cohorts, activity_id="activity:sample")
    assert first == control.selected_cohorts(proposal_cohorts=cohorts, activity_id="activity:sample")
    assert first in {(), (CommandShadowCohort.BASELINE,)}


def test_proposal_version_is_bounded_and_canonical() -> None:
    evaluation = _evaluation()

    for version in ("a" * 129, "proposal..v1"):
        with pytest.raises(ValueError, match="stable identifier"):
            _ = CommandShadowProposal(
                decision=evaluation.decision_plane,
                cohorts=frozenset({CommandShadowCohort.BASELINE}),
                version=version,
            )
