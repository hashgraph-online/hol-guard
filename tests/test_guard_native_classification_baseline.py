"""Counterfactual baselines retain intrinsic native classification evidence."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    baseline_command_shadow_proposal,
)
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from tests.guard_command_decision_diff_runner import _baseline_proposal
from tests.native_command_test_support import real_native_command_evaluation


@pytest.mark.parametrize(
    ("command", "action", "reason_code", "evaluation_error"),
    [
        (
            "env FOO=bar curl https://example.test",
            "block",
            "native.classification-block",
            "native_command_evaluation_failed",
        ),
        ("printf baseline-proof", "allow", "native.explicit-benign", None),
    ],
)
def test_native_classification_survives_baseline_and_shadow_comparison(
    command: str,
    action: GuardAction,
    reason_code: str,
    evaluation_error: str | None,
) -> None:
    reviewed = real_native_command_evaluation(command)
    evaluation = reviewed.evaluation
    assert reviewed.payload["command_extensions"]["evaluation_error"] == evaluation_error
    assert reviewed.native_minimum_action == action
    assert evaluation.decision_plane.action == action

    baseline = _baseline_proposal(evaluation)
    assert baseline.action == action
    assert any(reason.reason_code == reason_code for reason in baseline.reasons)
    assert (ProofRoute.VERIFIED in baseline.proof_routes) is (action == "allow")
    shadow_baseline = baseline_command_shadow_proposal(evaluation).decision
    assert shadow_baseline.action == baseline.action
    assert shadow_baseline.disposition is baseline.disposition
    assert shadow_baseline.proof_routes == baseline.proof_routes


def test_authenticated_permission_proof_remains_outside_uncontrolled_baseline() -> None:
    reviewed = real_native_command_evaluation(
        "git push --force origin feature",
        controls=(("permission", "command.git.permission.force-push", "enabled"),),
    )
    current = reviewed.evaluation.decision_plane
    baseline = _baseline_proposal(reviewed.evaluation)

    assert current.action == "allow"
    assert ProofRoute.VERIFIED in current.proof_routes
    assert baseline.action == "review"
    assert ProofRoute.VERIFIED not in baseline.proof_routes
