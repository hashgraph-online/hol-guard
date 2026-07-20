"""User-facing interaction mapping for classified GitHub capabilities."""

from __future__ import annotations

from .github_capability_contract import GitHubCommandAssessment, github_capability_contract


def github_capability_requires_confirmation(assessment: GitHubCommandAssessment) -> bool:
    return assessment.action_floor != "allow"


def github_capability_action_class(assessment: GitHubCommandAssessment) -> str:
    if not github_capability_requires_confirmation(assessment):
        raise ValueError("read-only GitHub capabilities do not have review action classes")
    action_class = github_capability_contract(assessment.capability).action_class
    if action_class is None:
        raise ValueError("reviewed GitHub capability is missing an action class")
    return action_class
