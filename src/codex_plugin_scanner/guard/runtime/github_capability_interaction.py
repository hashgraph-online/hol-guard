"""User-facing interaction mapping for classified GitHub capabilities."""

from __future__ import annotations

from typing import Final

from .github_capability_contract import GitHubCommandAssessment, github_capability_contract

_maintenance_action_class = github_capability_contract("maintain_remote").action_class
if _maintenance_action_class is None:
    raise RuntimeError("GitHub maintenance capability is missing an action class")
GITHUB_MAINTENANCE_ACTION_CLASS: Final = _maintenance_action_class


def github_capability_requires_confirmation(assessment: GitHubCommandAssessment) -> bool:
    return assessment.action_floor != "allow"


def github_capability_action_class(assessment: GitHubCommandAssessment) -> str:
    if not github_capability_requires_confirmation(assessment):
        raise ValueError("read-only GitHub capabilities do not have review action classes")
    capability = "admin_merge_remote" if "admin_merge_remote" in assessment.capabilities else assessment.capability
    action_class = github_capability_contract(capability).action_class
    if action_class is None:
        raise ValueError("reviewed GitHub capability is missing an action class")
    return action_class
