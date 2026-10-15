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
