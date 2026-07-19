"""User-facing interaction mapping for classified GitHub capabilities."""

from __future__ import annotations

from typing import Final

from .github_capability_contract import GitHubCommandAssessment, GitHubCommandCapability

_ACTION_CLASSES: Final[dict[GitHubCommandCapability, str]] = {
    "maintain_remote": "GitHub bounded maintenance command",
    "content_remote": "GitHub content mutation command",
    "merge_remote": "GitHub merge command",
    "publish_remote": "GitHub release publication command",
    "workflow_remote": "GitHub workflow mutation command",
    "force_remote": "GitHub force mutation command",
    "delete_remote": "GitHub delete command",
    "secret_remote": "GitHub secret mutation command",
    "access_remote": "GitHub access mutation command",
    "mutate_remote": "GitHub remote mutation command",
    "write_local": "GitHub local configuration write",
    "unknown": "Unverified GitHub command capability",
}


def github_capability_requires_confirmation(assessment: GitHubCommandAssessment) -> bool:
    return assessment.action_floor != "allow"


def github_capability_action_class(assessment: GitHubCommandAssessment) -> str:
    if not github_capability_requires_confirmation(assessment):
        raise ValueError("read-only GitHub capabilities do not have review action classes")
    return _ACTION_CLASSES[assessment.capability]
