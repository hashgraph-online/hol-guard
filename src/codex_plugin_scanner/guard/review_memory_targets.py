"""Exact signed memory target projection for local matchers."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .exact_command_policy import exact_command_policy_digest
from .project_identity import is_portable_project_identity
from .review_oauth_binding import GuardReviewContractError, GuardReviewOAuthMetadata

_MAX_MEMORY_TARGET_IDS = 50


def _text_ids(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise GuardReviewContractError("decision_memory_target_invalid")
    if len(value) > _MAX_MEMORY_TARGET_IDS:
        raise GuardReviewContractError("decision_memory_target_partial")
    items = [str(item).strip() for item in value if isinstance(item, str) and str(item).strip()]
    if len(items) != len(value):
        raise GuardReviewContractError("decision_memory_target_invalid")
    return tuple(items)


def validate_exact_memory_target(
    target: Mapping[str, object],
    *,
    oauth: GuardReviewOAuthMetadata,
    project_identity: str | None = None,
) -> None:
    """Accept signed Cloud target arrays and refuse only unrepresentable projections."""

    workspace_ids = _text_ids(target.get("workspaceIds"))
    machine_ids = _text_ids(target.get("machineIds"))
    project_ids = _text_ids(target.get("projectIds"))
    if workspace_ids and oauth.workspace_id not in workspace_ids:
        raise GuardReviewContractError("decision_memory_workspace_mismatch")
    if machine_ids and oauth.installation_id not in machine_ids:
        raise GuardReviewContractError("decision_memory_machine_mismatch")
    if project_ids and (project_identity is None or project_identity not in project_ids):
        raise GuardReviewContractError("decision_memory_project_mismatch")


def local_memory_match_fields(
    target: Mapping[str, object],
    *,
    oauth: GuardReviewOAuthMetadata,
    project_identity: str | None,
    action: str | None = None,
    scope: str | None = None,
) -> tuple[str | None, str | None]:
    """Return matcher fields the local resolver actually compares.

    Workspace stays a real workspace or portable project identity. Machine
    membership is enforced at apply time, not encoded into the workspace key.
    Portable identities can carry restrictive decisions only.
    """

    _ = oauth
    project_ids = _text_ids(target.get("projectIds"))
    chosen: str | None = None
    if project_ids:
        if project_identity and project_identity in project_ids:
            chosen = project_identity
        elif len(project_ids) == 1:
            chosen = project_ids[0]
        else:
            raise GuardReviewContractError("decision_memory_target_partial")
    elif project_identity and is_portable_project_identity(project_identity):
        chosen = project_identity
    if scope == "project" and chosen is None:
        chosen = project_identity
    if (
        chosen is not None
        and action == "allow"
        and (is_portable_project_identity(chosen) or not Path(chosen).is_absolute())
    ):
        raise GuardReviewContractError("decision_memory_project_allow_unsupported")
    if scope == "project" and chosen is None:
        raise GuardReviewContractError("decision_memory_project_scope_unsupported")
    return chosen, None


__all__ = ["local_memory_match_fields", "validate_exact_memory_target"]


def validate_memory_rule_target_exact(
    target: dict[str, object],
    *,
    oauth: GuardReviewOAuthMetadata,
    rule: dict[str, object],
) -> None:
    if "exactCommand" in rule:
        try:
            _ = exact_command_policy_digest(rule["exactCommand"], rule.get("artifactId"), scope=rule.get("scope"))
        except ValueError as error:
            raise GuardReviewContractError("invalid_decision_memory_exact_command") from error
    value = rule.get("projectIdentity")
    project_identity = value if isinstance(value, str) and value.strip() else None
    validate_exact_memory_target(target, oauth=oauth, project_identity=project_identity)
