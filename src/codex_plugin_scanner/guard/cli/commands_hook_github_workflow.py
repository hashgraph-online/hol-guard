# pyright: reportPrivateUsage=false
"""Trusted GitHub workflow preparation for the command hook."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from ..config import GuardConfig
from ..models import GuardArtifact
from ..native_command_control_authority_io import (
    NativeCommandControlAuthorityUnavailableError,
    NativeCommandControlMutationRequiredError,
)
from ..native_github_workflow import GitHubWorkflowDescriptor, github_workflow_describe_native
from ..native_hook_decision import NativeHookDecisionError
from ..runtime.command_decision_adapter import effect_decision_to_dict
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot, extension_control_policy_version
from ..runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from ..runtime.github_workflow_runtime import (
    claim_resolved_github_workflow_authorization,
    github_workflow_capability_required,
    resolved_github_workflow_capability_preflight,
)
from ..runtime.native_command_evaluation import native_command_review, resolve_native_command_review
from ..store import GuardStore
from .commands_support_runtime_policy import (
    _runtime_artifact_command_action_floor,
    _runtime_hook_effective_policy_config,
)

_AUTHORITY_UNAVAILABLE = "native_github_workflow_authority_unavailable"
_EVALUATION_UNAVAILABLE = "native_github_workflow_evaluation_unavailable"


class GitHubWorkflowEvaluationUnavailableError(NativeHookDecisionError):
    """No resident evaluation for a claimed workflow approval.

    The hook pipeline answers it with the host outage response; Python never
    floors the decision itself.
    """


@dataclass(frozen=True)
class GitHubWorkflowHookState:
    artifact: GuardArtifact
    descriptor: GitHubWorkflowDescriptor | None
    approval_record: GitHubWorkflowApprovalRecord | None
    authorization_claimed: bool
    capability_required: bool


def prepare_github_workflow_hook_state(
    artifact: GuardArtifact,
    *,
    workspace: Path | None,
    guard_home: Path,
    config: GuardConfig,
    store: GuardStore,
    approval_request_id: str | None,
) -> GitHubWorkflowHookState:
    descriptor = _runtime_github_workflow_descriptor(artifact, workspace=workspace, config=config)
    record = descriptor.record if descriptor is not None else None
    if record is not None:
        metadata = dict(artifact.metadata)
        metadata["github_workflow_approval_record"] = record.to_dict()
        artifact = replace(artifact, metadata=metadata)
    required = approval_request_id is not None and github_workflow_capability_required(store, approval_request_id)
    if descriptor is None or approval_request_id is None:
        return GitHubWorkflowHookState(artifact, descriptor, record, False, required)
    if not resolved_github_workflow_capability_preflight(store, approval_request_id, descriptor):
        # No live capability to claim: the hook goes on without one and needs
        # no resident review for it.
        return GitHubWorkflowHookState(artifact, descriptor, record, False, required)
    try:
        authority = store.read_extension_control_authority_for_registry(
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            read_only=True,
        )
    except (NativeCommandControlAuthorityUnavailableError, NativeCommandControlMutationRequiredError):
        # A lease that is busy or needs a migration leaves this hook without a
        # reading, and nothing has been claimed yet: the host outage response.
        raise GitHubWorkflowEvaluationUnavailableError(_AUTHORITY_UNAVAILABLE) from None
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(authority)
    # The resident reviews the command before the claim, so a resident that
    # cannot answer never spends one of the approval's uses.
    review = native_command_review(
        artifact.command or "",
        guard_home=guard_home,
        cwd=workspace,
        extension_control_snapshot=snapshot,
    )
    if review is None:
        raise GitHubWorkflowEvaluationUnavailableError(_EVALUATION_UNAVAILABLE)
    if review.native.get("minimum_action") == "block":
        # A workflow proof never relaxes a resident block, so the claim could
        # not change this hook's answer: leave the use unspent.
        return GitHubWorkflowHookState(artifact, descriptor, record, False, required)
    authorization = claim_resolved_github_workflow_authorization(store, approval_request_id, descriptor)
    if authorization is None:
        return GitHubWorkflowHookState(artifact, descriptor, record, False, required)
    metadata = dict(artifact.metadata)
    evaluation = resolve_native_command_review(
        review,
        compatibility_action_class=_optional_string(metadata.get("action_class")),
        compatibility_reason=_optional_string(metadata.get("runtime_request_reason")),
        workflow_authorization=authorization,
    )
    if evaluation is None:
        raise GitHubWorkflowEvaluationUnavailableError(_EVALUATION_UNAVAILABLE)
    metadata["command_action_floor"] = evaluation.evaluation.decision_plane.action
    metadata["command_decision_plane"] = effect_decision_to_dict(evaluation.evaluation.decision_plane)
    return GitHubWorkflowHookState(replace(artifact, metadata=metadata), descriptor, record, True, required)


def github_workflow_approval_evidence(record: GitHubWorkflowApprovalRecord) -> dict[str, object]:
    return {"source": "github_workflow_approval_record", "record": record.to_dict()}


def claimed_approval_request_id(decision: Mapping[str, object]) -> str | None:
    approval_id = decision.get("approval_id")
    request_id = decision.get("request_id")
    revision = decision.get("_approval_authority_revision")
    if (
        isinstance(approval_id, str)
        and approval_id
        and isinstance(request_id, str)
        and request_id
        and isinstance(revision, int)
        and not isinstance(revision, bool)
        and revision >= 0
    ):
        return request_id
    return None


def _runtime_github_workflow_descriptor(
    artifact: GuardArtifact, *, workspace: Path | None, config: GuardConfig
) -> GitHubWorkflowDescriptor | None:
    if artifact.artifact_type != "tool_action_request" or artifact.command is None:
        return None
    return github_workflow_describe_native(
        artifact.command,
        workspace=workspace,
        config_path=artifact.config_path,
        configuration=_runtime_hook_effective_policy_config(config),
        sandbox={
            "analysis": config.sandbox_analysis,
            "required": _runtime_artifact_command_action_floor(artifact) == "sandbox-required",
        },
        policy_version=extension_control_policy_version("policy.v1"),
    )


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


__all__ = [
    "GitHubWorkflowEvaluationUnavailableError",
    "GitHubWorkflowHookState",
    "claimed_approval_request_id",
    "github_workflow_approval_evidence",
    "prepare_github_workflow_hook_state",
]
