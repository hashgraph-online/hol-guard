# pyright: reportPrivateUsage=false
"""Trusted GitHub workflow preparation for the command hook."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from ..config import GuardConfig
from ..models import GuardArtifact
from ..runtime.command_decision_adapter import effect_decision_to_dict
from ..runtime.command_evaluation import evaluate_command
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_contract import ControlSurface
from ..runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from ..runtime.github_workflow_context import GitHubWorkflowDescriptor, build_github_workflow_descriptor
from ..runtime.github_workflow_runtime import (
    claim_resolved_github_workflow_authorization,
    github_workflow_capability_required,
)
from ..store import GuardStore
from .commands_support_runtime_policy import (
    _runtime_artifact_command_action_floor,
    _runtime_hook_effective_policy_config,
)


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
    config: GuardConfig,
    store: GuardStore,
    approval_request_id: str | None,
) -> GitHubWorkflowHookState:
    descriptor = _runtime_github_workflow_descriptor(artifact, workspace=workspace, config=config)
    record = GitHubWorkflowApprovalRecord.from_descriptor(descriptor) if descriptor is not None else None
    if record is not None:
        metadata = dict(artifact.metadata)
        metadata["github_workflow_approval_record"] = record.to_dict()
        artifact = replace(artifact, metadata=metadata)
    required = approval_request_id is not None and github_workflow_capability_required(store, approval_request_id)
    if descriptor is None or approval_request_id is None:
        return GitHubWorkflowHookState(artifact, descriptor, record, False, required)
    authorization = claim_resolved_github_workflow_authorization(store, approval_request_id, descriptor)
    if authorization is None:
        return GitHubWorkflowHookState(artifact, descriptor, record, False, required)
    metadata = dict(artifact.metadata)
    extension_control_layers = store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    ).layers_for(ControlSurface.COMMAND_EVALUATION)
    evaluation = evaluate_command(
        artifact.command or "",
        compatibility_action_class=_optional_string(metadata.get("action_class")),
        compatibility_reason=_optional_string(metadata.get("runtime_request_reason")),
        cwd=workspace,
        workflow_authorization=authorization,
        extension_control_layers=extension_control_layers,
    )
    metadata["command_action_floor"] = evaluation.decision_plane.action
    metadata["command_decision_plane"] = effect_decision_to_dict(evaluation.decision_plane)
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
    return build_github_workflow_descriptor(
        artifact.command,
        workspace=workspace,
        config_path=artifact.config_path,
        configuration=_runtime_hook_effective_policy_config(config),
        sandbox={
            "analysis": config.sandbox_analysis,
            "required": _runtime_artifact_command_action_floor(artifact) == "sandbox-required",
        },
    )


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


__all__ = [
    "GitHubWorkflowHookState",
    "claimed_approval_request_id",
    "github_workflow_approval_evidence",
    "prepare_github_workflow_hook_state",
]
