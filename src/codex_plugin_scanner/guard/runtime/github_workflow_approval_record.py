"""Privacy-safe persisted evidence for GitHub workflow approvals."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from ..workflow_capabilities import (
    WorkflowCapabilityBinding,
    WorkflowCapabilityError,
    canonical_framed_payload,
)
from .github_workflow_authorization import build_github_workflow_binding
from .github_workflow_context import GitHubWorkflowDescriptor

GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA: Final = "guard.github-workflow-approval-record.v1"


@dataclass(frozen=True, slots=True)
class GitHubWorkflowApprovalRecord:
    schema_version: str
    operation_kind: str
    resource_type: str
    command_identity_sha256: str
    operation_digest_sha256: str
    binding: WorkflowCapabilityBinding

    def __post_init__(self) -> None:
        if self.schema_version != GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA:
            raise ValueError("unsupported GitHub workflow approval record")
        if self.operation_kind not in {
            "resolve-review-thread",
            "unresolve-review-thread",
            "lock-issue",
            "unlock-issue",
            "pin-issue",
            "unpin-issue",
            "lock-pr",
            "unlock-pr",
            "mark-pr-ready",
            "mark-pr-draft",
        }:
            raise ValueError("invalid GitHub workflow operation kind")
        if self.resource_type not in {"github-review-thread", "github-issue", "github-pr"}:
            raise ValueError("invalid GitHub workflow resource type")
        if self.binding.operation_id != f"github.{self.operation_kind}.v1":
            raise ValueError("GitHub workflow operation binding mismatch")
        if self.binding.resource_type != self.resource_type:
            raise ValueError("GitHub workflow resource binding mismatch")
        _validate_sha256(self.command_identity_sha256)
        _validate_sha256(self.operation_digest_sha256)

    @classmethod
    def from_descriptor(cls, descriptor: GitHubWorkflowDescriptor) -> GitHubWorkflowApprovalRecord:
        operation = descriptor.operation
        return cls(
            schema_version=GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA,
            operation_kind=operation.kind,
            resource_type=operation.resource_type,
            command_identity_sha256=_digest("github-workflow-command-identity", operation.command_identity),
            operation_digest_sha256=_digest("github-workflow-operation-digest", operation.operation_digest),
            binding=build_github_workflow_binding(operation, descriptor.binding_context),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GitHubWorkflowApprovalRecord:
        expected = {
            "schema_version",
            "operation_kind",
            "resource_type",
            "command_identity_sha256",
            "operation_digest_sha256",
            "binding",
        }
        if set(payload) != expected:
            raise ValueError("invalid GitHub workflow approval record shape")
        binding = payload["binding"]
        return cls(
            schema_version=_required_string(payload, "schema_version"),
            operation_kind=_required_string(payload, "operation_kind"),
            resource_type=_required_string(payload, "resource_type"),
            command_identity_sha256=_required_string(payload, "command_identity_sha256"),
            operation_digest_sha256=_required_string(payload, "operation_digest_sha256"),
            binding=WorkflowCapabilityBinding.from_dict(binding),
        )

    def to_dict(self) -> dict[str, object]:
        binding = self.binding
        return {
            "schema_version": self.schema_version,
            "operation_kind": self.operation_kind,
            "resource_type": self.resource_type,
            "command_identity_sha256": self.command_identity_sha256,
            "operation_digest_sha256": self.operation_digest_sha256,
            "binding": {
                "operation_id": binding.operation_id,
                "resource_type": binding.resource_type,
                "resource_sha256": binding.resource_sha256,
                "repository_sha256": binding.repository_sha256,
                "workspace_sha256": binding.workspace_sha256,
                "executable_sha256": binding.executable_sha256,
                "launch_sha256": binding.launch_sha256,
                "policy_id": binding.policy_id,
                "policy_version": binding.policy_version,
                "effect_id": binding.effect_id,
                "effect_version": binding.effect_version,
                "decision_id": binding.decision_id,
                "decision_version": binding.decision_version,
                "rules": [{"rule_id": rule.rule_id, "rule_version": rule.rule_version} for rule in binding.rules],
            },
        }

    def matches_descriptor(self, descriptor: GitHubWorkflowDescriptor) -> bool:
        try:
            candidate = GitHubWorkflowApprovalRecord.from_descriptor(descriptor)
            return hmac.compare_digest(
                _digest("github-workflow-approval-record", self.to_dict()),
                _digest("github-workflow-approval-record", candidate.to_dict()),
            )
        except (TypeError, ValueError, WorkflowCapabilityError):
            return False


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {key}")
    return value


def _validate_sha256(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("invalid GitHub workflow approval digest")


def _digest(purpose: str, payload: object) -> str:
    return hashlib.sha256(canonical_framed_payload(purpose, payload)).hexdigest()


__all__ = (
    "GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA",
    "GitHubWorkflowApprovalRecord",
)
