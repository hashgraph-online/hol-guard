"""Issue and atomically claim exact GitHub workflow capabilities."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import asdict, dataclass
from typing import Final, Protocol

from typing_extensions import override

from ..workflow_capabilities import (
    WORKFLOW_CAPABILITY_ALGORITHM,
    WORKFLOW_CAPABILITY_SCHEMA,
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityBinding,
    WorkflowCapabilityClaim,
    WorkflowCapabilityError,
    WorkflowCapabilityRuleBinding,
    canonical_framed_payload,
    sign_workflow_capability,
)
from .effect_contract import ProofRequirement, ProofRoute
from .effect_decision import PositiveProof
from .github_capability_interaction import GITHUB_MAINTENANCE_ACTION_CLASS
from .github_workflow_operations import GitHubWorkflowOperation

_AUTHORIZATION_SEAL: Final = object()
_REPOSITORY = re.compile(r"[a-z0-9_.-]+/[a-z0-9_.-]+")
_GITHUB_MAINTENANCE_EFFECT_ID: Final = "github.maintain-remote"
_GITHUB_WORKFLOW_DECISION_ID: Final = "github.workflow-authorized"


class WorkflowCapabilityStore(Protocol):
    def issue_workflow_capability(
        self, signed: SignedWorkflowCapability, *, approval_provenance_id: str
    ) -> SignedWorkflowCapability: ...

    def claim_workflow_capability(
        self,
        capability_id: str,
        *,
        invocation_id: str,
        expected_binding: WorkflowCapabilityBinding,
        expected_subject_id: str,
        expected_task_id: str,
        expected_issuer_id: str,
        expected_approval_provenance_id: str,
    ) -> SignedWorkflowCapabilityReceipt: ...


@dataclass(frozen=True, slots=True)
class GitHubWorkflowBindingContext:
    repository_sha256: str
    workspace_sha256: str
    executable_sha256: str
    cwd_sha256: str
    environment_sha256: str
    configuration_sha256: str
    manifest_sha256: str
    lockfile_sha256: str
    sandbox_sha256: str
    policy_id: str
    policy_version: str
    effect_id: str
    effect_version: str
    decision_id: str
    decision_version: str
    rules: tuple[WorkflowCapabilityRuleBinding, ...]


@dataclass(frozen=True, slots=True, init=False, repr=False)
class GitHubWorkflowAuthorization:
    _operation_identity: str
    _compatibility_action_class: str
    _proof: PositiveProof
    _receipt_sha256: str
    _seal: object

    def __init__(
        self,
        *,
        authority_token: object,
        operation: GitHubWorkflowOperation,
        proof: PositiveProof,
        receipt_sha256: str,
    ) -> None:
        if authority_token is not _AUTHORIZATION_SEAL:
            raise TypeError("GitHub workflow authorization requires an atomic Guard claim")
        object.__setattr__(self, "_operation_identity", operation.command_identity)
        object.__setattr__(
            self,
            "_compatibility_action_class",
            GITHUB_MAINTENANCE_ACTION_CLASS,
        )
        object.__setattr__(self, "_proof", proof)
        object.__setattr__(self, "_receipt_sha256", receipt_sha256)
        object.__setattr__(self, "_seal", _AUTHORIZATION_SEAL)

    @override
    def __repr__(self) -> str:
        receipt = getattr(self, "_receipt_sha256", "invalid")
        return f"GitHubWorkflowAuthorization(receipt_sha256={receipt!r})"

    def evidence(self, *, command_identity: str) -> tuple[PositiveProof, str] | None:
        try:
            if self._seal is not _AUTHORIZATION_SEAL:
                return None
            if not hmac.compare_digest(self._operation_identity, command_identity):
                return None
            if len(self._receipt_sha256) != 64:
                return None
            return self._proof, self._compatibility_action_class
        except (AttributeError, TypeError, ValueError):
            return None


def build_github_workflow_binding(
    operation: GitHubWorkflowOperation,
    context: GitHubWorkflowBindingContext,
) -> WorkflowCapabilityBinding:
    _validate_github_workflow_binding_context(context)
    expected_repository_sha256 = github_repository_sha256(operation.repository)
    if not hmac.compare_digest(context.repository_sha256, expected_repository_sha256):
        raise WorkflowCapabilityError("github_workflow_repository_mismatch")
    launch_sha256 = _framed_sha256(
        "github-workflow-launch",
        {
            "command_identity": operation.command_identity,
            "configuration_sha256": context.configuration_sha256,
            "cwd_sha256": context.cwd_sha256,
            "environment_sha256": context.environment_sha256,
            "lockfile_sha256": context.lockfile_sha256,
            "manifest_sha256": context.manifest_sha256,
            "sandbox_sha256": context.sandbox_sha256,
        },
    )
    return WorkflowCapabilityBinding(
        operation_id=f"github.{operation.kind}.v1",
        resource_type=operation.resource_type,
        resource_sha256=_framed_sha256("github-workflow-resource", operation.resource_id),
        repository_sha256=context.repository_sha256,
        workspace_sha256=context.workspace_sha256,
        executable_sha256=context.executable_sha256,
        launch_sha256=launch_sha256,
        policy_id=context.policy_id,
        policy_version=context.policy_version,
        effect_id=context.effect_id,
        effect_version=context.effect_version,
        decision_id=context.decision_id,
        decision_version=context.decision_version,
        rules=context.rules,
    )


def issue_github_workflow_capability(
    store: WorkflowCapabilityStore,
    operation: GitHubWorkflowOperation,
    context: GitHubWorkflowBindingContext,
    *,
    capability_id: str,
    approval_provenance_id: str,
    task_id: str,
    nonce: str,
    issuer_id: str,
    subject_id: str,
    issued_at: str,
    not_before: str,
    expires_at: str,
    max_uses: int,
    key: bytes,
    key_id: str,
) -> SignedWorkflowCapability:
    return issue_github_workflow_capability_binding(
        store,
        build_github_workflow_binding(operation, context),
        capability_id=capability_id,
        approval_provenance_id=approval_provenance_id,
        task_id=task_id,
        nonce=nonce,
        issuer_id=issuer_id,
        subject_id=subject_id,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
        max_uses=max_uses,
        key=key,
        key_id=key_id,
    )


def issue_github_workflow_capability_binding(
    store: WorkflowCapabilityStore,
    binding: WorkflowCapabilityBinding,
    *,
    capability_id: str,
    approval_provenance_id: str,
    task_id: str,
    nonce: str,
    issuer_id: str,
    subject_id: str,
    issued_at: str,
    not_before: str,
    expires_at: str,
    max_uses: int,
    key: bytes,
    key_id: str,
) -> SignedWorkflowCapability:
    claim = WorkflowCapabilityClaim(
        schema_version=WORKFLOW_CAPABILITY_SCHEMA,
        algorithm=WORKFLOW_CAPABILITY_ALGORITHM,
        capability_id=capability_id,
        approval_provenance_id=approval_provenance_id,
        task_id=task_id,
        nonce=nonce,
        issuer_id=issuer_id,
        subject_id=subject_id,
        binding=binding,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
        max_uses=max_uses,
    )
    signed = sign_workflow_capability(claim, key=key, key_id=key_id)
    return store.issue_workflow_capability(signed, approval_provenance_id=approval_provenance_id)


def claim_github_workflow_authorization(
    store: WorkflowCapabilityStore,
    capability_id: str,
    operation: GitHubWorkflowOperation,
    context: GitHubWorkflowBindingContext,
    *,
    invocation_id: str,
    subject_id: str,
    task_id: str,
    issuer_id: str,
    approval_provenance_id: str,
) -> GitHubWorkflowAuthorization:
    binding = build_github_workflow_binding(operation, context)
    receipt = store.claim_workflow_capability(
        capability_id,
        invocation_id=invocation_id,
        expected_binding=binding,
        expected_subject_id=subject_id,
        expected_task_id=task_id,
        expected_issuer_id=issuer_id,
        expected_approval_provenance_id=approval_provenance_id,
    )
    if type(receipt) is not SignedWorkflowCapabilityReceipt:
        raise WorkflowCapabilityError("invalid_github_workflow_receipt")
    claimed = receipt.receipt
    if (
        claimed.binding != binding
        or claimed.capability_id != capability_id
        or claimed.invocation_id != invocation_id
        or claimed.task_id != task_id
        or claimed.approval_provenance_id != approval_provenance_id
    ):
        raise WorkflowCapabilityError("github_workflow_receipt_mismatch")
    receipt_sha256 = _framed_sha256("github-workflow-receipt", receipt.to_dict())
    return GitHubWorkflowAuthorization(
        authority_token=_AUTHORIZATION_SEAL,
        operation=operation,
        receipt_sha256=receipt_sha256,
        proof=PositiveProof(
            route=ProofRoute.WORKFLOW_AUTHORIZED,
            binding_digest=_framed_sha256(
                "github-workflow-claimed-binding",
                {"binding": asdict(binding), "receipt_sha256": receipt_sha256},
            ),
            satisfied_requirements=frozenset(
                {
                    ProofRequirement.OPERATION_AND_TARGETS,
                    ProofRequirement.REMOTE_RESOURCE_IDENTITY,
                    ProofRequirement.REPOSITORY_IDENTITY,
                    ProofRequirement.WORKSPACE_IDENTITY,
                    ProofRequirement.WORKING_DIRECTORY_IDENTITY,
                    ProofRequirement.EXECUTABLE_IDENTITY,
                    ProofRequirement.LAUNCH_CHAIN,
                    ProofRequirement.CONFIGURATION_IDENTITY,
                    ProofRequirement.DEPENDENCY_PROVENANCE,
                    ProofRequirement.PARSER_CONFIDENCE,
                    ProofRequirement.EXPECTED_EFFECTS,
                    ProofRequirement.CAPABILITY_CONSTRAINTS,
                }
            ),
        ),
    )


def github_workflow_authorization_evidence(
    authorization: GitHubWorkflowAuthorization | None,
    *,
    command_identity: str,
) -> tuple[PositiveProof, str] | None:
    """Return sealed claimed proof only for the exact canonical command."""

    if type(authorization) is not GitHubWorkflowAuthorization:
        return None
    return authorization.evidence(command_identity=command_identity)


def github_repository_sha256(repository: str) -> str:
    normalized = repository.strip().lower()
    if normalized != repository or _REPOSITORY.fullmatch(normalized) is None:
        raise WorkflowCapabilityError("invalid_github_workflow_repository")
    return _framed_sha256("github-workflow-repository", normalized)


def _validate_github_workflow_binding_context(context: GitHubWorkflowBindingContext) -> None:
    if context.effect_id != _GITHUB_MAINTENANCE_EFFECT_ID:
        raise WorkflowCapabilityError("github_workflow_effect_mismatch")
    if context.decision_id != _GITHUB_WORKFLOW_DECISION_ID:
        raise WorkflowCapabilityError("github_workflow_decision_mismatch")
    if len(context.rules) != 1 or context.rules[0].rule_id != _GITHUB_MAINTENANCE_EFFECT_ID:
        raise WorkflowCapabilityError("github_workflow_rule_mismatch")


def _framed_sha256(purpose: str, payload: object) -> str:
    return hashlib.sha256(canonical_framed_payload(purpose, payload)).hexdigest()


__all__ = (
    "GitHubWorkflowAuthorization",
    "GitHubWorkflowBindingContext",
    "build_github_workflow_binding",
    "claim_github_workflow_authorization",
    "github_repository_sha256",
    "github_workflow_authorization_evidence",
    "issue_github_workflow_capability",
    "issue_github_workflow_capability_binding",
)
