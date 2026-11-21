"""Issue and atomically claim exact GitHub workflow capabilities."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Final, Protocol

from typing_extensions import override

from ..workflow_capabilities import (
    WORKFLOW_CAPABILITY_ALGORITHM,
    WORKFLOW_CAPABILITY_SCHEMA,
    SignedWorkflowCapability,
    SignedWorkflowCapabilityReceipt,
    WorkflowCapabilityBinding,
    WorkflowCapabilityClaim,
)
from .effect_decision import PositiveProof

# The `maintain_remote` action class in the Rust GitHub capability contract
# (guard-command/src/github_capability_contract.rs), the only capability a
# workflow authorization can cover.
GITHUB_MAINTENANCE_ACTION_CLASS: Final = "maintenance"
_AUTHORIZATION_SEAL: Final = object()


class WorkflowCapabilityStore(Protocol):
    def issue_workflow_capability(
        self, claim: WorkflowCapabilityClaim, *, approval_provenance_id: str
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
        command_identity: str,
        proof: PositiveProof,
        receipt_sha256: str,
    ) -> None:
        if authority_token is not _AUTHORIZATION_SEAL:
            raise TypeError("GitHub workflow authorization requires an atomic Guard claim")
        object.__setattr__(self, "_operation_identity", command_identity)
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

    def to_wire(self) -> dict[str, object] | None:
        """Return the resident wire form, or None when this object lost its claim seal.

        The seal check is host-side object identity and cannot cross the wire,
        so only a still-sealed authorization is ever serialized (``sealed`` true).
        """
        try:
            if self._seal is not _AUTHORIZATION_SEAL:
                return None
            return {
                "operation_identity": self._operation_identity,
                "proof": {
                    "route": self._proof.route.value,
                    "binding_digest": self._proof.binding_digest,
                    "satisfied_requirements": sorted(item.value for item in self._proof.satisfied_requirements),
                    "enforced": self._proof.enforced,
                },
                "receipt_sha256": self._receipt_sha256,
                "sealed": True,
            }
        except (AttributeError, TypeError, ValueError):
            return None

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
    return store.issue_workflow_capability(claim, approval_provenance_id=approval_provenance_id)


__all__ = (
    "GitHubWorkflowAuthorization",
    "issue_github_workflow_capability_binding",
)
