"""Production issuance and retry claim facade for GitHub workflow capabilities."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Protocol

from ..native_github_workflow import (
    GitHubWorkflowLineage,
    github_workflow_validated_lineage,
)
from ..workflow_capabilities import (
    SignedWorkflowCapability,
    WorkflowCapabilityError,
    format_utc_timestamp,
)
from .github_workflow_approval_record import GitHubWorkflowApprovalRecord
from .github_workflow_authorization import (
    WorkflowCapabilityStore,
    issue_github_workflow_capability_binding,
)

_ISSUER_ID = "guard.local"
_CAPABILITY_TTL = timedelta(minutes=10)
_CAPABILITY_MAX_USES = 10


class GitHubWorkflowRuntimeStore(WorkflowCapabilityStore, Protocol):
    def get_approval_request(self, request_id: str, *, derive_scope: bool = True) -> dict[str, object] | None: ...

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None: ...

    def get_guard_session(self, session_id: str) -> dict[str, object] | None: ...

    def lookup_workflow_capability(self, capability_id: str) -> SignedWorkflowCapability | None: ...

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...


def issue_resolved_github_workflow_capability(
    store: GitHubWorkflowRuntimeStore,
    request: Mapping[str, object],
    *,
    resolved_at: str,
) -> bool:
    """Issue one deterministic capability only after an exact persisted allow."""

    try:
        lineage = _validated_lineage(store, request)
        if request.get("status") != "resolved" or request.get("resolution_action") != "allow":
            return False
        capability_id = lineage.capability_id
        try:
            existing = store.lookup_workflow_capability(capability_id)
        except WorkflowCapabilityError as error:
            if str(error) != "capability_control_unavailable":
                raise
            existing = None
        if existing is not None:
            return _existing_matches(existing, lineage)
        # The resident signs the claim; this only confirms the local key exists.
        if any(part is None for part in store._policy_integrity_secret_material(create=False)):
            return False
        issued_at = datetime.fromisoformat(resolved_at.replace("Z", "+00:00"))
        if issued_at.tzinfo is None:
            raise ValueError("resolution timestamp timezone required")
        signed = issue_github_workflow_capability_binding(
            store,
            lineage.record.binding,
            capability_id=capability_id,
            approval_provenance_id=lineage.request_id,
            task_id=lineage.operation_id,
            nonce=lineage.nonce,
            issuer_id=_ISSUER_ID,
            subject_id=lineage.session_id,
            issued_at=format_utc_timestamp(issued_at),
            not_before=format_utc_timestamp(issued_at),
            expires_at=format_utc_timestamp(issued_at + _CAPABILITY_TTL),
            max_uses=_CAPABILITY_MAX_USES,
        )
        return signed.claim.capability_id == capability_id
    except (KeyError, TypeError, ValueError, WorkflowCapabilityError):
        return False


def approval_record_from_approval_request(request: Mapping[str, object]) -> GitHubWorkflowApprovalRecord | None:
    evidence = request.get("scanner_evidence")
    if not isinstance(evidence, list):
        return None
    candidates: list[GitHubWorkflowApprovalRecord] = []
    for item in evidence:
        if not isinstance(item, Mapping) or item.get("source") != "github_workflow_approval_record":
            continue
        payload = item.get("record")
        if not isinstance(payload, Mapping):
            return None
        candidates.append(GitHubWorkflowApprovalRecord.from_dict(payload))
    return candidates[0] if len(candidates) == 1 else None


def github_workflow_requires_local_once(request: Mapping[str, object]) -> bool:
    """Preserve Guard-owned approval lineage for a workflow retry."""

    try:
        return approval_record_from_approval_request(request) is not None
    except (TypeError, ValueError):
        return False


def issue_github_workflow_capability_for_resolution(
    store: GitHubWorkflowRuntimeStore, request_id: str, resolved_at: str
) -> None:
    """Issue when eligible while keeping ordinary approvals unchanged."""

    try:
        request = store.get_approval_request(request_id, derive_scope=False)
        if request is not None:
            _ = issue_resolved_github_workflow_capability(store, request, resolved_at=resolved_at)
    except Exception:
        return


def _validated_lineage(store: GitHubWorkflowRuntimeStore, request: Mapping[str, object]) -> GitHubWorkflowLineage:
    """The resident's verdict that these three store rows are one workflow lineage.

    Python reads the rows because the resident does no store IO, and the
    operation names the session row to read. Every comparison between them --
    the approval linkage, the operation state, the session's surface and
    capabilities, the one harness, the hook event, the persisted command's
    re-derivation and the workspace binding -- is the resident's. There is no
    Python fallback: an undecidable lineage raises, and the capability the
    caller was about to issue, claim or preflight never exists.
    """
    request_id = _required_string(request, "request_id")
    operation = store.get_guard_operation_for_approval_request(request_id)
    if operation is None:
        raise ValueError("missing Guard operation")
    session = store.get_guard_session(_required_string(operation, "session_id"))
    if session is None:
        raise ValueError("missing Guard session")
    lineage = github_workflow_validated_lineage(request, operation, session)
    if lineage is None or lineage.request_id != request_id:
        raise ValueError("invalid GitHub workflow lineage")
    return lineage


def _existing_matches(signed: SignedWorkflowCapability, lineage: GitHubWorkflowLineage) -> bool:
    claim = signed.claim
    return (
        claim.approval_provenance_id == lineage.request_id
        and claim.task_id == lineage.operation_id
        and claim.subject_id == lineage.session_id
        and claim.issuer_id == _ISSUER_ID
        and claim.binding == lineage.record.binding
        and claim.max_uses == _CAPABILITY_MAX_USES
    )


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {key}")
    return value


__all__ = (
    "approval_record_from_approval_request",
    "github_workflow_requires_local_once",
    "issue_github_workflow_capability_for_resolution",
    "issue_resolved_github_workflow_capability",
)
