"""Production issuance and retry claim facade for GitHub workflow capabilities."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Protocol

from ..workflow_capabilities import (
    SignedWorkflowCapability,
    WorkflowCapabilityError,
    canonical_framed_payload,
    format_utc_timestamp,
    parse_utc_timestamp,
)
from .command_model import parse_shell_command
from .github_workflow_approval_record import GitHubWorkflowApprovalRecord
from .github_workflow_authorization import (
    GitHubWorkflowAuthorization,
    WorkflowCapabilityStore,
    claim_github_workflow_authorization,
    issue_github_workflow_capability_binding,
)
from .github_workflow_context import GitHubWorkflowDescriptor
from .github_workflow_operations import parse_github_workflow_operation

_ISSUER_ID = "guard.local"
_CAPABILITY_TTL = timedelta(minutes=10)
_CAPABILITY_MAX_USES = 10


class GitHubWorkflowRuntimeStore(WorkflowCapabilityStore, Protocol):
    def get_approval_request(self, request_id: str) -> dict[str, object] | None: ...

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
        request_id, record, operation, session = _validated_lineage(store, request)
        if request.get("status") != "resolved" or request.get("resolution_action") != "allow":
            return False
        capability_id = _capability_id(request_id)
        try:
            existing = store.lookup_workflow_capability(capability_id)
        except WorkflowCapabilityError as error:
            if str(error) != "capability_control_unavailable":
                raise
            existing = None
        if existing is not None:
            return _existing_matches(existing, request_id, operation, session, record)
        key, key_id = store._policy_integrity_secret_material(create=False)
        if key is None or key_id is None:
            return False
        issued_at = parse_utc_timestamp(resolved_at)
        signed = issue_github_workflow_capability_binding(
            store,
            record.binding,
            capability_id=capability_id,
            approval_provenance_id=request_id,
            task_id=_required_string(operation, "operation_id"),
            nonce=_digest("github-workflow-nonce", request_id),
            issuer_id=_ISSUER_ID,
            subject_id=_required_string(session, "session_id"),
            issued_at=format_utc_timestamp(issued_at),
            not_before=format_utc_timestamp(issued_at),
            expires_at=format_utc_timestamp(issued_at + _CAPABILITY_TTL),
            max_uses=_CAPABILITY_MAX_USES,
            key=key,
            key_id=key_id,
        )
        return signed.claim.capability_id == capability_id
    except (KeyError, TypeError, ValueError, WorkflowCapabilityError):
        return False


def claim_resolved_github_workflow_authorization(
    store: GitHubWorkflowRuntimeStore,
    request_id: str,
    descriptor: GitHubWorkflowDescriptor,
) -> GitHubWorkflowAuthorization | None:
    """Atomically claim the exact capability using only persisted Guard lineage."""

    try:
        request = store.get_approval_request(request_id)
        if request is None or request.get("status") != "resolved" or request.get("resolution_action") != "allow":
            return None
        persisted_id, record, operation, session = _validated_lineage(store, request)
        if persisted_id != request_id or not record.matches_descriptor(descriptor):
            return None
        capability_id = _capability_id(request_id)
        return claim_github_workflow_authorization(
            store,
            capability_id,
            descriptor.operation,
            descriptor.binding_context,
            invocation_id=f"github-invocation-{secrets.token_hex(16)}",
            subject_id=_required_string(session, "session_id"),
            task_id=_required_string(operation, "operation_id"),
            issuer_id=_ISSUER_ID,
            approval_provenance_id=request_id,
        )
    except (KeyError, TypeError, ValueError, WorkflowCapabilityError):
        return None


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


def github_workflow_capability_required(store: GitHubWorkflowRuntimeStore, request_id: str) -> bool:
    """Return whether a claimed approval is marked as a workflow task."""

    try:
        request = store.get_approval_request(request_id)
        if request is None or request.get("status") != "resolved" or request.get("resolution_action") != "allow":
            return False
        evidence = request.get("scanner_evidence")
        if not isinstance(evidence, list):
            return False
        marked = [
            item
            for item in evidence
            if isinstance(item, Mapping) and item.get("source") == "github_workflow_approval_record"
        ]
        return len(marked) > 0
    except Exception:
        return True


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
        request = store.get_approval_request(request_id)
        if request is not None:
            _ = issue_resolved_github_workflow_capability(store, request, resolved_at=resolved_at)
    except Exception:
        return


def _validated_lineage(
    store: GitHubWorkflowRuntimeStore, request: Mapping[str, object]
) -> tuple[str, GitHubWorkflowApprovalRecord, Mapping[str, object], Mapping[str, object]]:
    request_id = _required_string(request, "request_id")
    record = approval_record_from_approval_request(request)
    if record is None:
        raise ValueError("missing GitHub workflow approval record")
    operation = store.get_guard_operation_for_approval_request(request_id)
    if operation is None:
        raise ValueError("missing Guard operation")
    operation_request_ids = operation.get("approval_request_ids")
    if not isinstance(operation_request_ids, list) or operation_request_ids.count(request_id) != 1:
        raise ValueError("invalid Guard operation approval linkage")
    if operation.get("operation_type") != "tool_call" or operation.get("status") not in {
        "waiting_on_approval",
        "completed",
        "resumed",
    }:
        raise ValueError("invalid Guard workflow operation state")
    session_id = _required_string(operation, "session_id")
    session = store.get_guard_session(session_id)
    if session is None or _required_string(session, "session_id") != session_id:
        raise ValueError("missing Guard session")
    capabilities = session.get("capabilities")
    if (
        session.get("surface") != "harness-adapter"
        or not isinstance(capabilities, list)
        or "approval-resolution" not in capabilities
    ):
        raise ValueError("invalid Guard workflow session")
    harness = _required_string(request, "harness")
    if _required_string(operation, "harness") != harness or _required_string(session, "harness") != harness:
        raise ValueError("Guard operation harness mismatch")
    metadata = operation.get("metadata")
    if not isinstance(metadata, Mapping):
        raise ValueError("missing Guard operation metadata")
    if metadata.get("hook_event_name") not in {
        "PreToolUse",
        "beforeShellExecution",
        "preToolUse",
    }:
        raise ValueError("invalid Guard workflow hook event")
    command_text = metadata.get("command_text")
    if not isinstance(command_text, str) or not command_text:
        raise ValueError("Guard operation command mismatch")
    if not _persisted_command_matches_record(command_text, record):
        raise ValueError("Guard operation command mismatch")
    operation_workspace = _required_string(metadata, "workspace")
    session_workspace = _required_string(session, "workspace")
    if (
        operation_workspace != session_workspace
        or _digest("github-workspace", str(Path(operation_workspace).resolve())) != record.binding.workspace_sha256
    ):
        raise ValueError("Guard operation workspace mismatch")
    if request.get("artifact_type") != "tool_action_request":
        raise ValueError("invalid GitHub workflow approval type")
    return request_id, record, operation, session


def _existing_matches(
    signed: SignedWorkflowCapability,
    request_id: str,
    operation: Mapping[str, object],
    session: Mapping[str, object],
    record: GitHubWorkflowApprovalRecord,
) -> bool:
    claim = signed.claim
    return (
        claim.approval_provenance_id == request_id
        and claim.task_id == _required_string(operation, "operation_id")
        and claim.subject_id == _required_string(session, "session_id")
        and claim.issuer_id == _ISSUER_ID
        and claim.binding == record.binding
        and claim.max_uses == _CAPABILITY_MAX_USES
    )


def _persisted_command_matches_record(command_text: str, record: GitHubWorkflowApprovalRecord) -> bool:
    try:
        command = parse_shell_command(command_text)
        if len(command.segments) != 1:
            return False
        executable = command.segments[0].executable
        if not isinstance(executable, str) or not executable:
            return False
        path = Path(executable)
        canonical = path.resolve(strict=True)
        if (
            not path.is_absolute()
            or path != canonical
            or not path.is_file()
            or not os.access(path, os.X_OK)
            or _file_sha256(path) != record.binding.executable_sha256
        ):
            return False
        candidate = parse_github_workflow_operation(
            command,
            expected_executable=executable,
        ) or parse_github_workflow_operation(
            command,
            repository="guard/locator",
            expected_executable=executable,
        )
        return (
            candidate is not None
            and candidate.kind == record.operation_kind
            and candidate.resource_type == record.resource_type
            and _digest("github-workflow-resource", candidate.resource_id) == record.binding.resource_sha256
            and _digest("github-workflow-command-identity", command.security_identity) == record.command_identity_sha256
        )
    except (OSError, TypeError, ValueError):
        return False


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _capability_id(request_id: str) -> str:
    return f"gwc-{_digest('github-workflow-capability', request_id)}"


def _digest(purpose: str, payload: object) -> str:
    return hashlib.sha256(canonical_framed_payload(purpose, payload)).hexdigest()


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {key}")
    return value


__all__ = (
    "approval_record_from_approval_request",
    "claim_resolved_github_workflow_authorization",
    "github_workflow_capability_required",
    "github_workflow_requires_local_once",
    "issue_github_workflow_capability_for_resolution",
    "issue_resolved_github_workflow_capability",
)
