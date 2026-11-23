"""Request-status and whole-source mutation share the existing SQLite owner."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..business_policy_document_import import (
    approved_install_digest,
    compile_document_for_import,
    has_business_rules,
)
from ..native_business_source_store import BusinessSourceMutation, approved_business_source_mutation
from ..native_command_control_authority_io import hold_command_control_authority_lock
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..policy_document import policy_document_digest
from .policy_errors import PolicyToolError
from .policy_recovery_state import request_recovery_recorded
from .policy_store import ApplyRequestResult, MCPolicyRequestRepository, PendingPolicyRequest
from .policy_time import utc_now_iso as _now_iso

if TYPE_CHECKING:
    from ..approval_gate import ApprovalGateGrant
    from ..policy_document import GuardPolicyDocument
    from ..store import GuardStore


def apply_pending_policy_request(
    store: GuardStore,
    request_id: str,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
) -> dict[str, object]:
    from .policy_tools import (
        _build_current_document,
        _pending_policy_candidate,
        _read_policy_integrity_generation,
    )

    repo = MCPolicyRequestRepository(store)
    request, document = _pending_policy_candidate(store, request_id)
    if request_recovery_recorded(store, request_id):
        raise PolicyToolError("business_source_already_recovered", "This request's policy was already recovered.")
    compiled = compile_document_for_import(document)
    current_document = _build_current_document(store)
    current_digest = policy_document_digest(current_document) if current_document else None
    if has_business_rules(document) and current_digest == request.policy_document_digest:
        raise PolicyToolError(
            "business_source_already_installed",
            "This business policy is already installed. Decline the unchanged request.",
        )
    if current_digest != request.expected_current_digest:
        raise PolicyToolError("current_digest_mismatch", "Current policy digest has changed.")
    expected_generation = request.expected_policy_generation
    if expected_generation is not None:
        current_generation = _read_policy_integrity_generation(store)
        if current_generation is not None and current_generation != expected_generation:
            raise PolicyToolError("stale_policy_generation", "Policy integrity generation has changed.")
    if has_business_rules(document):
        try:
            with approved_business_source_mutation(
                store,
                document,
                mode=request.mode,
                now=_now_iso(),
                approval_gate_grant=approval_gate_grant,
                expected_current_digest=request.expected_current_digest,
                reject_already_installed=True,
            ) as mutation:
                result = _apply_business_request(
                    store, repo, request, document, mutation, approval_gate_grant=approval_gate_grant
                )
        except NativePolicySnapshotError as error:
            if str(error) == "native_business_source_already_installed":
                raise PolicyToolError(
                    "business_source_already_installed", "This business policy is already installed."
                ) from None
            if str(error) == "native_business_source_current_digest_changed":
                raise PolicyToolError("current_digest_mismatch", "Current policy digest has changed.") from None
            raise
    else:
        # The resident re-checks the request, the candidate, the imported rows
        # behind the current digest and the generation, then writes the rows
        # and resolves the request in one transaction. The generation lock
        # spans that write and the finalize after it, as it does for a
        # document import, so no other advance lands between them.
        with store.hold_policy_integrity_generation_lock(), hold_command_control_authority_lock(store.guard_home):
            fingerprint = store._native_store_call("policy_rows_fingerprint", {})
            rows_fingerprint = fingerprint.get("fingerprint") if isinstance(fingerprint, dict) else None
            if not isinstance(rows_fingerprint, str):
                raise RuntimeError("Guard could not read the imported policy rows.")
            previous_document = _build_current_document(store)
            checked_digest = policy_document_digest(previous_document) if previous_document is not None else None
            if checked_digest != request.expected_current_digest:
                raise PolicyToolError("current_digest_mismatch", "Current policy digest has changed.")
            now = _now_iso()
            try:
                import_args = store.policy_creation_import_args(
                    document, compiled, mode=request.mode, now=now, approval_gate_grant=approval_gate_grant
                )
            except PolicyToolError:
                raise
            except Exception:
                # A refused approval or an unwritable document ends the
                # request, as it did inside the request transaction.
                repo.mark_failed(request_id)
                raise
            result, next_control_state = repo.apply_request_native(
                request_id,
                candidate=request,
                import_args={**import_args, "rows_fingerprint": rows_fingerprint},
            )
            store.finalize_policy_import(next_control_state)
    return {
        "requestId": result.request_id,
        "status": result.status,
        "resolvedAt": result.resolved_at,
        "inserted": result.inserted,
        "replaced": result.replaced,
    }


def _apply_business_request(
    store: GuardStore,
    repo: MCPolicyRequestRepository,
    request: PendingPolicyRequest,
    document: GuardPolicyDocument,
    mutation: BusinessSourceMutation,
    *,
    approval_gate_grant: ApprovalGateGrant | None,
) -> ApplyRequestResult:
    """Install an approved business source the request carries.

    The mutation holds the command-control authority lock. The resident
    re-checks the request, its candidate, the imported rows behind the
    current digest and the generation, then drops the imported rows, stages
    the installation witness and resolves the request in one transaction.
    """
    from .policy_tools import _build_current_legacy_document

    fingerprint = store._native_store_call("policy_rows_fingerprint", {})
    rows_fingerprint = fingerprint.get("fingerprint") if isinstance(fingerprint, dict) else None
    if not isinstance(rows_fingerprint, str):
        raise RuntimeError("Guard could not read the imported policy rows.")
    previous_source = mutation.previous_source
    if previous_source is not None:
        checked_digest: str | None = previous_source.source_digest
    else:
        previous_document = _build_current_legacy_document(store)
        checked_digest = policy_document_digest(previous_document) if previous_document is not None else None
    if checked_digest != request.expected_current_digest:
        raise PolicyToolError("current_digest_mismatch", "Current policy digest has changed.")
    now = _now_iso()
    try:
        digest = approved_install_digest(
            store, document, mutation, mode=request.mode, now=now, approval_gate_grant=approval_gate_grant
        )
        import_args = store.policy_import_args(document, [], mode="replace", now=now, digest=digest, vault_key=True)
    except PolicyToolError:
        raise
    except Exception:
        # A refused approval or an incoherent install ends the request, as
        # it did inside the request transaction.
        repo.mark_failed(request.request_id)
        raise
    result, next_control_state = repo.apply_request_native(
        request.request_id,
        candidate=request,
        import_args={
            **import_args,
            "rows_fingerprint": rows_fingerprint,
            "business_witness": mutation.witness_text(),
            "reported_inserted": len(document.rules),
        },
    )
    store.finalize_policy_import(next_control_state)
    return result
