"""Request-status and whole-source mutation share the existing SQLite owner."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from ..business_policy_document_import import (
    apply_business_document_on_connection,
    compile_document_for_import,
    has_business_rules,
)
from ..native_business_source_store import BusinessSourceMutation, approved_business_source_mutation
from ..native_command_control_authority_io import hold_command_control_authority_lock
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..policy_document import policy_document_digest
from .policy_errors import PolicyToolError
from .policy_recovery_state import request_recovery_recorded, request_recovery_recorded_on_connection
from .policy_store import MCPolicyRequestRepository, PendingPolicyRequest
from .policy_time import utc_now_iso as _now_iso

if TYPE_CHECKING:
    from ..approval_gate import ApprovalGateGrant
    from ..store import GuardStore
    from ..store_policy_document import PolicyDocumentImportResult


def apply_pending_policy_request(
    store: GuardStore,
    request_id: str,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
) -> dict[str, object]:
    from .policy_tools import (
        _build_current_document,
        _build_current_legacy_document,
        _pending_policy_candidate,
        _read_policy_integrity_generation,
        _safe_int,
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
    mutation: BusinessSourceMutation | None = None

    def _do_import(pending: PendingPolicyRequest, conn: sqlite3.Connection) -> PolicyDocumentImportResult:
        if request_recovery_recorded_on_connection(conn, request_id):
            raise PolicyToolError("business_source_already_recovered", "This request's policy was already recovered.")
        if any(
            getattr(pending, name) != getattr(request, name)
            for name in (
                "policy_document_digest",
                "canonical_policy_yaml",
                "mode",
                "expected_current_digest",
                "expected_policy_generation",
            )
        ):
            raise PolicyToolError("candidate_digest_mismatch", "Stored candidate changed before apply.")
        previous_source = mutation.previous_source if mutation is not None else None
        checked_digest = None
        if previous_source is not None:
            checked_digest = previous_source.source_digest
        else:
            if mutation is not None:
                previous_document = _build_current_legacy_document(store)
            else:
                previous_document = _build_current_document(store)
            if previous_document is not None:
                checked_digest = policy_document_digest(previous_document)
        if checked_digest != request.expected_current_digest:
            raise PolicyToolError("current_digest_mismatch", "Current policy digest has changed.")
        if expected_generation is not None:
            state = store._load_policy_integrity_state(conn)
            gen = state.get("generation") if isinstance(state, dict) else None
            if gen is not None and _safe_int(gen) != expected_generation:
                raise PolicyToolError("stale_policy_generation", "Policy integrity generation has changed.")
        if mutation is not None:
            return apply_business_document_on_connection(
                store,
                document,
                mutation,
                mode=request.mode,
                now=_now_iso(),
                approval_gate_grant=approval_gate_grant,
                connection=conn,
            )
        return store.apply_policy_creation_request(
            document,
            compiled,
            mode=request.mode,
            now=_now_iso(),
            approval_gate_grant=approval_gate_grant,
            connection=conn,
        )

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
                result = repo.apply_request(request_id, apply_fn=_do_import)
        except NativePolicySnapshotError as error:
            if str(error) == "native_business_source_already_installed":
                raise PolicyToolError(
                    "business_source_already_installed", "This business policy is already installed."
                ) from None
            if str(error) == "native_business_source_current_digest_changed":
                raise PolicyToolError("current_digest_mismatch", "Current policy digest has changed.") from None
            raise
    else:
        with hold_command_control_authority_lock(store.guard_home):
            result = repo.apply_request(request_id, apply_fn=_do_import)
    return {
        "requestId": result.request_id,
        "status": result.status,
        "resolvedAt": result.resolved_at,
        "inserted": result.inserted,
        "replaced": result.replaced,
    }
