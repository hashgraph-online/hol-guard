"""Core implementations for MCP policy authoring tools.

These functions are framework-independent and testable without FastMCP.
They reuse the existing strict YAML parser, canonical model, compiler,
authority validation, semantic diff, import planner, and atomic store
transaction.  No CLI subprocess, no second schema, no remote transport.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING

from ..approval_gate import ApprovalGateGrant
from ..business_policy_document_import import (
    compile_document_for_import,
    has_business_rules,
    plan_document_for_import,
    read_business_document_for_store,
)
from ..policy_document import GuardPolicyDocument, policy_document_digest
from ..policy_document_authority import PolicyImportApprovalBinding, policy_import_approval_binding
from ..policy_document_compile import build_policy_document_from_rows
from ..policy_document_diff import diff_policy_documents
from ..policy_document_io import CompiledPolicyRow
from ..policy_document_yaml import (
    PolicyDocumentError,
    format_policy_document_yaml,
    parse_policy_document_yaml,
)
from ..store_policy_document import PolicyImportMode
from .policy_errors import PolicyToolError
from .policy_store import (
    MCPolicyRequestRepository,
    PendingPolicyRequest,
    StageRequestInput,
)
from .policy_time import utc_now_iso

_now_iso = utc_now_iso

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.store import GuardStore

_POLICY_IMPORT_FLAG = "HOL_GUARD_POLICY_YAML_IMPORT"
_MCP_POLICY_WRITE_FLAG = "HOL_GUARD_MCP_POLICY_WRITE"


def _safe_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return 0


def _parse_and_compile(policy_yaml: str) -> tuple[GuardPolicyDocument, tuple[CompiledPolicyRow, ...]]:
    try:
        document = parse_policy_document_yaml(policy_yaml)
    except PolicyDocumentError as error:
        diagnostics = error.diagnostics if hasattr(error, "diagnostics") else ()
        # Map diagnostic codes to the stable MCP error code set. Unknown
        # diagnostic codes fall back to policy_parse_failed.
        code = "policy_parse_failed"
        if diagnostics:
            diag_code = diagnostics[0].code
            from .policy_errors import _ALL_CODES

            if diag_code in _ALL_CODES:
                code = diag_code
        raise PolicyToolError(code, "Policy YAML parsing failed.") from error
    try:
        compiled = compile_document_for_import(document)
    except Exception as error:
        raise PolicyToolError("policy_compile_failed", "Policy compilation failed.") from error
    return document, compiled


def _build_current_document(store: GuardStore) -> GuardPolicyDocument | None:
    business = read_business_document_for_store(store)
    if business is not None:
        return business
    return _build_current_legacy_document(store)


def _build_current_legacy_document(store: GuardStore) -> GuardPolicyDocument | None:
    rows = store.list_policy_decisions()
    imported_rows = [row for row in rows if row.get("source") == "policy-yaml-import"]
    if not imported_rows:
        return None
    return build_policy_document_from_rows(imported_rows, document_id="local-policy")


def _semantic_diff_summary(
    baseline: GuardPolicyDocument | None, candidate: GuardPolicyDocument
) -> dict[str, list[str]]:
    if baseline is None:
        return {
            "additions": [rule.id for rule in candidate.rules],
            "modifications": [],
            "removals": [],
        }
    diff = diff_policy_documents(baseline, candidate)
    return {
        "additions": list(diff.additions),
        "modifications": list(diff.modifications),
        "removals": list(diff.removals),
    }


def _write_plan_summary(
    store: GuardStore, compiled: tuple[CompiledPolicyRow, ...], mode: PolicyImportMode, document: GuardPolicyDocument
) -> dict[str, list[str]]:
    plan = plan_document_for_import(store, document, compiled, mode)
    return {
        "additions": list(plan.additions),
        "replacements": list(plan.replacements),
        "removals": list(plan.removals),
    }


def _read_policy_integrity_generation(store: GuardStore) -> int | None:
    """Read the authoritative policy integrity generation via a real connection.

    Uses ``_load_policy_integrity_state`` on an actual SQLite connection
    instead of passing ``None`` to ``_refresh_policy_integrity_state``.
    Returns ``None`` when integrity state is unavailable (e.g. fresh DB
    with no key yet); staging proceeds without a generation binding in
    that degraded case.
    """
    try:
        with store._connect() as connection:
            state = store._load_policy_integrity_state(connection)
        if not isinstance(state, dict):
            return None
        gen = state.get("generation")
        if gen is None:
            return None
        if isinstance(gen, (int, float)):
            return int(gen)
        if isinstance(gen, str) and gen.strip():
            return int(gen)
        return None
    except Exception:
        return None


def _check_feature_flags() -> None:
    import os

    if os.environ.get(_POLICY_IMPORT_FLAG) != "1":
        raise PolicyToolError(
            "policy_import_disabled",
            "Policy YAML import is not enabled. Set HOL_GUARD_POLICY_YAML_IMPORT=1.",
        )
    if os.environ.get(_MCP_POLICY_WRITE_FLAG) != "1":
        raise PolicyToolError(
            "mcp_policy_write_disabled",
            "MCP policy write is not enabled. Set HOL_GUARD_MCP_POLICY_WRITE=1.",
        )


def execute_validate_policy(store: GuardStore, arguments: dict[str, object]) -> str:
    """Validate a canonical policy document without writing any state."""
    from .policy_schemas import parse_validate_policy_input
    from .tools import _envelope

    parsed = parse_validate_policy_input(arguments)
    document, compiled = _parse_and_compile(parsed.policy_yaml)
    candidate_digest = policy_document_digest(document)
    current_document = _build_current_document(store)
    current_digest = policy_document_digest(current_document) if current_document else None
    diff_summary = _semantic_diff_summary(current_document, document)
    plan_summary = _write_plan_summary(store, compiled, parsed.mode, document)

    payload: dict[str, object] = {
        "ok": True,
        "valid": True,
        "documentId": document.metadata.id,
        "candidateDigest": candidate_digest,
        "currentDigest": current_digest,
        "mode": parsed.mode,
        "ruleCount": len(document.rules),
        "compiledRows": len(compiled),
        "semanticDiff": {
            "additions": diff_summary["additions"],
            "modifications": diff_summary["modifications"],
            "removals": diff_summary["removals"],
        },
        "writePlan": {
            "additions": plan_summary["additions"],
            "replacements": plan_summary["replacements"],
            "removals": plan_summary["removals"],
        },
        "writeEnabled": False,
        "requiresHumanApproval": True,
    }
    return _envelope(payload)


def execute_create_policy(
    store: GuardStore,
    arguments: dict[str, object],
    *,
    approval_url_builder: Callable[[str], str | None] | None = None,
) -> str:
    """Stage a digest-bound policy creation request and initiate approval."""
    from .policy_schemas import parse_create_policy_input
    from .tools import _envelope

    _check_feature_flags()
    parsed = parse_create_policy_input(arguments)
    document, compiled = _parse_and_compile(parsed.policy_yaml)
    candidate_digest = policy_document_digest(document)

    if candidate_digest != parsed.candidate_digest:
        raise PolicyToolError(
            "candidate_digest_mismatch",
            "candidateDigest does not match the recomputed policy digest.",
        )

    current_document = _build_current_document(store)
    current_digest = policy_document_digest(current_document) if current_document else None

    if current_digest != parsed.expected_current_digest:
        raise PolicyToolError(
            "current_digest_mismatch",
            "expectedCurrentDigest does not match the current policy digest.",
        )

    diff_summary = _semantic_diff_summary(current_document, document)
    if (
        not diff_summary["additions"]
        and not diff_summary["modifications"]
        and not diff_summary["removals"]
        and not (has_business_rules(document) and current_digest != candidate_digest)
    ):
        raise PolicyToolError("policy_no_changes", "The candidate policy has no semantic changes.")

    plan_summary = _write_plan_summary(store, compiled, parsed.mode, document)
    canonical_yaml = format_policy_document_yaml(document)
    plan_json = json.dumps(plan_summary, separators=(",", ":"), sort_keys=True)

    expected_generation = _read_policy_integrity_generation(store)

    repo = MCPolicyRequestRepository(store)
    stage_result = repo.stage_request(
        StageRequestInput(
            policy_document_id=document.metadata.id,
            policy_document_digest=candidate_digest,
            expected_current_digest=current_digest,
            expected_policy_generation=expected_generation,
            mode=parsed.mode,
            canonical_policy_yaml=canonical_yaml,
            plan_json=plan_json,
            idempotency_key=parsed.idempotency_key,
        )
    )

    approval_url: str | None = None
    if approval_url_builder is not None:
        approval_url = approval_url_builder(stage_result.request_id)

    payload: dict[str, object] = {
        "ok": True,
        "requestId": stage_result.request_id,
        "status": stage_result.status,
        "documentId": document.metadata.id,
        "candidateDigest": candidate_digest,
        "mode": parsed.mode,
        "createdAt": stage_result.created_at,
        "expiresAt": stage_result.expires_at,
        "semanticDiff": {
            "additionCount": len(diff_summary["additions"]),
            "modificationCount": len(diff_summary["modifications"]),
            "removalCount": len(diff_summary["removals"]),
        },
    }
    if approval_url is not None:
        payload["approvalUrl"] = approval_url
    return _envelope(payload)


def execute_get_policy_creation(store: GuardStore, arguments: dict[str, object]) -> str:
    """Read the status of one policy creation request by opaque request ID."""
    from .policy_schemas import parse_get_policy_creation_input
    from .tools import _envelope

    parsed = parse_get_policy_creation_input(arguments)
    repo = MCPolicyRequestRepository(store)
    request = repo.get_request(parsed.request_id)
    if request is None:
        raise PolicyToolError("policy_request_not_found", "Policy request not found.")

    result: dict[str, object] = {}
    if request.result_json:
        try:
            loaded = json.loads(request.result_json)
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, dict):
            result = {str(k): v for k, v in loaded.items()}

    payload: dict[str, object] = {
        "ok": True,
        "requestId": request.request_id,
        "status": request.status,
        "documentId": request.policy_document_id,
        "candidateDigest": request.policy_document_digest,
        "mode": request.mode,
        "createdAt": request.created_at,
        "expiresAt": request.expires_at,
        "resolvedAt": request.resolved_at,
        "result": {
            "inserted": _safe_int(result.get("inserted")),
            "replaced": _safe_int(result.get("replaced")),
        },
        "error": request.failure_code,
    }
    return _envelope(payload)


def _pending_policy_candidate(
    store: GuardStore,
    request_id: str,
) -> tuple[PendingPolicyRequest, GuardPolicyDocument]:
    """Recheck candidate identity separately at issuance and application."""
    request = MCPolicyRequestRepository(store).get_request(request_id)
    if request is None:
        raise PolicyToolError("policy_request_not_found", "Policy request not found.")
    if request.status != "pending":
        raise PolicyToolError("approval_already_resolved", f"Request is {request.status}.")
    if request.mode not in {"merge", "replace"}:
        raise PolicyToolError("candidate_invalid", "Stored policy candidate is invalid.")
    try:
        document = parse_policy_document_yaml(request.canonical_policy_yaml)
    except ValueError:
        raise PolicyToolError("candidate_invalid", "Stored policy candidate is invalid.") from None
    if policy_document_digest(document) != request.policy_document_digest:
        raise PolicyToolError("candidate_digest_mismatch", "Stored candidate digest mismatch.")
    return request, document


def pending_policy_import_approval_binding(
    store: GuardStore,
    request_id: str,
) -> PolicyImportApprovalBinding:
    """Bind approval issuance to the stored candidate rechecked during apply."""
    request, document = _pending_policy_candidate(store, request_id)
    return policy_import_approval_binding(document, request.mode)


def apply_pending_policy_request(
    store: GuardStore,
    request_id: str,
    *,
    approval_gate_grant: ApprovalGateGrant | None = None,
) -> dict[str, object]:
    """Apply the exact approved candidate through the shared transaction owner."""
    from .policy_apply import apply_pending_policy_request as apply

    return apply(store, request_id, approval_gate_grant=approval_gate_grant)


def decline_pending_policy_request(store: GuardStore, request_id: str) -> dict[str, object]:
    """Decline a pending policy request."""
    repo = MCPolicyRequestRepository(store)
    request = repo.decline_request(request_id)
    return {
        "requestId": request.request_id,
        "status": request.status,
        "resolvedAt": request.resolved_at,
    }


__all__ = [
    "apply_pending_policy_request",
    "decline_pending_policy_request",
    "execute_create_policy",
    "execute_get_policy_creation",
    "execute_validate_policy",
]
