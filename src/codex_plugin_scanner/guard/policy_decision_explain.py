"""Explain which policy rule decides a recorded Guard decision.

A decision id is a receipt id. The receipt records the harness, the artifact and when it happened;
the explanation replays that event against the policy that is Live on this device now, so it names the
rule that would decide it today and says so.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import cast

from .business_policy_document_import import has_business_rules, read_business_document_for_store
from .native_policy_document import NativePolicyDocumentError
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_decision_engine import PolicyEvent, PolicyEventError, compile_local_rows, decide_rows, parse_event
from .policy_document import GuardPolicyDocument, policy_document_digest
from .policy_document_io import build_policy_document_from_rows
from .policy_document_types import CompiledPolicyRow, PolicyCompilationError
from .policy_document_yaml import PolicyDocumentError
from .store import GuardStore

# Reading or compiling the Live policy can fail on an unreadable business source or a native refusal.
ACTIVE_POLICY_ERRORS = (
    NativePolicyDocumentError,
    NativePolicySnapshotError,
    PolicyCompilationError,
    PolicyDocumentError,
    PolicyEventError,
    TypeError,
    ValueError,
)
# Receipts record the harness and artifact, not the publisher or workspace, so rules scoped to those cannot
# be replayed faithfully.
CONTEXT_NOT_RECORDED_NOTE = "publisher_and_workspace_scopes_not_replayed"


def active_policy_document(store: GuardStore) -> GuardPolicyDocument:
    """The policy Live on this device: the business source when installed, otherwise the local rows."""

    return read_business_document_for_store(store) or build_policy_document_from_rows(
        store.list_policy_decisions(), include_provenance=True
    )


def _canonical_time(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scoped_to_unrecorded_context(rows: tuple[CompiledPolicyRow, ...]) -> bool:
    return any(row.decision.scope in ("publisher", "workspace") for row in rows)


def receipt_event(receipt: dict[str, object]) -> PolicyEvent:
    harness = receipt.get("harness")
    artifact = receipt.get("artifact_id")
    return parse_event(
        {
            "harness": harness if isinstance(harness, str) else "",
            "artifact": artifact if isinstance(artifact, str) and artifact else None,
            "at": _canonical_time(receipt.get("timestamp")),
        }
    )


def matched_rule_for_receipt(store: GuardStore, receipt: dict[str, object]) -> dict[str, object]:
    """``{"rule_id", "effect", "description", ...}`` for the rule that decides this receipt's event now."""

    result: dict[str, object] = {
        "rule_id": None,
        "effect": "default",
        "description": None,
        "evaluated_against": "current_policy",
    }
    try:
        document = active_policy_document(store)
        if has_business_rules(document):
            result["note"] = "business_rules_not_evaluated_locally"
            return result
        rows = compile_local_rows(document)
        decision = decide_rows(
            rows,
            receipt_event(receipt),
            now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    except ACTIVE_POLICY_ERRORS:
        result["note"] = "receipt_not_evaluable"
        return result
    if _scoped_to_unrecorded_context(rows):
        result["note"] = CONTEXT_NOT_RECORDED_NOTE
    rule_id = cast("str | None", decision["ruleId"])
    result["effect"] = decision["effect"]
    result["rule_id"] = rule_id
    result["ambiguous"] = decision["ambiguous"]
    result["policy_digest"] = policy_document_digest(document)
    if rule_id is not None:
        result["description"] = next((rule.description for rule in document.rules if rule.id == rule_id), None)
    return result


def explain_receipt_decision(store: GuardStore, receipt_id: str) -> dict[str, object] | None:
    """The full Decision for a receipt, or ``None`` when the receipt is unknown."""

    receipt = store.get_receipt(receipt_id)
    if receipt is None:
        return None
    payload: dict[str, object] = {
        "decisionId": receipt_id,
        "receipt": {
            "harness": receipt.get("harness"),
            "artifactId": receipt.get("artifact_id"),
            "recordedDecision": receipt.get("policy_decision"),
            "timestamp": receipt.get("timestamp"),
        },
        "evaluatedAgainst": "current_policy",
    }
    try:
        document = active_policy_document(store)
        if has_business_rules(document):
            payload["note"] = "business_rules_not_evaluated_locally"
            return payload
        rows = compile_local_rows(document)
        decision = decide_rows(
            rows,
            receipt_event(receipt),
            now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    except ACTIVE_POLICY_ERRORS:
        payload["note"] = "receipt_not_evaluable"
        return payload
    if _scoped_to_unrecorded_context(rows):
        payload["note"] = CONTEXT_NOT_RECORDED_NOTE
    decision["document"] = {"id": document.metadata.id, "digest": policy_document_digest(document)}
    payload["decision"] = decision
    return payload


__all__ = [
    "ACTIVE_POLICY_ERRORS",
    "CONTEXT_NOT_RECORDED_NOTE",
    "active_policy_document",
    "explain_receipt_decision",
    "matched_rule_for_receipt",
    "receipt_event",
]
