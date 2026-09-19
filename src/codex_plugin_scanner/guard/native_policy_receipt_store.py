"""Journal-recoverable projection of native decision attribution into receipts."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Protocol

from .models import GuardReceipt
from .native_policy_decision_context import NativePolicyDecisionContext


class NativePolicyReceiptStore(Protocol):
    def add_receipt(self, receipt: GuardReceipt, *, action_envelope: dict[str, object] | None = None) -> None: ...
    def get_receipt(self, receipt_id: str) -> dict[str, object] | None: ...


def persist_native_policy_receipt(
    store: NativePolicyReceiptStore, *, receipt: Mapping[str, object], context: NativePolicyDecisionContext
) -> None:
    """Retry one deterministic decision receipt without re-reading current policy.

    The caller keeps the native journal record until this projection succeeds.
    Existing add_receipt commits the ordinary receipt, envelope and outbox event
    together. A crash between the native insert and this transaction is replayed.
    """
    if not context.matches_receipt(receipt):
        raise ValueError("native policy context does not match its receipt")
    ordinary = GuardReceipt(
        receipt_id=context.native_decision_id,
        timestamp=context.recorded_at,
        harness=context.harness,
        artifact_id=f"native-request:{receipt['request_digest']}",
        artifact_hash=str(receipt["request_digest"]),
        policy_decision=context.policy_action,
        capabilities_summary="Native pre-tool policy decision",
        changed_capabilities=(),
        provenance_summary="A native policy decision was recorded before the action.",
        artifact_name="Native action",
        source_scope="native_pre_tool",
    )
    envelope: dict[str, object] = {
        "harness": context.harness,
        "event_name": "PreToolUse",
        "policy_action": context.policy_action,
        "nativePolicyDecision": context.to_dict(),
    }
    if context.observed_policy_action is not None:
        envelope["observed_policy_action"] = context.observed_policy_action

    def same_existing() -> bool:
        existing = store.get_receipt(ordinary.receipt_id)
        if existing is None:
            return False
        stored_envelope = existing.get("action_envelope_json")
        if (
            not isinstance(stored_envelope, Mapping)
            or stored_envelope.get("nativePolicyDecision") != context.to_dict()
            or any(
                existing.get(key) != value
                for key, value in {
                    "timestamp": ordinary.timestamp,
                    "harness": ordinary.harness,
                    "artifact_id": ordinary.artifact_id,
                    "artifact_hash": ordinary.artifact_hash,
                    "policy_decision": ordinary.policy_decision,
                }.items()
            )
        ):
            raise ValueError("native policy decision receipt identity conflicts")
        return True

    if same_existing():
        return
    try:
        store.add_receipt(ordinary, action_envelope=envelope)
    except sqlite3.IntegrityError:
        if not same_existing():
            raise
