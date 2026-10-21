"""Validate native review wire bindings; no Python risk or permission decision."""

from __future__ import annotations

from collections.abc import Mapping

from ..native_bash_protocol import ARTIFACT_ID, NativeBashError
from ..native_bash_reply import supported_execution_assurance, validate_review_lineage
from ..native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt


def valid_bound_bash_review(
    prepared: Mapping[str, object],
    *,
    harness: str,
    exact_token: object,
    review_binding: object,
    decision: Mapping[str, object],
    native_receipt: object,
) -> bool:
    review = prepared.get("review")
    subject = prepared.get("subject")
    context = subject.get("context") if isinstance(subject, Mapping) else None
    receipt = validate_native_decision_receipt(native_receipt)
    host = {"omp": "omp-input-rewrite-v1", "pi": "pi-input-mutation-v1"}.get(harness)
    try:
        lineage = validate_review_lineage(prepared.get("review_lineage"))
    except NativeBashError:
        return False
    return (
        prepared.get("artifact_id") == ARTIFACT_ID
        and prepared.get("artifact_hash") == exact_token == review_binding == lineage["artifact_hash"]
        and isinstance(exact_token, str)
        and exact_token.startswith("guard-approval-context:v1:")
        and isinstance(review, Mapping)
        and review.get("decision") == decision
        and review.get("receipt") == native_receipt
        and isinstance(subject, Mapping)
        and subject.get("schema") == "guard.bash-subject.v1"
        and supported_execution_assurance(subject.get("execution_assurance"))
        and host is not None
        and isinstance(context, Mapping)
        and context.get("host") == host
        and receipt is not None
        and receipt_matches_edge(
            {
                "harness": harness,
                "event_name": "PreToolUse",
                "payload_kind": receipt["payload_kind"],
                "result": decision,
            },
            receipt,
        )
    )
