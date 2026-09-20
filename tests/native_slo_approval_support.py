"""Typed synthetic evidence for source-only native approval controls."""

from __future__ import annotations

import hashlib
from pathlib import Path

from codex_plugin_scanner.guard.native_decision_receipt import (
    canonical_receipt_bytes,
    receipt_matches_edge,
    validate_native_decision_receipt,
)

from .native_review_approval_support import _test_request_digest
from .test_native_command_observations import _observations, _receipt, _rehash


def _review_evidence(
    harness: str, payload: dict[str, object], workspace: Path, *, reason: str
) -> tuple[dict[str, object], dict[str, object]]:
    """Bind a synthetic review to the exact positive fixture request."""

    observations = _observations()
    observations["observations"] = []
    observations["binding"]["observation_count"] = 0
    _rehash(observations)
    digest = _test_request_digest(harness, payload, workspace)
    receipt = _receipt(observations)
    receipt.update(
        request_id=f"sha256:{digest}",
        request_digest=digest,
        harness=harness,
        workspace_bound=workspace is not None,
        reason_code="native_policy_review",
        deadline_budget_ms=None,
    )
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    result = {
        "decision": receipt["decision"],
        "minimum_action": "review",
        "policy_action": receipt["policy_action"],
        "reason_code": receipt["reason_code"],
        "reason": reason,
        "command_extensions": observations,
    }
    assert validate_native_decision_receipt(receipt) == receipt
    assert receipt_matches_edge(
        {"harness": harness, "event_name": "PreToolUse", "payload_kind": "inline", "result": result}, receipt
    )
    return result, receipt


def _assert_recorded_policy_binding(row: dict[str, object], receipt: dict[str, object]) -> None:
    envelope = row["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert envelope["native_review_policy_binding"] == {
        "schema": "guard.native-review-policy-binding.v1",
        "policy_digest": receipt["policy_digest"],
        "rule_digest": receipt["rule_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "command_extensions": receipt["command_extensions"],
    }
    if receipt["harness"] == "codex":
        assert envelope["native_review_request_digest"] == receipt["request_digest"]
