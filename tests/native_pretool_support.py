"""Synthetic typed PreToolUse edges and verified policy-domain fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path

from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes

from .native_review_approval_support import _test_request_digest
from .test_native_command_observations import _observations, _rehash


def _edge(harness: str, event: str, action_type: str = "unknown") -> dict[str, object]:
    edge: dict[str, object] = {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        "harness": harness,
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "result": {
            "schema": "guard-pre-tool-result.v1",
            "version": 1,
            "authority": "rust",
            "action": {
                "schema": "guard-pre-tool-action.v1",
                "version": 1,
                "harness": harness,
                "event": event,
                "action_type": action_type,
                "operation": "unknown",
                "bounded": True,
                "sensitive_target": False,
            },
            "decision": "deny",
            "policy_action": "review",
            "minimum_action": "review",
            "reason_code": "native_pre_tool_unknown_review",
            "reason": "HOL Guard requires review for this bounded action.",
            "explicitly_benign": False,
        },
    }
    result = edge["result"]
    assert isinstance(result, dict)
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "request-1",
        "request_digest": "a" * 64,
        "harness": harness,
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": None,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": result["decision"],
        "model_output_action": "not_applicable",
        "policy_action": result["policy_action"],
        "observed_policy_action": None,
        "reason_code": result["reason_code"],
        "workspace_bound": False,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 100,
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    edge["receipt"] = receipt
    return edge


def _sync_receipt(edge: dict[str, object]) -> None:
    result = edge["result"]
    receipt = edge["receipt"]
    assert isinstance(result, dict)
    assert isinstance(receipt, dict)
    receipt.update(
        {
            "decision": result["decision"],
            "policy_action": result["policy_action"],
            "reason_code": result["reason_code"],
        }
    )
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()


def _bound_network_review_edge(harness: str, *, payload: dict[str, object], workspace: Path) -> dict[str, object]:
    edge = _edge(harness, "PreToolUse", "network")
    # This approval path requires a verified policy domain. Keep the shared
    # decoder fixture minimal and bind only this synthetic network review.
    observations = _observations()
    observations["observations"] = []
    observations["binding"]["observation_count"] = 0
    _rehash(observations)
    result = edge["result"]
    receipt = edge["receipt"]
    assert isinstance(result, dict)
    assert isinstance(receipt, dict)
    action = result["action"]
    assert isinstance(action, dict)
    action["operation"] = "request"
    result["command_extensions"] = observations
    digest = _test_request_digest(harness, payload, workspace)
    receipt.update(
        {
            "request_id": f"sha256:{digest}",
            "request_digest": digest,
            "policy_digest": "b" * 64,
            "rule_digest": "c" * 64,
            "runtime_identity": "d" * 64,
            "workspace_bound": True,
            "command_extensions": dict(observations["binding"]),
        }
    )
    _sync_receipt(edge)
    return edge
