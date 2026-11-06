"""Shared typed native envelopes for transport and host-rendering tests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


def _identity_payload(receipt: Mapping[str, object]) -> dict[str, object]:
    identity = {
        "schema": "guard-native-hook-decision-identity.v1",
        "version": 1,
        "request_id": receipt["request_id"],
        "request_digest": receipt["request_digest"],
        "harness": receipt["harness"],
        "event_name": receipt["event_name"],
        "payload_kind": receipt["payload_kind"],
        "policy_generation": receipt["policy_generation"],
        "policy_digest": receipt["policy_digest"],
        "rule_digest": receipt["rule_digest"],
        "runtime_identity": receipt["runtime_identity"],
        "decision": receipt["decision"],
        "model_output_action": receipt["model_output_action"],
        "policy_action": receipt["policy_action"],
        "observed_policy_action": receipt["observed_policy_action"],
        "reason_code": receipt["reason_code"],
        "workspace_bound": receipt["workspace_bound"],
        "source_ref_external_allowed": receipt["source_ref_external_allowed"],
        "reviewed_output_sha256": receipt["reviewed_output_sha256"],
        "observe_mode": receipt["observe_mode"],
        "deadline_budget_ms": receipt["deadline_budget_ms"],
    }
    if "command_extensions" in receipt:
        identity["command_extensions"] = receipt["command_extensions"]
    if "prompt_risk_classes" in receipt:
        identity["prompt_risk_classes"] = receipt["prompt_risk_classes"]
    if "business_review_binding" in receipt:
        identity["business_review_binding"] = receipt["business_review_binding"]
    return identity


def canonical_receipt_bytes(receipt: Mapping[str, object]) -> bytes:
    """Return the decision identity encoding the Rust edge hashes into ``decision_id``."""

    return json.dumps(
        _identity_payload(receipt),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _edge(harness: str, event: str, action_type: str = "unknown") -> dict[str, object]:
    edge: dict[str, object] = {
        "schema": "guard-hook-edge-result.v2",
        "authority": "rust",
        # The edge answers with the request id the envelope carried.
        "request_id": "request-1",
        "harness": harness,
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "harness_response": {"decision": "block", "reason": "HOL Guard requires review for this bounded action."},
        "containment_route": "none",
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
