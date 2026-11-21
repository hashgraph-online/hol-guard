"""Receipt replay vectors binding native command observations to a decision.

The wire validator itself lives in the resident; its malformed-wire and
redaction vectors are in `native_command_extension_evidence_tests.rs`.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from codex_plugin_scanner.guard.native_decision_receipt import (
    receipt_matches_edge,
    validate_native_decision_receipt,
)
from tests.native_pretool_edge_fixtures import canonical_receipt_bytes


def _evidence() -> dict[str, object]:
    return {"segment_index": 0, "executable": "ollama", "detail": "Matched bounded structured command constraints."}


def _observations() -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "guard.native-command-observations.v1",
        "binding": {
            "schema": "guard.native-command-receipt-binding.v1",
            "program_digest": "a" * 64,
            "catalog_digest": "b" * 64,
            "trust_digest": "c" * 64,
            "control_revision": 3,
            "managed_control_revision": 5,
            "control_effective_digest": "d" * 64,
            "observations_digest": "",
            "observation_count": 1,
            "uncertainty_count": 0,
        },
        "observations": [
            {
                "extension_id": "command.ollama",
                "extension_version": "1.0.0",
                "rule_id": "command.ollama.push",
                "rule_version": "1.0.0",
                "match_class": "unsafe",
                "match_classes": ["unsafe"],
                "matcher_evidence": [_evidence()],
                "safe_variants": [],
                "uncertainty_reasons": [],
                "effective_segment_indexes": [0],
            }
        ],
        "permission_observations": [],
        "evaluation_error": None,
    }
    _rehash(value)
    return value


def _rehash(value: dict[str, Any]) -> None:
    payload = {field: value[field] for field in ("observations", "permission_observations", "evaluation_error")}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    value["binding"]["observations_digest"] = hashlib.sha256(
        b"hol-guard.native-command-observations.v1\0" + canonical
    ).hexdigest()


def _receipt(extensions: dict[str, Any] | None, *, review_anchor: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "",
        "request_id": "request-1",
        "request_digest": "a" * 64,
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": "b" * 64,
        "rule_digest": "c" * 64,
        "runtime_identity": "d" * 64,
        "decision": "deny",
        "model_output_action": "not_applicable",
        "policy_action": "review",
        "observed_policy_action": None,
        "reason_code": "native_command_extension_review",
        "workspace_bound": True,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 750,
    }
    if review_anchor:
        # Evidence only; the store never persists it and it stays out of the
        # decision identity.
        value["review_anchor_digest"] = "9" * 64
    if extensions is not None:
        value["command_extensions"] = copy.deepcopy(extensions["binding"])
    identity = {
        **{key: item for key, item in value.items() if key not in {"authority", "decision_id", "review_anchor_digest"}},
        "schema": "guard-native-hook-decision-identity.v1",
    }
    value["decision_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    return value


def _edge(extensions: dict[str, Any]) -> dict[str, Any]:
    receipt = _receipt(extensions)
    return {
        "harness": "claude-code",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "request_id": "request-1",
        "result": {
            "decision": "deny",
            "policy_action": "review",
            "observed_policy_action": None,
            "reason_code": receipt["reason_code"],
            "reviewed_output_sha256": None,
            "observe_mode": False,
            "command_extensions": extensions,
        },
    }


def test_observations_bind_exact_redacted_evidence_to_receipt() -> None:
    observations = _observations()
    receipt = _receipt(observations)
    assert validate_native_decision_receipt(receipt) == receipt
    assert receipt_matches_edge(_edge(observations), receipt)
    assert not receipt_matches_edge(_edge(observations), _receipt(None))
    for field in (
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "control_effective_digest",
        "observations_digest",
    ):
        changed = copy.deepcopy(receipt)
        changed["command_extensions"][field] = "e" * 64
        assert validate_native_decision_receipt(changed) is None
    for field in ("control_revision", "managed_control_revision"):
        changed = copy.deepcopy(receipt)
        changed["command_extensions"][field] += 1
        assert validate_native_decision_receipt(changed) is None
        changed_result = copy.deepcopy(observations)
        changed_result["binding"][field] += 1
        assert not receipt_matches_edge(_edge(changed_result), receipt)


def test_prompt_extension_binding_cannot_be_detached_from_its_native_receipt() -> None:
    observations = _observations()
    receipt = {**_receipt(observations), "event_name": "UserPromptSubmit"}
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    edge = _edge(observations)
    edge["event_name"] = "UserPromptSubmit"
    edge["result"]["action"] = {"event": "UserPromptSubmit", "action_type": "prompt"}
    assert validate_native_decision_receipt(receipt) == receipt
    assert receipt_matches_edge(edge, receipt)

    changed = copy.deepcopy(edge)
    changed["result"]["command_extensions"]["binding"]["program_digest"] = "e" * 64
    assert not receipt_matches_edge(changed, receipt)
