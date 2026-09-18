"""Independent malformed-wire, redaction, and receipt replay vectors."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_command_observations import validate_native_command_observations
from codex_plugin_scanner.guard.native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt
from codex_plugin_scanner.guard.native_hook_edge import _decode_pre_tool_result


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


def _receipt(extensions: dict[str, Any] | None) -> dict[str, Any]:
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
    if extensions is not None:
        value["command_extensions"] = copy.deepcopy(extensions["binding"])
    identity = {
        **{key: item for key, item in value.items() if key not in {"authority", "decision_id"}},
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
    assert validate_native_command_observations(observations) == observations
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


@pytest.mark.parametrize(
    "field,value",
    [
        ("segment_index", True),
        ("segment_index", 128),
        ("segment_index", -1),
        ("executable", "/private/ollama"),
        ("executable", "secret token"),
        ("detail", "raw secret command"),
    ],
)
def test_untrusted_evidence_is_rejected_even_with_recomputed_digest(field: str, value: object) -> None:
    observations = _observations()
    observations["observations"][0]["matcher_evidence"][0][field] = value
    _rehash(observations)
    assert validate_native_command_observations(observations) is None


def test_safe_variant_suppression_is_exact_and_cannot_hide_other_segments() -> None:
    observations = _observations()
    item = observations["observations"][0]
    item["matcher_evidence"].append({**_evidence(), "segment_index": 1})
    item["safe_variants"] = [{"match_class": "safe-variant", "variant_id": "help", "matcher_evidence": [_evidence()]}]
    item["effective_segment_indexes"] = [1]
    _rehash(observations)
    assert validate_native_command_observations(observations) == observations
    item["effective_segment_indexes"] = []
    _rehash(observations)
    assert validate_native_command_observations(observations) is None


def test_permission_only_evidence_and_uncertainty_cannot_disappear() -> None:
    observations = _observations()
    observations["permission_observations"] = [
        {
            "extension_id": "command.github",
            "permission_id": "command.github.permission.read-remote",
            "matcher_evidence": [{**_evidence(), "executable": "gh"}],
            "uncertainty_reasons": ["matcher-failure"],
        }
    ]
    observations["binding"]["observation_count"] = 2
    observations["binding"]["uncertainty_count"] = 1
    _rehash(observations)
    assert validate_native_command_observations(observations) == observations
    observations["binding"]["uncertainty_count"] = 0
    assert validate_native_command_observations(observations) is None
    observations["binding"]["uncertainty_count"] = 1
    observations["permission_observations"][0]["permission_id"] = "command.ollama.permission.push"
    _rehash(observations)
    assert validate_native_command_observations(observations) is None


def test_unknown_fields_duplicates_limits_and_unbound_error_reject() -> None:
    original = _observations()
    bad = copy.deepcopy(original)
    bad["raw_command"] = "secret"
    assert validate_native_command_observations(bad) is None
    bad = copy.deepcopy(original)
    bad["observations"] *= 2
    bad["binding"]["observation_count"] = 2
    _rehash(bad)
    assert validate_native_command_observations(bad) is None
    bad = copy.deepcopy(original)
    bad["observations"][0]["matcher_evidence"] *= 8_193
    _rehash(bad)
    assert validate_native_command_observations(bad) is None
    bad = copy.deepcopy(original)
    bad["evaluation_error"] = "native_command_evaluation_failed"
    _rehash(bad)
    assert validate_native_command_observations(bad) is None
    assert not _decode_pre_tool_result({"command_extensions": bad}, harness="claude-code")
