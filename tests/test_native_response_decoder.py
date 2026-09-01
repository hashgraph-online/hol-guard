from __future__ import annotations

from codex_plugin_scanner.guard.native_response_decoder import (
    decode_native_approval_challenge,
    decode_native_approval_result,
    native_error,
)


def _challenge() -> dict[str, object]:
    digest = "a" * 64
    return {
        "schema": "guard-native-approval-challenge.v3",
        "version": 3,
        "request_id": "sha256:" + digest,
        "request_digest": digest,
        "action_digest": "b" * 64,
        "action_type": "command",
        "operation": "execute",
        "intrinsic_action": "review",
        "minimum_action": "review",
        "floor_class": "approvable",
        "approval_eligible": True,
        "policy_generation": 1,
        "policy_digest": "c" * 64,
        "rule_digest": "d" * 64,
        "runtime_identity": "e" * 64,
        "runtime_protocol_version": 1,
        "runtime_package": "hol-guard-runtime",
        "runtime_version": "0.1.0",
        "runtime_binary_identity": "e" * 64,
        "harness": "claude-code",
        "workspace_binding": "f" * 64,
        "device_binding": "1" * 64,
        "installation_binding": "2" * 64,
        "publisher_binding": None,
        "artifact_binding": None,
        "scope_contract_version": "guard-native-scope.v1",
        "scope_contract_digest": "3" * 64,
        "scope_binding": "4" * 64,
        "resident_epoch": "5" * 64,
        "nonce": "6" * 64,
        "issued_at_ms": 1,
        "expires_at_ms": 2,
        "requested_action": "review",
        "signing_key_id": "7" * 64,
    }


def _receipt() -> dict[str, object]:
    challenge = _challenge()
    return {
        "schema": "guard-native-approval-receipt.v3",
        "version": 3,
        "phase": "validated",
        "request_id": challenge["request_id"],
        "request_digest": challenge["request_digest"],
        "action_digest": challenge["action_digest"],
        "policy_generation": challenge["policy_generation"],
        "policy_digest": challenge["policy_digest"],
        "rule_digest": challenge["rule_digest"],
        "runtime_identity": challenge["runtime_identity"],
        "runtime_protocol_version": 1,
        "runtime_package": challenge["runtime_package"],
        "runtime_version": challenge["runtime_version"],
        "runtime_binary_identity": challenge["runtime_binary_identity"],
        "harness": challenge["harness"],
        "workspace_binding": challenge["workspace_binding"],
        "device_binding": challenge["device_binding"],
        "installation_binding": challenge["installation_binding"],
        "publisher_binding": challenge["publisher_binding"],
        "artifact_binding": challenge["artifact_binding"],
        "scope_contract_version": challenge["scope_contract_version"],
        "scope_contract_digest": challenge["scope_contract_digest"],
        "scope_binding": challenge["scope_binding"],
        "resident_epoch": challenge["resident_epoch"],
        "nonce": challenge["nonce"],
        "issued_at_ms": challenge["issued_at_ms"],
        "expires_at_ms": challenge["expires_at_ms"],
        "decision": "allow",
        "requested_action": "review",
        "approved_action": "allow",
        "reason_code": "native_approval_validated",
        "nonce_digest": "8" * 64,
        "replay_claimed": True,
    }


def test_decoder_requires_epoch_and_accepts_full_native_contract() -> None:
    challenge = _challenge()
    assert decode_native_approval_challenge(challenge) == challenge
    del challenge["resident_epoch"]
    assert decode_native_approval_challenge(challenge) is None

    result = {
        "schema": "guard-native-approval-result.v3",
        "version": 3,
        "authority": "rust",
        "receipt": _receipt(),
    }
    assert decode_native_approval_result(result, phase="validated") == result
    receipt = result["receipt"]
    assert isinstance(receipt, dict)
    receipt["phase"] = "consumed"
    assert decode_native_approval_result(result, phase="validated") is None


def test_native_error_rejects_unregistered_approval_codes() -> None:
    assert native_error({"error": "native_approval_replay", "retryable": False}) == "native_approval_replay"
    assert native_error({"error": "native_approval_not_in_contract", "retryable": False}) is None
