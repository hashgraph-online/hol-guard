"""Bounded, presentation-only transport coverage for native approval V4."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

from codex_plugin_scanner.guard.native_approval_bridge import (
    NativeApprovalBridge,
    decode_native_approval_v4_artifact,
    decode_native_approval_v4_challenge,
    decode_native_approval_v4_proof,
    decode_native_approval_v4_result,
    native_approval_continuation_allowed,
)
from codex_plugin_scanner.guard.native_approval_protocol import _decode_json_object

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_DIGEST_D = "d" * 64


def _challenge() -> dict[str, object]:
    return {
        "schema": "guard-native-approval-challenge.v4",
        "version": 4,
        "request_id": "sha256:" + _DIGEST_A,
        "request_digest": _DIGEST_A,
        "action_digest": _DIGEST_B,
        "action_type": "command",
        "operation": "execute",
        "intrinsic_action": "review",
        "minimum_action": "review",
        "floor_class": "approvable",
        "approval_eligible": True,
        "policy_generation": 7,
        "policy_digest": _DIGEST_C,
        "rule_digest": _DIGEST_D,
        "runtime_identity": _DIGEST_A,
        "runtime_protocol_version": 1,
        "runtime_package": "hol-guard-runtime",
        "runtime_version": "3.0.1",
        "runtime_binary_identity": _DIGEST_A,
        "harness": "claude-code",
        "workspace_binding": _DIGEST_B,
        "device_binding": _DIGEST_C,
        "installation_binding": _DIGEST_D,
        "publisher_binding": None,
        "artifact_binding": None,
        "scope_contract_version": "guard-native-scope.v1",
        "scope_contract_digest": _DIGEST_A,
        "scope_binding": _DIGEST_B,
        "resident_epoch": _DIGEST_C,
        "nonce": _DIGEST_D,
        "issued_at_ms": 1_000,
        "expires_at_ms": 2_000,
        "requested_action": "review",
        "signing_key_id": _DIGEST_C,
        "webauthn": {
            "rp_id": "example.com",
            "origin": "https://example.com",
            "credential_id": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "algorithm": -8,
            "challenge": "A" * 43,
            "user_verification": "required",
        },
    }


def _artifact() -> dict[str, object]:
    challenge = _challenge()
    challenge["schema"] = "guard-native-approval-artifact.v4"
    challenge["approved_action"] = "allow"
    challenge["webauthn"] = {
        "id": "AQ",
        "rawId": "AQ",
        "type": "public-key",
        "response": {
            "authenticatorData": "AQ",
            "clientDataJSON": "AQ",
            "signature": "AQ",
            "userHandle": None,
        },
    }
    return challenge


def _proof() -> dict[str, object]:
    challenge = _challenge()
    return {
        "schema": "guard-native-approval-proof.v4",
        "challenge": challenge,
        "assertion": cast(dict[str, object], _artifact()["webauthn"]),
    }


def _result(*, phase: str) -> dict[str, object]:
    source = _challenge()
    receipt = {
        "schema": "guard-native-approval-receipt.v4",
        "version": 4,
        "phase": phase,
        "request_id": source["request_id"],
        "request_digest": source["request_digest"],
        "action_digest": source["action_digest"],
        "policy_generation": source["policy_generation"],
        "policy_digest": source["policy_digest"],
        "rule_digest": source["rule_digest"],
        "runtime_identity": source["runtime_identity"],
        "runtime_protocol_version": source["runtime_protocol_version"],
        "runtime_package": source["runtime_package"],
        "runtime_version": source["runtime_version"],
        "runtime_binary_identity": source["runtime_binary_identity"],
        "harness": source["harness"],
        "workspace_binding": source["workspace_binding"],
        "device_binding": source["device_binding"],
        "installation_binding": source["installation_binding"],
        "publisher_binding": source["publisher_binding"],
        "artifact_binding": source["artifact_binding"],
        "scope_contract_version": source["scope_contract_version"],
        "scope_contract_digest": source["scope_contract_digest"],
        "scope_binding": source["scope_binding"],
        "resident_epoch": source["resident_epoch"],
        "nonce": source["nonce"],
        "issued_at_ms": source["issued_at_ms"],
        "expires_at_ms": source["expires_at_ms"],
        "decision": "allow",
        "requested_action": source["requested_action"],
        "approved_action": "allow",
        "reason_code": f"native_approval_v4_{phase}",
        "nonce_digest": _DIGEST_D,
        "replay_claimed": True,
        "rp_id": "example.com",
        "origin": "https://example.com",
        "credential_id_digest": _DIGEST_A,
        "algorithm": -8,
        "authenticator_sign_count": 1,
    }
    return {
        "schema": "guard-native-approval-result.v4",
        "version": 4,
        "authority": "rust",
        "receipt": receipt,
    }


def _status(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "hol-guard-runtime"),
        capabilities=SimpleNamespace(
            protocol_version=1,
            features=("resident-protocol-v2", "native-approval-webauthn-v4"),
        ),
    )


def test_v4_decoders_bound_browser_shape_without_verifying_it() -> None:
    challenge = _challenge()
    assert decode_native_approval_v4_challenge(challenge) == challenge
    artifact = _artifact()
    assert decode_native_approval_v4_artifact(artifact) == artifact
    # These bytes are intentionally not a real WebAuthn signature.  Python
    # preserves the opaque response and leaves verification to Rust.
    webauthn = cast(dict[str, object], artifact["webauthn"])
    response = cast(dict[str, object], webauthn["response"])
    assert response["signature"] == "AQ"
    assert decode_native_approval_v4_proof(_proof()) == _proof()


def test_v4_proof_decoder_accepts_portal_opaque_action_labels() -> None:
    proof = _proof()
    challenge = cast(dict[str, object], proof["challenge"])
    challenge.update(
        {
            "request_id": "local-1",
            "action_type": "shell_command",
            "operation": "guard.review.resolveExact",
            "intrinsic_action": "execute",
            "minimum_action": "allow",
            "floor_class": "allow_once",
            "runtime_protocol_version": 4,
        }
    )
    assert decode_native_approval_v4_proof(proof) == proof


def test_v4_shape_rejects_duplicate_unknown_and_mismatched_browser_fields() -> None:
    assert _decode_json_object(b'{"id":"AQ","id":"Ag"}', maximum=1024) is None
    challenge = _challenge()
    challenge_webauthn = cast(dict[str, object], challenge["webauthn"])
    challenge["webauthn"] = dict(challenge_webauthn, extra=True)
    assert decode_native_approval_v4_challenge(challenge) is None

    artifact = _artifact()
    assertion = dict(cast(dict[str, object], artifact["webauthn"]))
    assertion["rawId"] = "Ag"
    artifact["webauthn"] = assertion
    assert decode_native_approval_v4_artifact(artifact) is None


def test_v4_challenge_origin_supports_loopback_and_requires_exact_rp_id() -> None:
    for rp_id, origin in (
        ("localhost", "http://localhost"),
        ("127.0.0.1", "http://127.0.0.1:8080"),
        ("[::1]", "http://[::1]:8080"),
        ("[2001:db8::1]", "https://[2001:db8::1]"),
    ):
        challenge = _challenge()
        challenge["webauthn"] = dict(
            cast(dict[str, object], challenge["webauthn"]),
            rp_id=rp_id,
            origin=origin,
        )
        assert decode_native_approval_v4_challenge(challenge) == challenge

    challenge = _challenge()
    challenge["webauthn"] = dict(
        cast(dict[str, object], challenge["webauthn"]),
        rp_id="example.com",
        origin="https://other.example.com",
    )
    assert decode_native_approval_v4_challenge(challenge) is None

    proof = _proof()
    proof["extra"] = True
    assert decode_native_approval_v4_proof(proof) is None

    proof = _proof()
    proof["challenge"] = dict(cast(dict[str, object], proof["challenge"]), request_id="sha256:" + _DIGEST_B)
    # The decoder only checks the transport shape. Binding to the actual
    # session belongs to the bridge and, finally, to Rust.
    assert decode_native_approval_v4_proof(proof) is not None

    artifact = _artifact()
    artifact_webauthn = cast(dict[str, object], artifact["webauthn"])
    response = dict(cast(dict[str, object], artifact_webauthn["response"]))
    response["userHandle"] = "A" * 700
    artifact["webauthn"] = dict(artifact_webauthn, response=response)
    assert decode_native_approval_v4_artifact(artifact) is None


def test_v4_result_is_phase_and_context_bounded() -> None:
    result = _result(phase="consumed")
    assert decode_native_approval_v4_result(result, phase="consumed") == result
    assert decode_native_approval_v4_result(result, phase="validated") is None
    receipt = result["receipt"]
    assert isinstance(receipt, dict)
    receipt["authenticator_sign_count"] = -1
    assert decode_native_approval_v4_result(result, phase="consumed") is None


def test_v4_bridge_forwards_assertion_immediately(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    responses = [_challenge(), _result(phase="validated"), _result(phase="consumed")]

    def client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        request_value = json.loads(payload.decode("utf-8"))
        assert isinstance(request_value, dict)
        request = cast(dict[str, object], request_value)
        calls.append(request)
        return json.dumps(responses.pop(0), separators=(",", ":")).encode()

    bridge = NativeApprovalBridge(
        client_request=client,
        status_provider=lambda: _status(tmp_path),
        environment_provider=lambda: {},
        clock=lambda: 100.0,
    )
    session = bridge.create_v4_challenge(
        payload={"event": "PreToolUse", "tool_name": "Bash"},
        harness="claude-code",
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        cwd=tmp_path,
        policy_snapshot={"generation": 7, "policy_digest": _DIGEST_C, "runtime_identity": _DIGEST_A},
        deadline=100.5,
    )
    assert session is not None
    consumed = bridge.validate_and_consume_v4(session, _artifact(), deadline=100.5)
    assert consumed is not None
    assert [call["operation"] for call in calls] == [
        "approval_challenge_v4",
        "approval_validate_v4",
        "approval_consume_v4",
    ]
    assert native_approval_continuation_allowed(
        consumed,
        session=session,
        request_id=session.request_id,
        request_digest=session.request_digest,
        action_digest=session.action_digest,
        policy_generation=session.policy_generation,
        policy_digest=session.policy_digest,
        harness=session.harness,
    )


def test_v4_bridge_adapts_portal_proof_without_local_authority(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    responses = [_challenge(), _result(phase="validated"), _result(phase="consumed")]

    def client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        request_value = json.loads(payload.decode("utf-8"))
        assert isinstance(request_value, dict)
        request = cast(dict[str, object], request_value)
        calls.append(request)
        return json.dumps(responses.pop(0), separators=(",", ":")).encode()

    bridge = NativeApprovalBridge(
        client_request=client,
        status_provider=lambda: _status(tmp_path),
        environment_provider=lambda: {},
        clock=lambda: 100.0,
    )
    session = bridge.create_v4_challenge(
        payload={"event": "PreToolUse", "tool_name": "Bash"},
        harness="claude-code",
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        cwd=tmp_path,
        policy_snapshot={"generation": 7, "policy_digest": _DIGEST_C, "runtime_identity": _DIGEST_A},
        deadline=100.5,
    )
    assert session is not None
    consumed = bridge.validate_and_consume_v4(session, _proof(), deadline=100.5)
    assert consumed is not None
    request = calls[1]["request"]
    assert isinstance(request, dict)
    artifact = cast(dict[str, object], request["artifact"])
    assert isinstance(artifact, dict)
    assert artifact["schema"] == "guard-native-approval-artifact.v4"
    assert artifact["approved_action"] == "allow"
    assert artifact["webauthn"] == _proof()["assertion"]


def test_v4_bridge_rejects_proof_bound_to_another_session(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    def client(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        request_value = json.loads(payload.decode("utf-8"))
        assert isinstance(request_value, dict)
        calls.append(cast(dict[str, object], request_value))
        return json.dumps(_challenge(), separators=(",", ":")).encode()

    bridge = NativeApprovalBridge(
        client_request=client,
        status_provider=lambda: _status(tmp_path),
        environment_provider=lambda: {},
        clock=lambda: 100.0,
    )
    session = bridge.create_v4_challenge(
        payload={"event": "PreToolUse", "tool_name": "Bash"},
        harness="claude-code",
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        cwd=tmp_path,
        policy_snapshot={"generation": 7, "policy_digest": _DIGEST_C, "runtime_identity": _DIGEST_A},
        deadline=100.5,
    )
    assert session is not None
    proof = _proof()
    proof_challenge = cast(dict[str, object], proof["challenge"])
    proof["challenge"] = dict(proof_challenge, request_id="sha256:" + _DIGEST_B)
    assert bridge.validate_and_consume_v4(session, proof, deadline=100.5) is None
    assert bridge.last_error_code == "native_approval_binding_mismatch"
    assert len(calls) == 1
