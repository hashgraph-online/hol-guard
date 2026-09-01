"""Adversarial tests for the presentation-only native approval bridge."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.native_approval_bridge import (
    NativeApprovalBridge,
    NativeConsumedReceipt,
    decode_native_approval_artifact,
    decode_native_approval_challenge,
    decode_native_approval_result,
    native_approval_continuation_allowed,
)

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_DIGEST_D = "d" * 64
_REQUEST_ID = "sha256:" + _DIGEST_A


def _challenge() -> dict[str, object]:
    return {
        "schema": "guard-native-approval-challenge.v3",
        "version": 3,
        "request_id": _REQUEST_ID,
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
        "scope_contract_version": "guard-approval-scope.v1",
        "scope_contract_digest": _DIGEST_A,
        "scope_binding": _DIGEST_B,
        "resident_epoch": _DIGEST_C,
        "nonce": _DIGEST_D,
        "issued_at_ms": 1_000,
        "expires_at_ms": 2_000,
        "requested_action": "review",
        "signing_key_id": _DIGEST_C,
    }


def _artifact() -> dict[str, object]:
    challenge = _challenge()
    challenge.pop("signing_key_id")
    challenge["approved_action"] = "allow"
    challenge["integrity"] = {
        "algorithm": "ed25519",
        "key_id": _DIGEST_C,
        "signature": "e" * 128,
    }
    challenge["schema"] = "guard-native-approval-artifact.v3"
    return challenge


def _result(*, phase: str, challenge: dict[str, object] | None = None) -> dict[str, object]:
    source = challenge or _challenge()
    return {
        "schema": "guard-native-approval-result.v3",
        "version": 3,
        "authority": "rust",
        "receipt": {
            "schema": "guard-native-approval-receipt.v3",
            "version": 3,
            "request_id": source["request_id"],
            "request_digest": source["request_digest"],
            "action_digest": source["action_digest"],
            "policy_generation": source["policy_generation"],
            "decision": "allow",
            "requested_action": source["requested_action"],
            "approved_action": "allow",
            "reason_code": f"native_approval_{phase}",
            "nonce_digest": _DIGEST_D,
            "replay_claimed": True,
        },
    }


def _status(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "hol-guard-runtime"),
        capabilities=SimpleNamespace(
            protocol_version=1,
            features=(
                "resident-protocol-v2",
                "native-approval-challenge-v3",
                "native-approval-validation-v3",
                "native-approval-consume-v3",
            ),
        ),
    )


def _bridge(
    tmp_path: Path, responses: list[dict[str, object] | bytes], calls: list[dict[str, object]]
) -> NativeApprovalBridge:
    def client(**kwargs: object) -> bytes:
        request = json.loads(bytes(kwargs["payload"]).decode("utf-8"))
        calls.append(request)
        response = responses.pop(0)
        return response if isinstance(response, bytes) else json.dumps(response, separators=(",", ":")).encode()

    return NativeApprovalBridge(
        client_request=client,
        status_provider=lambda: _status(tmp_path),
        environment_provider=lambda: {},
        clock=lambda: 100.0,
    )


def _create_session(bridge: NativeApprovalBridge, tmp_path: Path):
    return bridge.create_challenge(
        payload={"event": "PreToolUse", "tool_name": "Bash", "secret": "stays resident"},
        harness="claude-code",
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        cwd=tmp_path,
        policy_snapshot={"generation": 7, "policy_digest": _DIGEST_C, "runtime_identity": _DIGEST_A},
        deadline=100.5,
    )


def test_challenge_is_privacy_safe_and_wire_operation_is_exact(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    bridge = _bridge(tmp_path, [_challenge()], calls)

    session = _create_session(bridge, tmp_path)

    assert session is not None
    assert session.challenge == _challenge()
    assert "raw_payload" not in session.challenge
    assert "stays resident" not in json.dumps(session.challenge)
    presented = session.challenge
    presented["action_digest"] = _DIGEST_C
    assert session.action_digest == _DIGEST_B
    assert calls[0]["operation"] == "approval_challenge"
    request = calls[0]["request"]
    assert isinstance(request, dict)
    assert request["schema"] == "guard-native-approval-challenge-request.v3"
    assert request["version"] == 3
    assert set(request) == {"schema", "version", "envelope"}


def test_validate_then_consume_is_immediate_and_receipt_is_bound(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    bridge = _bridge(tmp_path, [_challenge(), _result(phase="validated"), _result(phase="consumed")], calls)
    session = _create_session(bridge, tmp_path)
    assert session is not None
    artifact = _artifact()

    consumed = bridge.validate_and_consume(session, artifact, deadline=100.5)

    assert isinstance(consumed, NativeConsumedReceipt)
    assert [call["operation"] for call in calls] == [
        "approval_challenge",
        "approval_validate",
        "approval_consume",
    ]
    for call in calls[1:]:
        request = call["request"]
        assert isinstance(request, dict)
        assert request["artifact"] == artifact
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


def test_preconsume_forged_cross_request_policy_and_harness_values_fail(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    bridge = _bridge(tmp_path, [_challenge(), _result(phase="validated"), _result(phase="consumed")], calls)
    session = _create_session(bridge, tmp_path)
    assert session is not None
    consumed = bridge.validate_and_consume(session, _artifact(), deadline=100.5)
    assert consumed is not None

    valid = {
        "session": session,
        "request_id": session.request_id,
        "request_digest": session.request_digest,
        "action_digest": session.action_digest,
        "policy_generation": session.policy_generation,
        "policy_digest": session.policy_digest,
        "harness": session.harness,
    }
    assert native_approval_continuation_allowed(consumed, **valid)
    assert not native_approval_continuation_allowed(consumed.receipt, **valid)
    assert not native_approval_continuation_allowed(_result(phase="validated")["receipt"], **valid)
    for mutation in (
        {"request_id": "other-request"},
        {"action_digest": _DIGEST_C},
        {"policy_generation": 8},
        {"policy_digest": _DIGEST_B},
        {"harness": "cursor"},
    ):
        mutated = valid | mutation
        assert not native_approval_continuation_allowed(consumed, **mutated)


def test_cross_request_artifact_is_rejected_before_native_validation(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    bridge = _bridge(tmp_path, [_challenge()], calls)
    session = _create_session(bridge, tmp_path)
    assert session is not None
    artifact = _artifact()
    artifact["request_digest"] = _DIGEST_C

    assert bridge.validate_and_consume(session, artifact, deadline=100.5) is None
    assert [call["operation"] for call in calls] == ["approval_challenge"]
    assert bridge.last_error_code == "native_approval_binding_mismatch"


def test_legacy_database_row_and_forged_receipt_cannot_authorize(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    bridge = _bridge(tmp_path, [_challenge(), _result(phase="validated"), _result(phase="consumed")], calls)
    session = _create_session(bridge, tmp_path)
    assert session is not None
    consumed = bridge.validate_and_consume(session, _artifact(), deadline=100.5)
    assert consumed is not None
    context = {
        "session": session,
        "request_id": session.request_id,
        "request_digest": session.request_digest,
        "action_digest": session.action_digest,
        "policy_generation": session.policy_generation,
        "policy_digest": session.policy_digest,
        "harness": session.harness,
    }

    forged = consumed.receipt
    forged["reason_code"] = "native_approval_consumed"
    legacy_row = {"approval_id": "local", "action": "allow", "claim_disposition": "consumed"}
    assert not native_approval_continuation_allowed(forged, **context)
    assert not native_approval_continuation_allowed(legacy_row, **context)


def test_decoders_reject_floor_lowering_unknown_fields_duplicate_json_and_unknown_errors() -> None:
    challenge = _challenge()
    lowered = challenge | {"minimum_action": "sandbox-required"}
    assert decode_native_approval_challenge(lowered) is None
    assert decode_native_approval_challenge(challenge | {"forged": True}) is None
    for key in ("action_type", "operation", "intrinsic_action", "minimum_action", "requested_action"):
        assert decode_native_approval_challenge(challenge | {key: []}) is None
    assert decode_native_approval_result(_result(phase="validated"), phase="consumed") is None
    assert decode_native_approval_artifact(_artifact() | {"extra": "forged"}) is None

    calls: list[dict[str, object]] = []
    bridge = _bridge(
        Path("/tmp/native-approval-test"),
        [b'{"schema":"guard-native-approval-challenge.v3","schema":"forged"}'],
        calls,
    )
    assert (
        bridge.create_challenge(
            payload={},
            harness="claude-code",
            guard_home=Path("/tmp/guard-home"),
            home_dir=Path("/tmp/home"),
            cwd=None,
            policy_snapshot={"generation": 1, "policy_digest": _DIGEST_A, "runtime_identity": _DIGEST_B},
            deadline=100.5,
        )
        is None
    )
    assert bridge.last_error_code == "native_approval_decoder_rejected"

    unknown_error_bridge = _bridge(
        Path("/tmp/native-approval-test"),
        [b'{"error":"native_approval_secret_leak","retryable":false}'],
        [],
    )
    assert (
        unknown_error_bridge.create_challenge(
            payload={},
            harness="claude-code",
            guard_home=Path("/tmp/guard-home"),
            home_dir=Path("/tmp/home"),
            cwd=None,
            policy_snapshot={"generation": 1, "policy_digest": _DIGEST_A, "runtime_identity": _DIGEST_B},
            deadline=100.5,
        )
        is None
    )
    assert unknown_error_bridge.last_error_code == "native_approval_decoder_rejected"
