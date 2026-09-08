"""Opaque Python transport helpers for native approval WebAuthn V4.

The bridge only carries the Portal proof envelope and invokes the resident.
Rust performs all semantic, policy, replay, and cryptographic validation.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from . import native_approval_protocol as _protocol
from . import native_approval_v4_protocol as _protocol_v4
from .native_approval_models import (
    NativeApprovalSession,
    NativeConsumedReceipt,
    _artifact_matches_session,
    _build_envelope,
    _new_consumed_receipt,
    _new_session,
    _receipt_matches_session,
)


class _BridgeRuntime(Protocol):
    """Private surface used by V4 helpers without importing the bridge class."""

    @property
    def last_error_code(self) -> str | None: ...

    def _fail(self, code: str) -> None: ...

    def _deadline(self, deadline: float | int | None) -> tuple[float, int] | None: ...

    def _request(
        self,
        *,
        operation: str,
        request: Mapping[str, object],
        deadline: float,
    ) -> dict[str, object] | None: ...


def create_v4_challenge(
    bridge: _BridgeRuntime,
    *,
    payload: dict[str, object],
    harness: str,
    guard_home: Path,
    home_dir: Path,
    cwd: Path | None,
    policy_snapshot: Mapping[str, object],
    deadline: float | None = None,
) -> NativeApprovalSession | None:
    """Create one resident-issued V4 challenge without local authority."""

    deadline_data = bridge._deadline(deadline)
    if deadline_data is None:
        bridge._fail("native_approval_deadline_expired")
        return None
    deadline_monotonic, budget_ms = deadline_data
    envelope_data = _build_envelope(
        payload=payload,
        harness=harness,
        guard_home=guard_home,
        home_dir=home_dir,
        cwd=cwd,
        policy_snapshot=policy_snapshot,
        deadline_budget_ms=budget_ms,
    )
    if envelope_data is None:
        bridge._fail("native_approval_request_invalid")
        return None
    envelope, encoded_envelope = envelope_data
    response = bridge._request(
        operation="approval_challenge_v4",
        request={
            "schema": _protocol_v4._CHALLENGE_REQUEST_V4_SCHEMA,
            "version": 4,
            "envelope": envelope,
        },
        deadline=deadline_monotonic,
    )
    challenge = _protocol.decode_native_approval_v4_challenge(response) if response is not None else None
    if challenge is None:
        if bridge.last_error_code is None:
            bridge._fail("native_approval_decoder_rejected")
        return None
    return _new_session(challenge, encoded_envelope)


def _artifact_payload(artifact: Mapping[str, object] | bytes) -> dict[str, object] | None:
    if isinstance(artifact, bytes):
        return _protocol._decode_json_object(artifact, maximum=_protocol._NATIVE_APPROVAL_MAX_BYTES)
    if isinstance(artifact, Mapping):
        return dict(artifact)
    return None


def _adapt_portal_proof(
    bridge: _BridgeRuntime,
    payload: dict[str, object],
    session: NativeApprovalSession,
) -> dict[str, object] | None:
    proof = _protocol.decode_native_approval_v4_proof(payload)
    if proof is None:
        return _protocol.decode_native_approval_v4_artifact(payload)
    proof_challenge = proof.get("challenge")
    if proof_challenge != session.challenge:
        bridge._fail("native_approval_binding_mismatch")
        return None
    assertion = proof.get("assertion")
    if not isinstance(assertion, dict):
        bridge._fail("native_approval_artifact_input_invalid")
        return None
    # Mechanical Portal-to-resident mapping; the resident remains authoritative.
    flattened = dict(cast(dict[str, object], proof_challenge))
    flattened["schema"] = _protocol_v4._ARTIFACT_V4_SCHEMA
    flattened["approved_action"] = "allow"
    flattened["webauthn"] = assertion
    return _protocol.decode_native_approval_v4_artifact(flattened)


def _decode_v4_artifact(
    bridge: _BridgeRuntime,
    session: NativeApprovalSession,
    artifact: Mapping[str, object] | bytes,
) -> dict[str, object] | None:
    payload = _artifact_payload(artifact)
    if payload is None:
        bridge._fail("native_approval_artifact_input_invalid")
        return None
    decoded = _adapt_portal_proof(bridge, payload, session)
    if decoded is None:
        if bridge.last_error_code is None:
            bridge._fail("native_approval_artifact_input_invalid")
        return None
    if not _artifact_matches_session(decoded, session):
        bridge._fail("native_approval_binding_mismatch")
        return None
    return decoded


def _phase_request(
    bridge: _BridgeRuntime,
    *,
    operation: str,
    schema: str,
    session: NativeApprovalSession,
    artifact: dict[str, object],
    deadline: float,
) -> dict[str, object] | None:
    envelope = _protocol._decode_json_object(session._envelope, maximum=_protocol._NATIVE_REQUEST_MAX_BYTES)
    if envelope is None:
        bridge._fail("native_approval_request_invalid")
        return None
    return bridge._request(
        operation=operation,
        request={"schema": schema, "version": 4, "envelope": envelope, "artifact": artifact},
        deadline=deadline,
    )


def _phase_receipt(
    bridge: _BridgeRuntime,
    response: dict[str, object] | None,
    *,
    phase: _protocol.NativeApprovalPhase,
    session: NativeApprovalSession,
) -> dict[str, object] | None:
    decoded = _protocol.decode_native_approval_v4_result(response, phase=phase) if response is not None else None
    if decoded is None:
        if bridge.last_error_code is None:
            bridge._fail("native_approval_decoder_rejected")
        return None
    receipt = cast(dict[str, object], decoded["receipt"])
    if not _receipt_matches_session(receipt, session):
        bridge._fail("native_approval_receipt_binding_mismatch")
        return None
    return receipt


def validate_and_consume_v4(
    bridge: _BridgeRuntime,
    session: NativeApprovalSession,
    artifact: Mapping[str, object] | bytes,
    *,
    deadline: float | None = None,
) -> NativeConsumedReceipt | None:
    """Validate and consume a V4 browser assertion through the resident."""

    if not isinstance(session, NativeApprovalSession):
        bridge._fail("native_approval_request_invalid")
        return None
    decoded_artifact = _decode_v4_artifact(bridge, session, artifact)
    if decoded_artifact is None:
        return None
    deadline_data = bridge._deadline(deadline)
    if deadline_data is None:
        bridge._fail("native_approval_deadline_expired")
        return None
    deadline_monotonic, _ = deadline_data
    validated_response = _phase_request(
        bridge,
        operation="approval_validate_v4",
        schema=_protocol_v4._VALIDATE_REQUEST_V4_SCHEMA,
        session=session,
        artifact=decoded_artifact,
        deadline=deadline_monotonic,
    )
    if _phase_receipt(bridge, validated_response, phase="validated", session=session) is None:
        return None
    consumed_response = _phase_request(
        bridge,
        operation="approval_consume_v4",
        schema=_protocol_v4._CONSUME_REQUEST_V4_SCHEMA,
        session=session,
        artifact=decoded_artifact,
        deadline=deadline_monotonic,
    )
    receipt = _phase_receipt(bridge, consumed_response, phase="consumed", session=session)
    return _new_consumed_receipt(receipt, session) if receipt is not None else None
