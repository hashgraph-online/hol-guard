"""Presentation-only orchestration for native approval V3 and V4.

Python carries bounded transport data and presents approval prompts. The Rust
resident remains the only approval, policy, replay, and cryptographic authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from . import native_approval_bridge_v3 as _v3
from . import native_approval_protocol as _protocol
from . import native_approval_v4_bridge as _v4_bridge
from . import native_approval_v4_protocol as _protocol_v4
from .native_approval_models import (
    NativeApprovalSession,
    NativeConsumedReceipt,
    _receipt_matches_session,
)

NativeApprovalBridgeError = _v3.NativeApprovalBridgeError
NativeApprovalPhase = _v3.NativeApprovalPhase


class NativeApprovalBridge(_v3.NativeApprovalBridge):
    """Extend the V3 transport bridge with opaque V4 WebAuthn calls."""

    def create_v4_challenge(
        self,
        *,
        payload: dict[str, object],
        harness: str,
        guard_home: Path,
        home_dir: Path,
        cwd: Path | None,
        policy_snapshot: Mapping[str, object],
        deadline: float | None = None,
    ) -> NativeApprovalSession | None:
        """Create one resident-issued V4 challenge."""

        self._last_error_code = None
        _ = _v3._LAST_FAILURE_CODE.set(None)
        return _v4_bridge.create_v4_challenge(
            self,
            payload=payload,
            harness=harness,
            guard_home=guard_home,
            home_dir=home_dir,
            cwd=cwd,
            policy_snapshot=policy_snapshot,
            deadline=deadline,
        )

    def validate_and_consume_v4(
        self,
        session: NativeApprovalSession,
        artifact: Mapping[str, object] | bytes,
        *,
        deadline: float | None = None,
    ) -> NativeConsumedReceipt | None:
        """Validate then consume one browser assertion in Rust."""

        self._last_error_code = None
        _ = _v3._LAST_FAILURE_CODE.set(None)
        return _v4_bridge.validate_and_consume_v4(self, session, artifact, deadline=deadline)


def native_approval_continuation_allowed(
    receipt: object,
    *,
    session: NativeApprovalSession,
    request_id: str,
    request_digest: str,
    action_digest: str,
    policy_generation: int,
    policy_digest: str,
    harness: str,
) -> bool:
    """Require exact consumed native provenance before harness continuation."""

    if not isinstance(session, NativeApprovalSession):
        return False
    if session._challenge.get("version") != 4:
        return _v3.native_approval_continuation_allowed(
            receipt,
            session=session,
            request_id=request_id,
            request_digest=request_digest,
            action_digest=action_digest,
            policy_generation=policy_generation,
            policy_digest=policy_digest,
            harness=harness,
        )
    if not isinstance(receipt, NativeConsumedReceipt):
        return False
    if receipt._session is not session or receipt._provenance is not session._provenance:
        return False
    payload = receipt._receipt
    return (
        _protocol_v4._receipt_v4_is_valid(payload, phase="consumed")
        and payload.get("decision") == "allow"
        and payload.get("reason_code") == "native_approval_v4_consumed"
        and payload.get("replay_claimed") is True
        and payload.get("request_id") == session.request_id == request_id
        and payload.get("request_digest") == session.request_digest == request_digest
        and payload.get("action_digest") == session.action_digest == action_digest
        and payload.get("policy_generation") == session.policy_generation == policy_generation
        and session.policy_digest == policy_digest
        and session.harness == harness
        and _receipt_matches_session(payload, session)
    )


def native_approval_last_failure_code() -> str | None:
    """Return this context's finite bridge failure code."""

    return _v3.native_approval_last_failure_code()


_DEFAULT_BRIDGE = NativeApprovalBridge()


def create_native_approval_challenge(
    *,
    payload: dict[str, object],
    harness: str,
    guard_home: Path,
    home_dir: Path,
    cwd: Path | None,
    policy_snapshot: Mapping[str, object],
    deadline: float | None = None,
) -> NativeApprovalSession | None:
    """Create one V3 challenge through the default resident bridge."""

    return _DEFAULT_BRIDGE.create_challenge(
        payload=payload,
        harness=harness,
        guard_home=guard_home,
        home_dir=home_dir,
        cwd=cwd,
        policy_snapshot=policy_snapshot,
        deadline=deadline,
    )


def validate_and_consume_native_approval(
    session: NativeApprovalSession,
    artifact: Mapping[str, object] | bytes,
    *,
    deadline: float | None = None,
) -> NativeConsumedReceipt | None:
    """Validate then immediately consume one V3 signed artifact."""

    return _DEFAULT_BRIDGE.validate_and_consume(session, artifact, deadline=deadline)


def create_native_approval_v4_challenge(
    *,
    payload: dict[str, object],
    harness: str,
    guard_home: Path,
    home_dir: Path,
    cwd: Path | None,
    policy_snapshot: Mapping[str, object],
    deadline: float | None = None,
) -> NativeApprovalSession | None:
    """Create one V4 WebAuthn challenge through the default bridge."""

    return _DEFAULT_BRIDGE.create_v4_challenge(
        payload=payload,
        harness=harness,
        guard_home=guard_home,
        home_dir=home_dir,
        cwd=cwd,
        policy_snapshot=policy_snapshot,
        deadline=deadline,
    )


def validate_and_consume_native_approval_v4(
    session: NativeApprovalSession,
    artifact: Mapping[str, object] | bytes,
    *,
    deadline: float | None = None,
) -> NativeConsumedReceipt | None:
    """Validate then immediately consume one V4 browser assertion."""

    return _DEFAULT_BRIDGE.validate_and_consume_v4(session, artifact, deadline=deadline)


def native_consumed_receipt_allows_continuation(
    receipt: object,
    *,
    session: NativeApprovalSession,
    request_id: str,
    request_digest: str,
    action_digest: str,
    policy_generation: int,
    policy_digest: str,
    harness: str,
) -> bool:
    """Alias for the strict native consumed receipt gate."""

    return native_approval_continuation_allowed(
        receipt,
        session=session,
        request_id=request_id,
        request_digest=request_digest,
        action_digest=action_digest,
        policy_generation=policy_generation,
        policy_digest=policy_digest,
        harness=harness,
    )


present_native_approval_challenge = create_native_approval_challenge


# Decoder aliases expose only bounded transport checks; Rust owns authority.
decode_native_approval_artifact = _protocol.decode_native_approval_artifact
decode_native_approval_challenge = _protocol.decode_native_approval_challenge
decode_native_approval_result = _protocol.decode_native_approval_result
decode_native_approval_v4_artifact = _protocol.decode_native_approval_v4_artifact
decode_native_approval_v4_challenge = _protocol.decode_native_approval_v4_challenge
decode_native_approval_v4_proof = _protocol.decode_native_approval_v4_proof
decode_native_approval_v4_result = _protocol.decode_native_approval_v4_result


__all__ = [
    "NativeApprovalBridge",
    "NativeApprovalBridgeError",
    "NativeApprovalSession",
    "NativeConsumedReceipt",
    "create_native_approval_challenge",
    "create_native_approval_v4_challenge",
    "decode_native_approval_artifact",
    "decode_native_approval_challenge",
    "decode_native_approval_result",
    "decode_native_approval_v4_artifact",
    "decode_native_approval_v4_challenge",
    "decode_native_approval_v4_proof",
    "decode_native_approval_v4_result",
    "native_approval_continuation_allowed",
    "native_approval_last_failure_code",
    "native_consumed_receipt_allows_continuation",
    "present_native_approval_challenge",
    "validate_and_consume_native_approval",
    "validate_and_consume_native_approval_v4",
]
