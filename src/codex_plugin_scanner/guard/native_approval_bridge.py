"""Presentation-only orchestration for the native approval protocol.

Rust is the approval authority.  Python may present a privacy-safe challenge,
carry an external signed artifact, and make the resident's validate/consume
calls.  It does not sign, verify, lower floors, persist approval state, or
interpret legacy local receipts.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from pathlib import Path
from typing import cast

from . import native_approval_protocol as _protocol
from .native_approval_errors import FINITE_FAILURE_CODES, NATIVE_APPROVAL_ERROR_CODES
from .native_approval_models import (
    NativeApprovalSession,
    NativeConsumedReceipt,
    _artifact_matches_session,
    _build_envelope,
    _new_consumed_receipt,
    _new_session,
    _receipt_matches_session,
)
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status

NativeApprovalPhase = _protocol.NativeApprovalPhase
ClientRequest = Callable[..., bytes | None]
StatusProvider = Callable[[], object]
Clock = Callable[[], float]

_LAST_FAILURE_CODE: ContextVar[str | None] = ContextVar("native_approval_bridge_failure_code", default=None)


class NativeApprovalBridgeError(ValueError):
    """Finite, privacy-safe bridge error code."""

    def __init__(self, code: str):
        safe_code = (
            code if isinstance(code, str) and code in FINITE_FAILURE_CODES else "native_approval_transport_failed"
        )
        self.code: str = safe_code
        super().__init__(safe_code)


def _status_supports_approval(status: object, *, feature: str) -> bool:
    mode = getattr(status, "mode", None)
    if not isinstance(mode, str) or mode not in {"auto", "force"}:
        return False
    if getattr(status, "available", False) is not True or getattr(status, "compatible", False) is not True:
        return False
    identity = getattr(status, "identity", None)
    capabilities = getattr(status, "capabilities", None)
    if identity is None or capabilities is None:
        return False
    if getattr(capabilities, "protocol_version", None) != _protocol._NATIVE_PROTOCOL_VERSION:
        return False
    features = getattr(capabilities, "features", ())
    if not isinstance(features, (tuple, list, set, frozenset)) or not all(isinstance(item, str) for item in features):
        return False
    return feature in features and "resident-protocol-v2" in features


class NativeApprovalBridge:
    """Call the resident's three native approval operations in order."""

    def __init__(
        self,
        *,
        client_request: ClientRequest | None = None,
        status_provider: StatusProvider | None = None,
        environment_provider: Callable[[], Mapping[str, str]] | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._client_request: ClientRequest = client_request or native_resident_client_request
        self._status_provider: StatusProvider = status_provider or native_runtime_status
        self._environment_provider: Callable[[], Mapping[str, str]] = environment_provider or _isolated_environment
        self._clock: Clock = clock or time.monotonic
        self._last_error_code: str | None = None

    @property
    def last_error_code(self) -> str | None:
        return self._last_error_code

    def _fail(self, code: str) -> None:
        safe_code = (
            code if isinstance(code, str) and code in FINITE_FAILURE_CODES else "native_approval_transport_failed"
        )
        self._last_error_code = safe_code
        _ = _LAST_FAILURE_CODE.set(safe_code)

    def _deadline(self, deadline: float | int | None) -> tuple[float, int] | None:
        try:
            now = self._clock()
        except (OSError, RuntimeError, TypeError, ValueError, LookupError, OverflowError):
            return None
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            return None
        if deadline is None:
            deadline = now + 10.0
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
            or deadline <= now
        ):
            return None
        budget_ms = int((deadline - now) * 1000)
        if budget_ms <= 0 or budget_ms > _protocol._MAX_DEADLINE_BUDGET_MS:
            return None
        return float(deadline), budget_ms

    def _request(self, *, operation: str, request: Mapping[str, object], deadline: float) -> dict[str, object] | None:
        wire = _protocol._encode_json_object(
            {"operation": operation, "request": request}, maximum=_protocol._NATIVE_REQUEST_MAX_BYTES
        )
        if wire is None:
            self._fail("native_approval_request_invalid")
            return None
        if operation == "approval_challenge":
            feature = "native-approval-challenge-v3"
        elif operation == "approval_validate":
            feature = "native-approval-validation-v3"
        elif operation == "approval_consume":
            feature = "native-approval-consume-v3"
        else:
            self._fail("native_approval_request_invalid")
            return None
        try:
            status = self._status_provider()
        except (OSError, RuntimeError, TypeError, ValueError, LookupError, OverflowError):
            self._fail("native_approval_runtime_unavailable")
            return None
        if not _status_supports_approval(status, feature=feature):
            self._fail("native_approval_runtime_unavailable")
            return None
        identity = getattr(status, "identity", None)
        executable = getattr(identity, "path", None)
        envelope = request.get("envelope")
        source = envelope.get("source") if isinstance(envelope, dict) else None
        guard_home = source.get("guard_home") if isinstance(source, dict) else None
        if not isinstance(executable, Path) or not isinstance(guard_home, str):
            self._fail("native_approval_request_invalid")
            return None
        try:
            raw_response = self._client_request(
                executable=executable,
                guard_home=Path(guard_home),
                environment=self._environment_provider(),
                payload=wire,
                raw_hook_envelope=False,
                deadline_monotonic=deadline,
            )
        except (OSError, RuntimeError, TypeError, ValueError, LookupError, OverflowError):
            self._fail("native_approval_transport_failed")
            return None
        if (
            not isinstance(raw_response, bytes)
            or not raw_response
            or len(raw_response) > _protocol._NATIVE_RESPONSE_MAX_BYTES
        ):
            self._fail("native_approval_transport_failed")
            return None
        decoded = _protocol._decode_json_object(raw_response, maximum=_protocol._NATIVE_RESPONSE_MAX_BYTES)
        if decoded is None:
            self._fail("native_approval_decoder_rejected")
            return None
        if set(decoded) == {"error", "retryable"}:
            error = decoded.get("error")
            if (
                not isinstance(error, str)
                or error not in NATIVE_APPROVAL_ERROR_CODES
                or not isinstance(decoded.get("retryable"), bool)
            ):
                self._fail("native_approval_decoder_rejected")
                return None
            self._fail(cast(str, error))
            return None
        return decoded

    def create_challenge(
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
        """Return one detached challenge; retain only private transport state."""

        self._last_error_code = None
        deadline_data = self._deadline(deadline)
        if deadline_data is None:
            self._fail("native_approval_deadline_expired")
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
            self._fail("native_approval_request_invalid")
            return None
        envelope, encoded_envelope = envelope_data
        response = self._request(
            operation="approval_challenge",
            request={
                "schema": _protocol._CHALLENGE_REQUEST_SCHEMA,
                "version": 3,
                "envelope": envelope,
            },
            deadline=deadline_monotonic,
        )
        challenge = _protocol.decode_native_approval_challenge(response) if response is not None else None
        if challenge is None:
            if self._last_error_code is None:
                self._fail("native_approval_decoder_rejected")
            return None
        return _new_session(challenge, encoded_envelope)

    def validate_and_consume(
        self,
        session: NativeApprovalSession,
        artifact: Mapping[str, object] | bytes,
        *,
        deadline: float | None = None,
    ) -> NativeConsumedReceipt | None:
        """Validate an external artifact and immediately consume it in Rust."""

        self._last_error_code = None
        if not isinstance(session, NativeApprovalSession):
            self._fail("native_approval_request_invalid")
            return None
        if isinstance(artifact, bytes):
            artifact_payload = _protocol._decode_json_object(artifact, maximum=_protocol._NATIVE_APPROVAL_MAX_BYTES)
        elif isinstance(artifact, Mapping):
            artifact_payload = dict(artifact)
        else:
            artifact_payload = None
        decoded_artifact = _protocol.decode_native_approval_artifact(artifact_payload)
        if decoded_artifact is None:
            self._fail("native_approval_artifact_input_invalid")
            return None
        if not _artifact_matches_session(decoded_artifact, session):
            self._fail("native_approval_binding_mismatch")
            return None
        deadline_data = self._deadline(deadline)
        if deadline_data is None:
            self._fail("native_approval_deadline_expired")
            return None
        deadline_monotonic, _ = deadline_data
        envelope = _protocol._decode_json_object(session._envelope, maximum=_protocol._NATIVE_REQUEST_MAX_BYTES)
        if envelope is None:
            self._fail("native_approval_request_invalid")
            return None
        validated_response = self._request(
            operation="approval_validate",
            request={
                "schema": _protocol._VALIDATE_REQUEST_SCHEMA,
                "version": 3,
                "envelope": envelope,
                "artifact": decoded_artifact,
            },
            deadline=deadline_monotonic,
        )
        validated = _protocol.decode_native_approval_result(validated_response, phase="validated")
        if validated is None:
            if self._last_error_code is None:
                self._fail("native_approval_decoder_rejected")
            return None
        validated_receipt = cast(dict[str, object], validated["receipt"])
        if not _receipt_matches_session(validated_receipt, session):
            self._fail("native_approval_receipt_binding_mismatch")
            return None
        # No presentation-layer decision or storage point exists between calls.
        consume_envelope = _protocol._decode_json_object(session._envelope, maximum=_protocol._NATIVE_REQUEST_MAX_BYTES)
        if consume_envelope is None:
            self._fail("native_approval_request_invalid")
            return None
        consumed_response = self._request(
            operation="approval_consume",
            request={
                "schema": _protocol._CONSUME_REQUEST_SCHEMA,
                "version": 3,
                "envelope": consume_envelope,
                "artifact": decoded_artifact,
            },
            deadline=deadline_monotonic,
        )
        consumed = _protocol.decode_native_approval_result(consumed_response, phase="consumed")
        if consumed is None:
            if self._last_error_code is None:
                self._fail("native_approval_decoder_rejected")
            return None
        receipt = cast(dict[str, object], consumed["receipt"])
        if not _receipt_matches_session(receipt, session):
            self._fail("native_approval_receipt_binding_mismatch")
            return None
        return _new_consumed_receipt(receipt, session)


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

    if not isinstance(receipt, NativeConsumedReceipt) or not isinstance(session, NativeApprovalSession):
        return False
    if receipt._session is not session or receipt._provenance is not session._provenance:
        return False
    payload = receipt._receipt
    return (
        _protocol._receipt_is_valid(payload, phase="consumed")
        and payload.get("decision") == "allow"
        and payload.get("reason_code") == "native_approval_consumed"
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

    return _LAST_FAILURE_CODE.get()


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
    """Create one challenge through the default resident bridge."""

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
    """Validate then immediately consume an external signed artifact."""

    return _DEFAULT_BRIDGE.validate_and_consume(session, artifact, deadline=deadline)


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


__all__ = [
    "NativeApprovalBridge",
    "NativeApprovalBridgeError",
    "NativeApprovalSession",
    "NativeConsumedReceipt",
    "create_native_approval_challenge",
    "decode_native_approval_artifact",
    "decode_native_approval_challenge",
    "decode_native_approval_result",
    "native_approval_continuation_allowed",
    "native_approval_last_failure_code",
    "native_consumed_receipt_allows_continuation",
    "present_native_approval_challenge",
    "validate_and_consume_native_approval",
]


# Keep decoder imports explicit and stable for callers of this orchestration
# module; the implementation remains owned by ``native_approval_protocol``.
decode_native_approval_artifact = _protocol.decode_native_approval_artifact
decode_native_approval_challenge = _protocol.decode_native_approval_challenge
decode_native_approval_result = _protocol.decode_native_approval_result
