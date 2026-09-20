"""Authenticated off-hook observation and retirement of one native authority."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _strict_json_loads_v3, _valid_digest_v3
from .native_policy_snapshot_constants import _MAX_GENERATION, _PUBLISH_TIMEOUT_SECONDS, NativePolicySnapshotError
from .native_policy_snapshot_policy import _scope_digest_v3

_MAX_CONTROL_BYTES = 4 * 1024
_OBSERVATION_DOMAIN = b"hol-guard-policy-snapshot-observation-v1\0"
_OBSERVATION_RESPONSE_DOMAIN = b"hol-guard-policy-snapshot-observation-response-v1\0"
_WITHDRAWAL_DOMAIN = b"hol-guard-policy-snapshot-withdrawal-v1\0"
_WITHDRAWAL_RESPONSE_DOMAIN = b"hol-guard-policy-snapshot-withdrawal-response-v1\0"
_CONTROL_REFUSALS = frozenset(
    {
        "native_policy_snapshot_writer_busy",
        "native_policy_snapshot_withdrawal_stale",
        "native_policy_snapshot_durable_authority_changed",
    }
)


@dataclass(frozen=True)
class NativeAuthorityReference:
    fingerprint: str
    generation_floor: int
    policy_digest: str
    usable_snapshot: bool


@dataclass(frozen=True)
class NativeAuthorityObservation:
    runtime_identity: str
    scope_digest: str
    resident_generation: int
    authority: NativeAuthorityReference | None


@dataclass(frozen=True)
class NativeAuthorityRetirement:
    runtime_identity: str
    scope_digest: str
    resident_generation: int
    generation: int
    policy_digest: str


def _invalid() -> NativePolicySnapshotError:
    return NativePolicySnapshotError("native_policy_snapshot_control_response_invalid")


def _fields(value: object, expected: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise _invalid()
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or not _valid_digest_v3(value):
        raise _invalid()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_GENERATION:
        raise _invalid()
    return value


def _reference(value: object) -> NativeAuthorityReference | None:
    if value is None:
        return None
    record = _fields(value, {"fingerprint", "generation_floor", "policy_digest", "usable_snapshot"})
    usable = record["usable_snapshot"]
    if type(usable) is not bool:
        raise _invalid()
    return NativeAuthorityReference(
        _digest(record["fingerprint"]),
        _generation(record["generation_floor"]),
        _digest(record["policy_digest"]),
        usable,
    )


def _reference_value(reference: NativeAuthorityReference | None) -> dict[str, object] | None:
    if reference is None:
        return None
    if type(reference) is not NativeAuthorityReference:
        raise _invalid()
    value: dict[str, object] = {
        "fingerprint": reference.fingerprint,
        "generation_floor": reference.generation_floor,
        "policy_digest": reference.policy_digest,
        "usable_snapshot": reference.usable_snapshot,
    }
    _reference(value)
    return value


def _signed_request(intent: dict[str, object], verifier_key: bytes, domain: bytes) -> dict[str, object]:
    if type(verifier_key) is not bytes or len(verifier_key) != 32:
        raise NativePolicySnapshotError("native_policy_snapshot_control_invalid")
    mac = hmac.new(verifier_key, domain + _canonical_json_bytes_v3(intent), hashlib.sha256).hexdigest()
    return {"intent": intent, "mac": mac}


def _remaining(deadline: float) -> float:
    if type(deadline) not in {int, float}:
        raise NativePolicySnapshotError("native_policy_snapshot_control_deadline_exceeded")
    try:
        finite = math.isfinite(deadline)
    except OverflowError:
        finite = False
    if not finite:
        raise NativePolicySnapshotError("native_policy_snapshot_control_deadline_exceeded")
    remaining = deadline - time.monotonic()
    if remaining < 0.001:
        raise NativePolicySnapshotError("native_policy_snapshot_control_deadline_exceeded")
    return remaining


def _response(
    output: bytes | None, request: dict[str, object], verifier_key: bytes, domain: bytes
) -> dict[str, object]:
    if output is None:
        raise NativePolicySnapshotError("native_policy_snapshot_control_transport_failed")
    if type(output) is not bytes or not 0 < len(output) <= _MAX_CONTROL_BYTES:
        raise _invalid()
    try:
        value = _strict_json_loads_v3(output)
        if _canonical_json_bytes_v3(value) != output:
            raise _invalid()
    except (NativePolicySnapshotError, RecursionError, TypeError, ValueError) as error:
        raise _invalid() from error
    if isinstance(value, dict) and set(value) <= {"error", "retryable"}:
        error = value.get("error")
        if (
            isinstance(error, str)
            and error in _CONTROL_REFUSALS
            and ("retryable" not in value or type(value["retryable"]) is bool)
        ):
            raise NativePolicySnapshotError(error)
        raise _invalid()
    envelope = _fields(value, {"response", "mac"})
    response = envelope["response"]
    if not isinstance(response, dict):
        raise _invalid()
    mac = _digest(envelope["mac"])
    expected = hmac.new(verifier_key, domain + _canonical_json_bytes_v3(response), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise NativePolicySnapshotError("native_policy_snapshot_control_unauthenticated")
    if response.get("request_sha256") != hashlib.sha256(_canonical_json_bytes_v3(request)).hexdigest():
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    return response


def _exchange(
    *,
    executable: Path,
    guard_home: Path,
    operation: str,
    request: dict[str, object],
    verifier_key: bytes,
    response_domain: bytes,
    deadline_monotonic: float,
    client: Callable[..., bytes | None] | None,
) -> dict[str, object]:
    from .native_policy_control_transport import native_policy_control_request
    from .native_runtime import _isolated_environment

    _remaining(deadline_monotonic)
    # Keep both the original aggregate deadline and the existing publication IPC ceiling.
    deadline = min(deadline_monotonic, time.monotonic() + _PUBLISH_TIMEOUT_SECONDS)
    budget_ms = min(9_000, int(_remaining(deadline) * 1_000))
    payload = _canonical_json_bytes_v3({"operation": operation, "request": request, "deadline_budget_ms": budget_ms})
    if len(payload) > _MAX_CONTROL_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_control_invalid")
    _remaining(deadline)
    try:
        output = (native_policy_control_request if client is None else client)(
            executable=executable,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=payload,
            deadline_monotonic=deadline,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        raise NativePolicySnapshotError("native_policy_snapshot_control_transport_failed") from None
    _remaining(deadline)
    response = _response(output, request, verifier_key, response_domain)
    _remaining(deadline)
    return response


def observe_native_authority(
    *,
    executable: Path,
    guard_home: Path,
    runtime_identity: str,
    verifier_key: bytes,
    deadline_monotonic: float,
    client: Callable[..., bytes | None] | None = None,
) -> NativeAuthorityObservation:
    """Authenticate one current native precondition, without granting readiness."""

    _remaining(deadline_monotonic)
    runtime = _digest(runtime_identity)
    scope = _scope_digest_v3(guard_home)
    nonce = secrets.token_hex(32)
    request = _signed_request(
        {
            "schema": "guard-policy-snapshot-observation.v1",
            "runtime_identity": runtime,
            "scope_digest": scope,
            "nonce": nonce,
        },
        verifier_key,
        _OBSERVATION_DOMAIN,
    )
    response = _fields(
        _exchange(
            executable=executable,
            guard_home=guard_home,
            operation="policy_snapshot_observe",
            request=request,
            verifier_key=verifier_key,
            response_domain=_OBSERVATION_RESPONSE_DOMAIN,
            deadline_monotonic=deadline_monotonic,
            client=client,
        ),
        {"schema", "runtime_identity", "scope_digest", "resident_generation", "nonce", "request_sha256", "authority"},
    )
    if (
        response["schema"] != "guard-policy-snapshot-observation-response.v1"
        or response["runtime_identity"] != runtime
        or response["scope_digest"] != scope
        or response["nonce"] != nonce
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    result = NativeAuthorityObservation(
        runtime, scope, _generation(response["resident_generation"]), _reference(response["authority"])
    )
    _remaining(deadline_monotonic)
    return result


def withdraw_native_authority(
    *,
    executable: Path,
    guard_home: Path,
    observation: NativeAuthorityObservation,
    retirement_generation: int,
    retirement_policy_digest: str,
    verifier_key: bytes,
    deadline_monotonic: float,
    client: Callable[..., bytes | None] | None = None,
) -> NativeAuthorityRetirement:
    """Retire one exact observation; a lost response is never inferred to be success."""

    _remaining(deadline_monotonic)
    if type(observation) is not NativeAuthorityObservation:
        raise _invalid()
    runtime = _digest(observation.runtime_identity)
    scope = _digest(observation.scope_digest)
    if scope != _scope_digest_v3(guard_home):
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    resident_generation = _generation(observation.resident_generation)
    authority = _reference_value(observation.authority)
    generation = _generation(retirement_generation)
    digest = _digest(retirement_policy_digest)
    if observation.authority is not None and generation <= observation.authority.generation_floor:
        raise NativePolicySnapshotError("native_policy_snapshot_control_invalid")
    request = _signed_request(
        {
            "schema": "guard-policy-snapshot-withdrawal.v1",
            "runtime_identity": runtime,
            "scope_digest": scope,
            "resident_generation": resident_generation,
            "expected_authority": authority,
            "retirement_generation": generation,
            "retirement_policy_digest": digest,
        },
        verifier_key,
        _WITHDRAWAL_DOMAIN,
    )
    response = _fields(
        _exchange(
            executable=executable,
            guard_home=guard_home,
            operation="policy_snapshot_withdraw",
            request=request,
            verifier_key=verifier_key,
            response_domain=_WITHDRAWAL_RESPONSE_DOMAIN,
            deadline_monotonic=deadline_monotonic,
            client=client,
        ),
        {
            "schema",
            "status",
            "runtime_identity",
            "scope_digest",
            "resident_generation",
            "generation",
            "policy_digest",
            "request_sha256",
        },
    )
    if (
        response["schema"] != "guard-policy-snapshot-withdrawal-response.v1"
        or response["status"] != "withdrawn"
        or response["runtime_identity"] != runtime
        or response["scope_digest"] != scope
        or _generation(response["resident_generation"]) != resident_generation
        or _generation(response["generation"]) != generation
        or response["policy_digest"] != digest
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    _remaining(deadline_monotonic)
    return NativeAuthorityRetirement(runtime, scope, resident_generation, generation, digest)
