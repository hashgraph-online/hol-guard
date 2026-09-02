"""Native resident publication protocol used by the publisher barrier."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

from .native_policy_snapshot_codec import _strict_json_loads_v3, _valid_digest_v3
from .native_policy_snapshot_constants import (
    _MAX_ACK_BYTES,
    _PUBLISH_TIMEOUT_SECONDS,
    POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_contract import _policy_snapshot_push_bytes_v3
from .native_policy_snapshot_generation import native_policy_snapshot_v3


def _decode_ack_v3(output: bytes | None) -> dict[str, object] | None:
    if output is None or len(output) == 0 or len(output) > _MAX_ACK_BYTES:
        return None
    try:
        value = _strict_json_loads_v3(output)
    except NativePolicySnapshotError:
        return None
    if not isinstance(value, dict) or set(value) != {
        "status",
        "generation",
        "policy_digest",
        "idempotent",
        "resident_generation",
    }:
        return None
    status = value.get("status")
    if not isinstance(status, str) or status not in {"accepted", POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION}:
        return None
    if (
        isinstance(value.get("generation"), bool)
        or not isinstance(value.get("generation"), int)
        or value.get("generation", 0) <= 0
        or not _valid_digest_v3(value.get("policy_digest"))
        or not isinstance(value.get("idempotent"), bool)
        or isinstance(value.get("resident_generation"), bool)
        or not isinstance(value.get("resident_generation"), int)
        or value.get("resident_generation", 0) <= 0
    ):
        return None
    if status == POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION and value.get("idempotent") is not False:
        return None
    return value


def _ack_from_resident_output(output: bytes | None) -> dict[str, object] | None:
    if output:
        try:
            value = _strict_json_loads_v3(output)
        except NativePolicySnapshotError:
            value = None
        else:
            error = value.get("error") if isinstance(value, dict) else None
            if (
                isinstance(value, dict)
                and isinstance(error, str)
                and error
                and error != POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
                and set(value) <= {"error", "retryable"}
            ):
                raise NativePolicySnapshotError(error)
    return _decode_ack_v3(output)


def _publish_snapshot_v3(
    *,
    publisher: Any,
    identity: Any,
    capabilities: Any,
    config: Mapping[str, object],
    master_key: bytes,
    client: Callable[..., bytes | None],
    renew_after_generation: int | None,
) -> tuple[dict[str, object], int]:
    """Materialize, push, and authenticate a snapshot, including one recovery retry."""

    from .native_resident_client import native_resident_client_failure_code
    from .native_runtime import _isolated_environment

    recovery_attempted = False
    while True:
        snapshot = native_policy_snapshot_v3(
            config=config,
            guard_home=publisher.guard_home,
            runtime_identity=identity.sha256,
            rule_digest=capabilities.rule_digest,
            policy_integrity_key=master_key,
            issued_at_ms=int(publisher._wall_clock() * 1_000),
            deadline_monotonic=publisher._monotonic_clock() + _PUBLISH_TIMEOUT_SECONDS,
            renew_after_generation=renew_after_generation,
        )
        encoded = _policy_snapshot_push_bytes_v3(snapshot)
        output = client(
            executable=identity.path,
            guard_home=publisher.guard_home,
            environment=_isolated_environment(),
            payload=encoded,
            deadline_monotonic=time.monotonic() + _PUBLISH_TIMEOUT_SECONDS,
        )
        ack = _ack_from_resident_output(output)
        if ack is None:
            raise NativePolicySnapshotError(
                native_resident_client_failure_code() or "native_policy_snapshot_ack_invalid"
            )
        if ack["status"] == POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION:
            floor = ack["generation"]
            candidate_generation = snapshot["generation"]
            if (
                recovery_attempted
                or isinstance(floor, bool)
                or not isinstance(floor, int)
                or not isinstance(candidate_generation, int)
                or floor < candidate_generation
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_ack_mismatch")
            renew_after_generation = floor
            recovery_attempted = True
            continue
        if ack["generation"] != snapshot["generation"] or ack["policy_digest"] != snapshot["policy_digest"]:
            raise NativePolicySnapshotError("native_policy_snapshot_ack_mismatch")
        resident_generation = ack.get("resident_generation")
        if (
            isinstance(resident_generation, bool)
            or not isinstance(resident_generation, int)
            or resident_generation <= 0
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_ack_mismatch")
        return snapshot, resident_generation
