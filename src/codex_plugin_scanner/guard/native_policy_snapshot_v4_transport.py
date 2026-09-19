"""Strict scoped publication ACKs; the publisher still commits the readiness barrier."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_policy_authority_contract import NativePolicyAuthorityCapabilities
from .native_policy_authority_read import NativeVerifiedPolicyInputs
from .native_policy_snapshot_codec import _canonical_json_bytes_v3, _strict_json_loads_v3, _valid_digest_v3
from .native_policy_snapshot_constants import (
    _MAX_ACK_BYTES,
    _MAX_GENERATION,
    _PUBLISH_TIMEOUT_SECONDS,
    POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION,
    POLICY_SNAPSHOT_MAX_BYTES,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_v4 import ACK_SCHEMA, PUSH_SCHEMA
from .native_policy_snapshot_v4_generation import NativeV4Candidate, reserve_snapshot_v4

if TYPE_CHECKING:
    from .config import GuardConfig


@dataclass(frozen=True, slots=True, repr=False)
class NativeV4Publication:
    """ACK-bound candidate, not ready until source/resident/epoch revalidation."""

    candidate: NativeV4Candidate
    resident_generation: int


@dataclass(frozen=True, slots=True)
class _Ack:
    status: str
    generation: int
    policy_digest: str
    source_input_digest: str
    resident_generation: int


def _positive_generation(value: object) -> bool:
    return type(value) is int and 1 <= value <= _MAX_GENERATION


def decode_ack_v4(output: bytes | None) -> _Ack:
    """Reject duplicate keys, noncanonical types, unknown fields, and refusals."""
    if type(output) is not bytes or not 0 < len(output) <= _MAX_ACK_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_ack_invalid")
    decoded = _strict_json_loads_v3(output)
    if not isinstance(decoded, dict):
        raise NativePolicySnapshotError("native_policy_snapshot_ack_invalid")
    value = cast(dict[str, object], decoded)
    expected = {
        "schema",
        "status",
        "generation",
        "policy_digest",
        "source_input_digest",
        "idempotent",
        "resident_generation",
    }
    if set(value) != expected:
        raise NativePolicySnapshotError("native_policy_snapshot_ack_invalid")
    if (
        value["schema"] != ACK_SCHEMA
        or value["status"] not in ("accepted", POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION)
        or not _positive_generation(value["generation"])
        or not _positive_generation(value["resident_generation"])
        or not _valid_digest_v3(value["policy_digest"])
        or not _valid_digest_v3(value["source_input_digest"])
        or type(value["idempotent"]) is not bool
        or (value["status"] == POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION and value["idempotent"] is not False)
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_ack_invalid")
    return _Ack(
        cast(str, value["status"]),
        cast(int, value["generation"]),
        cast(str, value["policy_digest"]),
        cast(str, value["source_input_digest"]),
        cast(int, value["resident_generation"]),
    )


def snapshot_push_bytes_v4(candidate: NativeV4Candidate) -> bytes:
    payload = _canonical_json_bytes_v3(
        {
            "operation": "policy_snapshot_push",
            "deadline_budget_ms": int(_PUBLISH_TIMEOUT_SECONDS * 1_000),
            "request": {"schema": PUSH_SCHEMA, "snapshot": candidate.snapshot},
        }
    )
    if len(payload) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    return payload


def publish_snapshot_v4(
    *,
    config: GuardConfig | Mapping[str, object],
    guard_home: Path,
    executable: Path,
    runtime_identity: str,
    rule_digest: str,
    master_key: bytes,
    inputs: NativeVerifiedPolicyInputs,
    capabilities: NativePolicyAuthorityCapabilities,
    client: Callable[..., bytes | None],
    command_extensions: Mapping[str, object] | None = None,
    wall_clock: Callable[[], float] = time.time,
    monotonic_clock: Callable[[], float] = time.monotonic,
    minimum_generation: int | None = None,
    expected_resident_generation: int | None = None,
    candidate_factory: Callable[[int | None, float], NativeV4Candidate] | None = None,
) -> NativeV4Publication:
    """Push fresh signed bytes with at most one explicit recovery attempt.

    An initial push may create the resident. Its positive generation is
    returned for mandatory immediate fingerprint validation by the publisher,
    alongside a fresh source read and its existing publication epoch fence.
    """
    from .native_runtime import _isolated_environment

    if expected_resident_generation is not None and not _positive_generation(expected_resident_generation):
        raise NativePolicySnapshotError("native_policy_snapshot_ack_mismatch")
    try:
        for attempt in range(2):
            reservation_deadline = monotonic_clock() + _PUBLISH_TIMEOUT_SECONDS
            if candidate_factory is not None:
                candidate = candidate_factory(minimum_generation, reservation_deadline)
            else:
                candidate = reserve_snapshot_v4(
                    config=config,
                    guard_home=guard_home,
                    runtime_identity=runtime_identity,
                    rule_digest=rule_digest,
                    master_key=master_key,
                    inputs=inputs,
                    capabilities=capabilities,
                    issued_at_ms=int(wall_clock() * 1_000),
                    command_extensions=command_extensions,
                    minimum_generation=minimum_generation,
                    deadline_monotonic=reservation_deadline,
                )
            output = client(
                executable=executable,
                guard_home=guard_home,
                environment=_isolated_environment(),
                payload=snapshot_push_bytes_v4(candidate),
                deadline_monotonic=monotonic_clock() + _PUBLISH_TIMEOUT_SECONDS,
            )
            ack = decode_ack_v4(output)
            snapshot = candidate.snapshot
            if (
                ack.generation != snapshot["generation"]
                or ack.policy_digest != snapshot["policy_digest"]
                or ack.source_input_digest != snapshot["source_input_digest"]
                or (
                    expected_resident_generation is not None and ack.resident_generation != expected_resident_generation
                )
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_ack_mismatch")
            if ack.status == "accepted":
                if cast(int, snapshot["expires_at_ms"]) <= int(wall_clock() * 1_000):
                    raise NativePolicySnapshotError("native_policy_snapshot_expired")
                return NativeV4Publication(candidate, ack.resident_generation)
            if attempt:
                raise NativePolicySnapshotError("native_policy_snapshot_ack_mismatch")
            minimum_generation = ack.generation
        raise NativePolicySnapshotError("native_policy_snapshot_ack_mismatch")
    finally:
        master_key = b""
