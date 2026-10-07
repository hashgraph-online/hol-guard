"""Thin offline native content bridge; no business decision or admission."""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from collections.abc import Mapping
from contextvars import ContextVar, Token
from threading import Lock
from typing import TYPE_CHECKING, cast

from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _digest_v3,
    _strict_json_loads_v3,
    _valid_digest_v3,
)
from .native_policy_snapshot_constants import POLICY_SNAPSHOT_MAX_BYTES, NativePolicySnapshotError

if TYPE_CHECKING:
    from .native_runtime_values import NativeRuntimeStatus

_DEADLINE: ContextVar[float | None] = ContextVar("business_snapshot_deadline", default=None)
_INSPECTED: OrderedDict[tuple[str, str], dict[str, object]] = OrderedDict()
_CACHE_LOCK = Lock()
_CACHE_LIMIT = 128


def begin_business_deadline(deadline: float | None) -> Token[float | None]:
    if deadline is not None and (isinstance(deadline, bool) or not math.isfinite(deadline)):
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_invalid")
    existing = _DEADLINE.get()
    if existing is None:
        chosen = deadline
    elif deadline is None:
        chosen = existing
    else:
        chosen = min(existing, deadline)
    return _DEADLINE.set(chosen)


def end_business_deadline(token: Token[float | None]) -> None:
    _DEADLINE.reset(token)


def _remaining_timeout() -> float:
    deadline = _DEADLINE.get()
    remaining = 5.0 if deadline is None else min(5.0, deadline - time.monotonic())
    if remaining <= 0:
        raise NativePolicySnapshotError("native_policy_snapshot_deadline_exceeded")
    return remaining


_INSPECTION_FIELDS = frozenset(
    {
        "schema",
        "version",
        "authenticity",
        "currentness",
        "snapshot_digest",
        "config_digest",
        "policy_digest",
        "business_policy_present",
    }
)


def capture_business_binding(value: Mapping[str, object]) -> dict[str, object]:
    """Own an immutable-in-flight wire copy; Rust still validates semantics."""

    encoded = _canonical_json_bytes_v3(value)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    result = _strict_json_loads_v3(encoded)
    if not isinstance(result, dict):
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    return cast(dict[str, object], result)


def _selected_runtime() -> NativeRuntimeStatus:
    from .native_runtime import native_runtime_status

    _remaining_timeout()
    status = native_runtime_status(deadline_monotonic=_DEADLINE.get())
    required = {
        "native-policy-snapshot-build-v1",
        "native-policy-snapshot-inspect-v1",
        "native-business-policy-retained-floor-v1",
    }
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not required <= set(status.capabilities.features)
    ):
        raise NativePolicySnapshotError("native_business_policy_consumer_unavailable")
    return status


def _native_content_operation(
    command: str,
    value: Mapping[str, object],
    *,
    status: NativeRuntimeStatus | None = None,
) -> dict[str, object]:
    from .native_runtime import _run_native_process

    if command not in {"policy-snapshot-build", "policy-snapshot-inspect"}:
        raise NativePolicySnapshotError("native_business_policy_consumer_unavailable")
    selected = status if status is not None else _selected_runtime()
    assert selected.identity is not None
    # CPython JSON/subprocess serialization creates immutable key copies for
    # constructor requests. Reference cleanup is best effort, not zeroization
    # or isolated custody; the native constructor separately zeroizes its input.
    encoded = _canonical_json_bytes_v3(value)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    output = _run_native_process(
        selected.identity.path,
        (command, "--stdin"),
        input_text=encoded.decode("utf-8"),
        timeout_seconds=_remaining_timeout(),
    )
    if output is None or len(output.encode("utf-8")) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    result = _strict_json_loads_v3(output.encode("utf-8"))
    if not isinstance(result, dict):
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    return cast(dict[str, object], result)


def validate_business_snapshot_content(
    snapshot: Mapping[str, object],
    *,
    allow_empty_mac: bool = False,
    verify_digests: bool = True,
    deadline_monotonic: float | None = None,
) -> None:
    token = begin_business_deadline(deadline_monotonic)
    try:
        _validate_business_snapshot_content(snapshot, allow_empty_mac=allow_empty_mac, verify_digests=verify_digests)
    finally:
        end_business_deadline(token)


def _validate_business_snapshot_content(
    snapshot: Mapping[str, object],
    *,
    allow_empty_mac: bool,
    verify_digests: bool,
) -> None:
    """Validate content with Rust; does not authenticate MAC or currentness."""

    value = dict(snapshot)
    if allow_empty_mac:
        integrity = value.get("integrity")
        if isinstance(integrity, Mapping) and integrity.get("mac") == "":
            value["integrity"] = {**integrity, "mac": "0" * 64}
    status = _selected_runtime()
    assert status.identity is not None
    digest = _digest_v3(value)
    key = (status.identity.sha256, digest)
    with _CACHE_LOCK:
        cached = _INSPECTED.get(key)
        result = dict(cached) if cached is not None else None
        if cached is not None:
            _INSPECTED.move_to_end(key)
    if result is None:
        result = _native_content_operation("policy-snapshot-inspect", value, status=status)
    if (
        set(result) != _INSPECTION_FIELDS
        or result.get("schema") != "guard-native-policy-content-inspection.v1"
        or type(result.get("version")) is not int
        or result.get("version") != 1
        or result.get("authenticity") != "not_checked"
        or result.get("currentness") != "not_checked"
        or result.get("business_policy_present") is not True
        or any(
            not _valid_digest_v3(result.get(field)) for field in ("snapshot_digest", "config_digest", "policy_digest")
        )
        or result.get("snapshot_digest") != digest
    ):
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    if verify_digests and any(result[field] != snapshot.get(field) for field in ("config_digest", "policy_digest")):
        raise NativePolicySnapshotError("native_policy_snapshot_digest_mismatch")
    # Cache only finite content projections, never MAC authentication or time
    # admission. Each caller still performs its own requested digest checks.
    with _CACHE_LOCK:
        _INSPECTED[key] = dict(result)
        _INSPECTED.move_to_end(key)
        while len(_INSPECTED) > _CACHE_LIMIT:
            _INSPECTED.popitem(last=False)


def build_native_business_snapshot(
    request: Mapping[str, object],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, object]:
    token = begin_business_deadline(deadline_monotonic)
    try:
        return _build_native_business_snapshot(request)
    finally:
        end_business_deadline(token)


def _build_native_business_snapshot(request: Mapping[str, object]) -> dict[str, object]:
    """Forward a typed constructor request, then verify returned binding/content."""

    result = _native_content_operation("policy-snapshot-build", request)
    for field in (
        "generation",
        "runtime_identity",
        "rule_digest",
        "mode",
        "scope_contract",
        "effective_policy",
        "issued_at_ms",
        "expires_at_ms",
        "business_policy",
    ):
        if result.get(field) != request.get(field):
            raise NativePolicySnapshotError("native_business_policy_content_invalid")
    if result.get("command_extensions") != request.get("command_extensions"):
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    validate_business_snapshot_content(result)
    return cast(dict[str, object], result)
