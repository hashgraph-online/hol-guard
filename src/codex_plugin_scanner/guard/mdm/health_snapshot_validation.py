"""Strict binding validation for machine health snapshots carried by lease outboxes.

The native runtime owns the snapshot shape: canonical bytes, exact keys, the
closed vocabularies and the binding to the lease claims. This module frames
the request and maps the answer onto the lease contract's error.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Protocol, cast

HEALTH_SNAPSHOT_BINDING_FEATURE = "native-health-snapshot-binding-v1"
HEALTH_SNAPSHOT_BINDING_COMMAND = "health-snapshot-binding"
HEALTH_SNAPSHOT_BINDING_SCHEMA = "health-snapshot-binding.v1"
_MAX_SNAPSHOT_BYTES = 256 * 1024
_MAX_UINT64 = (1 << 64) - 1
_STATUS_TIMEOUT_SECONDS = 10.0
_COMMAND_TIMEOUT_SECONDS = 30.0
_OUTPUT_LIMIT_BYTES = 4 * 1024


class SnapshotLeaseClaims(Protocol):
    @property
    def workspace_id(self) -> str: ...
    @property
    def device_id(self) -> str: ...
    @property
    def machine_installation_id(self) -> str: ...
    @property
    def installation_generation(self) -> str: ...
    @property
    def sequence(self) -> int: ...
    @property
    def snapshot_schema_version(self) -> str: ...
    @property
    def previous_lease_digest(self) -> str | None: ...


def _native_answer(snapshot: bytes, claims: SnapshotLeaseClaims) -> bool | None:
    """The runtime's verdict on one snapshot, or ``None`` when it cannot answer."""

    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or HEALTH_SNAPSHOT_BINDING_FEATURE not in status.capabilities.features
    ):
        return None
    request = {
        "schema": HEALTH_SNAPSHOT_BINDING_SCHEMA,
        "snapshot": base64.b64encode(snapshot).decode("ascii"),
        "claims": {
            "workspace_id": claims.workspace_id,
            "device_id": claims.device_id,
            "machine_installation_id": claims.machine_installation_id,
            "installation_generation": claims.installation_generation,
            "sequence": claims.sequence,
            "snapshot_schema_version": claims.snapshot_schema_version,
            "previous_lease_digest": claims.previous_lease_digest,
        },
    }
    output = _run_native_process(
        status.identity.path,
        (HEALTH_SNAPSHOT_BINDING_COMMAND, "--stdin"),
        input_text=json.dumps(request, sort_keys=True),
        timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if output is None:
        return None
    try:
        response = cast(object, json.loads(output))
    except ValueError:
        return None
    if not isinstance(response, dict):
        return None
    answer = cast(dict[str, object], response)
    valid = answer.get("valid")
    return valid if answer.get("ok") is True and isinstance(valid, bool) else None


def validate_health_snapshot_binding(snapshot: bytes, claims: SnapshotLeaseClaims) -> None:
    sequence = claims.sequence
    if (
        not snapshot
        or len(snapshot) > _MAX_SNAPSHOT_BYTES
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not 0 <= sequence <= _MAX_UINT64
    ):
        raise ValueError("health_lease_outbox_invalid")
    valid = _native_answer(snapshot, claims)
    if valid is None:
        # A snapshot nothing could check is never bound to a lease.
        raise ValueError("health_lease_snapshot_native_unavailable")
    if not valid:
        raise ValueError("health_lease_outbox_invalid")


__all__ = ["validate_health_snapshot_binding"]
