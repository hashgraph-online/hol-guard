"""Read one canonical native policy snapshot from a private state file.

The runtime's ``policy-snapshot-materialize`` op owns the publisher cache,
generation state and crash recovery; Python only reads retained records.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, cast

from . import native_policy_snapshot_storage_windows as _windows_storage
from .native_policy_snapshot_authority import _authority_snapshot_v3
from .native_policy_snapshot_constants import (
    POLICY_SNAPSHOT_AUTHORITY_SCHEMA,
    POLICY_SNAPSHOT_MAX_BYTES,
    NativePolicySnapshotError,
)

_windows_read_snapshot_bytes = _windows_storage._windows_read_snapshot_bytes


def _snapshot_api() -> Any:
    """Resolve façade hooks lazily to preserve the legacy test seams."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _read_v3_snapshot_file(
    path: Path,
    *,
    verifier_key: bytes | None = None,
    maximum_bytes: int = POLICY_SNAPSHOT_MAX_BYTES,
) -> tuple[dict[str, object], bytes] | None:
    """Read one exact canonical snapshot from a private state file."""

    api = _snapshot_api()
    if os.name == "nt" and api._windows_path_has_reparse_component(path):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    if os.name == "nt":
        payload = api._windows_read_snapshot_bytes(path, maximum_bytes=maximum_bytes)
        if payload is None:
            return None
    else:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size <= 0
                or metadata.st_size > maximum_bytes
                or (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077)
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
            payload = bytearray()
            while len(payload) <= maximum_bytes:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, maximum_bytes + 1 - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) != metadata.st_size or len(payload) > maximum_bytes:
                raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        except OSError as error:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_read_failed") from error
        finally:
            os.close(descriptor)
        payload = bytes(payload)
    value = api._strict_json_loads_v3(payload)
    if not isinstance(value, dict):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    if value.get("schema") == POLICY_SNAPSHOT_AUTHORITY_SCHEMA:
        if verifier_key is None:
            raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
        return _authority_snapshot_v3(value, payload, verifier_key), payload
    if verifier_key is None:
        # The hook-side read authenticates by MAC only; unauthenticated content
        # is never accepted and Python does not re-validate resident content.
        raise NativePolicySnapshotError("native_policy_snapshot_cache_invalid")
    canonical = api.snapshot_bytes_v3(value)
    if canonical != payload:
        raise NativePolicySnapshotError("native_policy_snapshot_cache_noncanonical")
    if not api.snapshot_mac_matches_v3(value, verifier_key):
        raise NativePolicySnapshotError("native_policy_snapshot_cache_integrity_invalid")
    return cast(dict[str, object], value), payload
