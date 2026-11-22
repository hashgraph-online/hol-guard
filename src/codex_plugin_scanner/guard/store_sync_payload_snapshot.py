"""Native store snapshot of several ``sync_state`` rows read together."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

SyncPayload = dict[str, object] | list[object] | None

#: The most rows one snapshot reads; the native store refuses more.
MAX_SYNC_PAYLOAD_SNAPSHOT_KEYS = 16


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


class SyncPayloadRowUnreadableError(ValueError):
    """A requested row holds text that is not JSON, as ``get_sync_payload`` raised for it."""


def sync_payload_snapshot_rows(answer: object, keys: tuple[str, ...]) -> dict[str, SyncPayload]:
    """Check the native answer and return each requested row.

    A missing row, or one that is neither an object nor an array, is ``None``,
    as ``get_sync_payload`` answers for it.
    """

    if not isinstance(answer, dict) or set(answer) != {"rows", "unreadable"}:
        raise RuntimeError("native sync_payload_snapshot returned no answer")
    unreadable = answer["unreadable"]
    if (
        not isinstance(unreadable, list)
        or not all(isinstance(key, str) for key in unreadable)
        or not set(unreadable) <= set(keys)
    ):
        raise RuntimeError("native sync_payload_snapshot returned no answer")
    if unreadable:
        raise SyncPayloadRowUnreadableError(f"sync_payload_unreadable:{','.join(unreadable)}")
    rows = answer["rows"]
    if not isinstance(rows, dict) or set(rows) != set(keys):
        raise RuntimeError("native sync_payload_snapshot returned no answer")
    result: dict[str, SyncPayload] = {}
    for key in keys:
        value = rows[key]
        if value is not None and not isinstance(value, (dict, list)):
            raise RuntimeError("native sync_payload_snapshot returned no answer")
        result[key] = value
    return result


class StoreSyncPayloadSnapshotMixin:
    """Several ``sync_state`` rows, read by the native store in one snapshot."""

    def sync_payload_snapshot(self: _NativeStore, *keys: str) -> dict[str, SyncPayload]:
        """Read ``keys`` together; raise ``SyncPayloadRowUnreadableError`` for a row that is not JSON."""

        if not keys or len(keys) > MAX_SYNC_PAYLOAD_SNAPSHOT_KEYS or len(set(keys)) != len(keys):
            raise ValueError("sync_payload_snapshot needs 1 to 16 distinct keys")
        answer = self._native_store_call("sync_payload_snapshot", {"keys": list(keys)})
        return sync_payload_snapshot_rows(answer, keys)


__all__ = [
    "MAX_SYNC_PAYLOAD_SNAPSHOT_KEYS",
    "StoreSyncPayloadSnapshotMixin",
    "SyncPayload",
    "SyncPayloadRowUnreadableError",
    "sync_payload_snapshot_rows",
]
