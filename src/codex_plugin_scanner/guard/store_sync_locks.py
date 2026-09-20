"""Named synchronization locks backed by the store's advisory lock boundary."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol, cast


class StoreSyncLockOwner(Protocol):
    guard_home: Path

    def _hold_advisory_file_lock(
        self,
        *,
        path: Path,
        timeout_seconds: float,
        poll_seconds: float,
        timeout_message: str,
    ) -> AbstractContextManager[None]: ...


def oauth_refresh(self: object, timeout_seconds: float) -> Iterator[None]:
    from . import store_connection_schema as api

    self = cast(StoreSyncLockOwner, self)

    with self._hold_advisory_file_lock(
        path=self.guard_home / "oauth-refresh.lock",
        timeout_seconds=timeout_seconds,
        poll_seconds=api._OAUTH_REFRESH_LOCK_POLL_SECONDS,
        timeout_message="Timed out waiting for Guard OAuth refresh lock.",
    ):
        yield


def cloud_sync(self: object, timeout_seconds: float) -> Iterator[None]:
    from . import store_connection_schema as api

    self = cast(StoreSyncLockOwner, self)

    with self._hold_advisory_file_lock(
        path=self.guard_home / "cloud-sync.lock",
        timeout_seconds=timeout_seconds,
        poll_seconds=api._CLOUD_SYNC_LOCK_POLL_SECONDS,
        timeout_message="Timed out waiting for Guard Cloud sync lock.",
    ):
        yield


def aibom_sync(self: object, timeout_seconds: float) -> Iterator[None]:
    from . import store_connection_schema as api

    self = cast(StoreSyncLockOwner, self)

    with self._hold_advisory_file_lock(
        path=self.guard_home / "aibom-sync.lock",
        timeout_seconds=timeout_seconds,
        poll_seconds=api._CLOUD_SYNC_LOCK_POLL_SECONDS,
        timeout_message="Timed out waiting for Guard inventory sync lock.",
    ):
        yield
