"""Cross-process first mint of the local policy-integrity signing key."""

from __future__ import annotations

import base64
import os
import time
from collections.abc import Callable
from pathlib import Path

from .store_base import _acquire_advisory_file_lock, _release_advisory_file_lock

MINT_LOCK_FILE_NAME = ".policy-integrity-key-mint.lock"
_MINT_LOCK_TIMEOUT_SECONDS = 10.0
_MINT_LOCK_RETRY_SECONDS = 0.01


def mint_policy_integrity_key_once(
    guard_home: Path,
    *,
    read_key: Callable[[], str | None],
    write_key: Callable[[str], None],
    native_controls_armed: Callable[[], bool],
) -> str | None:
    """Return the stored signing key, minting one only while holding the mint lock.

    Processes that start together on a fresh Guard home can all find no key.
    Without the lock each mints its own and the last write replaces the
    others, so a native verifier key derived from an earlier key no longer
    matches the stored one and every later daemon fails closed. Under the
    lock the store is read again, and a key another process wrote wins.

    Returns ``None`` when the lock cannot be taken in time, or when native
    controls are already armed with a key this process cannot read.
    """

    guard_home.mkdir(parents=True, exist_ok=True)
    lock_path = guard_home / MINT_LOCK_FILE_NAME
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "r+b") as handle:
        if not _acquire_within_deadline(handle):
            return None
        try:
            existing = read_key()
            if existing is not None:
                return existing
            if native_controls_armed():
                return None
            write_key(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))
            return read_key()
        finally:
            _release_advisory_file_lock(handle)


def _acquire_within_deadline(handle) -> bool:
    deadline = time.monotonic() + _MINT_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            _acquire_advisory_file_lock(handle)
            return True
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(_MINT_LOCK_RETRY_SECONDS)
