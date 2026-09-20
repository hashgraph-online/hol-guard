"""Serialize supported config mutations with native application observation."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .store_storage_lock import hold_storage_file_lock

_HELD = threading.local()


@contextmanager
def hold_policy_publication_mutation(guard_home: Path, *, timeout_seconds: float = 5.0) -> Iterator[None]:
    """Take the cross-process lock before any store or publisher lock.

    This covers supported config writers. Arbitrary filesystem modification and
    external process death remain observable invalidations, not locked writers.
    """
    canonical_home = guard_home.resolve(strict=False)
    process_id = os.getpid()
    identity = (process_id, str(canonical_home))
    held: set[tuple[int, str]] = (
        getattr(_HELD, "identities", set()) if getattr(_HELD, "process_id", None) == process_id else set()
    )
    if identity in held:
        yield
        return
    canonical_home.mkdir(parents=True, exist_ok=True)
    with hold_storage_file_lock(
        canonical_home / "native-policy-publication.lock", exclusive=True, timeout_seconds=timeout_seconds
    ):
        _HELD.process_id = process_id
        _HELD.identities = held
        held.add(identity)
        try:
            yield
        finally:
            held.remove(identity)
