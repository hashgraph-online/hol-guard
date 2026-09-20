"""Bound supported maintenance to one captured publication-lock directory.

This is serialization, not policy authority. The existing bounded owner holds
this context until its real work and cleanup finish, even if its caller expires.
"""

from __future__ import annotations

import os
import stat
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .native_policy_publication_lock import _HELD
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .store_storage_lock import hold_storage_file_lock


@dataclass(frozen=True, slots=True)
class PublicationMutationBinding:
    guard_home: Path
    canonical_home: Path
    device: int
    inode: int


def _active(cancelled: threading.Event, deadline_monotonic: float) -> float:
    remaining = deadline_monotonic - time.monotonic()
    if cancelled.is_set() or remaining <= 0:
        raise NativePolicySnapshotError("native_policy_snapshot_control_deadline_exceeded")
    return remaining


def _directory_identity(path: Path) -> tuple[int, int]:
    value = path.stat()
    if not stat.S_ISDIR(value.st_mode):
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    return value.st_dev, value.st_ino


def capture_publication_mutation_binding(
    guard_home: Path, *, cancelled: threading.Event, deadline_monotonic: float
) -> PublicationMutationBinding:
    """Capture inside the owner; never create a directory for this lookup."""
    _active(cancelled, deadline_monotonic)
    canonical = guard_home.resolve(strict=True)
    identity = _directory_identity(canonical)
    if _directory_identity(guard_home) != identity:
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    _active(cancelled, deadline_monotonic)
    return PublicationMutationBinding(guard_home, canonical, *identity)


def _check_binding(binding: PublicationMutationBinding, guard_home: Path) -> None:
    if type(binding) is not PublicationMutationBinding or binding.guard_home != guard_home:
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    expected = binding.device, binding.inode
    if _directory_identity(guard_home) != expected or _directory_identity(binding.canonical_home) != expected:
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")


@contextmanager
def hold_bound_policy_publication_mutation(
    binding: PublicationMutationBinding,
    *,
    guard_home: Path,
    cancelled: threading.Event,
    deadline_monotonic: float,
) -> Iterator[None]:
    """Use the same process/local identity as the existing reentrant lock."""
    _active(cancelled, deadline_monotonic)
    _check_binding(binding, guard_home)
    process_id = os.getpid()
    identity = process_id, str(binding.canonical_home)
    held: set[tuple[int, str]] = (
        getattr(_HELD, "identities", set()) if getattr(_HELD, "process_id", None) == process_id else set()
    )
    if identity in held:
        _active(cancelled, deadline_monotonic)
        yield
        return
    timeout = min(5.0, _active(cancelled, deadline_monotonic))
    with hold_storage_file_lock(
        binding.canonical_home / "native-policy-publication.lock",
        exclusive=True,
        timeout_seconds=timeout,
        deadline_monotonic=deadline_monotonic,
    ):
        _check_binding(binding, guard_home)
        _active(cancelled, deadline_monotonic)
        _HELD.process_id = process_id
        _HELD.identities = held
        held.add(identity)
        try:
            yield
        finally:
            held.remove(identity)
