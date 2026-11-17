"""Bounded cross-process ownership of Codex authority mutations.

The home-wide lock also protects the key shared by distinct config targets.
Snapshots, publication, migration and rollback must remain inside this scope.
The resident opens, checks and holds the lock file for the owning process, and
appends the mutation journal; this module keeps the in-process ownership. The
lock file is permanent: removing a held lock would split ownership.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from .codex_hook_file_integrity import CodexHookIntegrityError

_locks: dict[str, threading.RLock] = {}
_locks_guard = threading.Lock()
_process_identity = uuid.uuid4().hex
_dropped_events = 0
_LOCK_UNSAFE = "Codex transaction ownership file is unsafe."
_LOCK_REFUSALS = {
    "codex_hook_manifest_directory_unsafe": "The Codex managed-hook directory is not a private regular directory.",
    "codex_hook_manifest_directory_owner_mismatch": "The Codex managed-hook directory has an unexpected owner.",
    "codex_hook_manifest_directory_permissions_unsafe": (
        "The Codex managed-hook directory permissions are not owner-only."
    ),
}


@dataclass(frozen=True)
class CodexInstallOwner:
    guard_home: Path
    operation_id: str
    target_id: str
    actor: str
    pid: int
    thread_id: int


_OWNER: ContextVar[CodexInstallOwner | None] = ContextVar("codex_install_owner", default=None)


@contextmanager
def _home_owner_lock(guard_home: Path, *, deadline: float | None = None) -> Iterator[None]:
    deadline = time.monotonic() + 5 if deadline is None else deadline
    home = guard_home.resolve(strict=False)
    with _locks_guard:
        lock = _locks.setdefault(str(home), threading.RLock())
    if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
        raise TimeoutError("Codex installation transaction deadline exceeded.")
    owning_pid = os.getpid()
    try:
        yield
    finally:
        if owning_pid == os.getpid():
            lock.release()


def _after_fork_child() -> None:
    global _locks, _locks_guard, _process_identity, _dropped_events
    # The resident's lease belongs to the parent; a child acquires its own.
    _locks = {}
    _locks_guard = threading.Lock()
    _OWNER.set(None)
    _process_identity = uuid.uuid4().hex
    _dropped_events = 0


if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=lambda: _locks_guard.acquire(),
        after_in_parent=lambda: _locks_guard.release(),
        after_in_child=_after_fork_child,
    )


def require_codex_install_owner(guard_home: Path) -> CodexInstallOwner:
    owner = _OWNER.get()
    if (
        owner is None
        or owner.pid != os.getpid()
        or owner.thread_id != threading.get_ident()
        or owner.guard_home != guard_home.resolve(strict=False)
    ):
        raise CodexHookIntegrityError(
            "codex_hook_transaction_owner_missing", "Codex mutation requires exclusive installation ownership."
        )
    return owner


def record_codex_mutation(operation: str, path: Path, before: bytes | None, after: bytes | None) -> None:
    """Record identities only; never write command/config/key contents."""
    record_codex_mutation_identities(
        [
            {
                "operation": operation,
                "path": str(path),
                "before_present": before is not None,
                "after_present": after is not None,
                "before_digest": None if before is None else hashlib.sha256(before).hexdigest(),
                "after_digest": None if after is None else hashlib.sha256(after).hexdigest(),
            }
        ]
    )


def record_codex_mutation_identities(mutations: list[dict[str, object]]) -> None:
    """Have the resident append mutation identities to the owner's journal, in order."""
    global _dropped_events
    owner = _OWNER.get()
    if not mutations or owner is None or owner.pid != os.getpid() or owner.thread_id != threading.get_ident():
        return
    from .native_transition_files import append_journal

    identity: dict[str, object] = {
        "operation_id": owner.operation_id,
        "config_target_id": owner.target_id,
        "actor": owner.actor,
        "pid": os.getpid(),
        "process_identity": _process_identity,
        "dropped_events": _dropped_events,
    }
    try:
        _dropped_events = append_journal(owner.guard_home, identity, mutations)
    except Exception:
        # Diagnostic failure cannot replace the first publication/rollback error.
        _dropped_events += len(mutations)


@contextmanager
def codex_install_transaction(
    guard_home: Path,
    config_path: Path,
    *,
    actor: str,
    deadline: float | None = None,
) -> Iterator[CodexInstallOwner]:
    from .adapters.codex_lifecycle_lock import codex_configuration_lock

    deadline = time.monotonic() + 5 if deadline is None else deadline
    home = guard_home.resolve(strict=False)
    previous = _OWNER.get()
    if (
        previous is not None
        and previous.guard_home == home
        and previous.pid == os.getpid()
        and previous.thread_id == threading.get_ident()
    ):
        with codex_configuration_lock(config_path, deadline=deadline):
            yield previous
        return
    # Same-home callers contend on this lock before any target file lock.
    # The home directory is created only after the configuration lock is held,
    # so a competing path cannot leave a new home behind.
    with (
        _home_owner_lock(guard_home, deadline=deadline),
        codex_configuration_lock(config_path, deadline=deadline),
        _guard_home_install_transaction(guard_home, config_path, actor=actor, deadline=deadline) as owner,
    ):
        yield owner


@contextmanager
def _guard_home_install_transaction(
    guard_home: Path,
    config_path: Path,
    *,
    actor: str,
    deadline: float,
) -> Iterator[CodexInstallOwner]:

    home = guard_home.resolve(strict=False)
    target_id = hashlib.sha256(str(config_path.resolve(strict=False)).encode()).hexdigest()
    previous = _OWNER.get()
    if (
        previous is not None
        and previous.guard_home == home
        and previous.pid == os.getpid()
        and previous.thread_id == threading.get_ident()
    ):
        yield previous
        return
    from .native_transition_files import acquire_lease, release_lease

    with _locks_guard:
        lock = _locks.setdefault(str(home), threading.RLock())
    if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
        raise TimeoutError("Codex installation transaction deadline exceeded.")
    owning_pid = os.getpid()
    try:
        # The resident opens, checks and holds installation.lock for this process.
        try:
            lease = acquire_lease({"lock": "install", "guard_home": str(home)}, wait=True, deadline=deadline)
        except TimeoutError:
            raise TimeoutError("Codex installation transaction deadline exceeded.") from None
        except RuntimeError as error:
            code = str(error)
            raise CodexHookIntegrityError(code, _LOCK_REFUSALS.get(code, _LOCK_UNSAFE)) from None
        owner = CodexInstallOwner(home, uuid.uuid4().hex, target_id, actor, os.getpid(), threading.get_ident())
        token = _OWNER.set(owner)
        try:
            record_codex_mutation("begin", config_path, None, None)
            yield owner
            if owning_pid != os.getpid():
                raise CodexHookIntegrityError(
                    "codex_hook_transaction_owner_missing",
                    "Forked processes must acquire new installation ownership.",
                )
        except BaseException:
            record_codex_mutation("failed", config_path, None, None)
            raise
        else:
            record_codex_mutation("committed", config_path, None, None)
        finally:
            if owning_pid == os.getpid():
                _OWNER.reset(token)
                release_lease(lease)
    finally:
        if owning_pid == os.getpid():
            lock.release()
