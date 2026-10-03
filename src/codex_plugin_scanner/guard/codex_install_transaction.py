"""Bounded cross-process ownership of Codex authority mutations.

The home-wide lock also protects the key shared by distinct config targets.
Snapshots, publication, migration and rollback must remain inside this scope.
The lock file is permanent: removing a held lock would split ownership.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .codex_hook_file_integrity import CodexHookIntegrityError
from .daemon.file_locking import try_lock_daemon_file
from .mdm.file_lock import release_file_lock

_locks: dict[str, threading.RLock] = {}
_locks_guard = threading.Lock()
_open_lock_handles: dict[int, BinaryIO] = {}
_MAX_JOURNAL_BYTES = 1024 * 1024
_process_identity = uuid.uuid4().hex
_dropped_events = 0


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
    global _locks, _locks_guard, _open_lock_handles, _process_identity, _dropped_events
    # A fork duplicates the locked open-file description. Close only the
    # child's references: explicitly unlocking would unlock the parent too.
    for handle in _open_lock_handles.values():
        handle.close()
    _open_lock_handles = {}
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
    global _dropped_events
    owner = _OWNER.get()
    if owner is None or owner.pid != os.getpid() or owner.thread_id != threading.get_ident():
        return
    private_key = path.name == "hook-manifest.key"
    event = {
        "schema": "hol-guard.codex-authority-mutation.v1",
        "operation_id": owner.operation_id,
        "target_id": hashlib.sha256(str(path.resolve(strict=False)).encode()).hexdigest(),
        "config_target_id": owner.target_id,
        "actor": owner.actor,
        "pid": os.getpid(),
        "process_identity": _process_identity,
        "time_ns": time.time_ns(),
        "operation": operation,
        "dropped_events": _dropped_events,
        "before_present": before is not None,
        "after_present": after is not None,
        "before_digest": None if private_key or before is None else hashlib.sha256(before).hexdigest(),
        "after_digest": None if private_key or after is None else hashlib.sha256(after).hexdigest(),
    }
    path = owner.guard_home / "managed" / "codex" / "authority-mutations.jsonl"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "ab") as handle:
            _verify_lock_file(path, handle.fileno())
            if os.fstat(handle.fileno()).st_size >= _MAX_JOURNAL_BYTES:
                # Only the exclusive transaction owner rotates this bounded journal.
                backup = path.with_suffix(".jsonl.1")
                if backup.is_symlink():
                    return
                os.replace(path, backup)
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "ab") as fresh:
                    fresh.write((json.dumps(event, separators=(",", ":")) + "\n").encode())
                return
            handle.write((json.dumps(event, separators=(",", ":")) + "\n").encode())
    except (OSError, CodexHookIntegrityError):
        # Diagnostic failure cannot replace the first publication/rollback error.
        _dropped_events += 1
        return


def _verify_lock_file(path: Path, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    current = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        or getattr(current, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        or (os.name != "nt" and (opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) & 0o077))
    ):
        raise CodexHookIntegrityError(
            "codex_hook_transaction_lock_unsafe", "Codex transaction ownership file is unsafe."
        )


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
    from .codex_hook_integrity import _ensure_private_directory

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
    with _locks_guard:
        lock = _locks.setdefault(str(home), threading.RLock())
    if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
        raise TimeoutError("Codex installation transaction deadline exceeded.")
    owning_pid = os.getpid()
    handle = None
    try:
        path = home / "managed" / "codex" / "installation.lock"
        _ensure_private_directory(path.parent, repair_mode=True)
        with _locks_guard:
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            handle = os.fdopen(descriptor, "r+b")
            _open_lock_handles[id(handle)] = handle
        with handle:
            _verify_lock_file(path, handle.fileno())
            while not try_lock_daemon_file(handle):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Codex installation transaction deadline exceeded.")
                time.sleep(min(0.025, remaining))
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
                    release_file_lock(handle)
    finally:
        if owning_pid == os.getpid():
            with _locks_guard:
                if handle is not None:
                    _open_lock_handles.pop(id(handle), None)
            lock.release()
