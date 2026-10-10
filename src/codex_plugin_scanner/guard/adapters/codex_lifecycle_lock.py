"""Serialize cooperating Codex lifecycle writers across installation owners."""

from __future__ import annotations

import errno
import os
import re
import stat
import threading
import time
from collections.abc import Generator, Iterable
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO

from ..daemon.file_locking import try_lock_daemon_file
from ..mdm.file_lock import release_file_lock
from ..windows_paths import trusted_windows_user_profile
from .base import HarnessContext

_TargetOwnerKey = tuple[str, int, int]
_HELD_TARGETS: ContextVar[frozenset[_TargetOwnerKey]] = ContextVar("codex_lifecycle_targets", default=frozenset())
_open_target_handles: dict[_TargetOwnerKey, BinaryIO] = {}


def _after_fork_child() -> None:
    global _open_target_handles
    # Close inherited references without explicitly unlocking the parent's
    # open-file description. Child operations must acquire their own ownership.
    for handle in _open_target_handles.values():
        handle.close()
    _open_target_handles = {}
    _HELD_TARGETS.set(frozenset())


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Codex lifecycle transaction deadline exceeded.")


def _account_home() -> Path:
    if os.name == "nt":
        return trusted_windows_user_profile()
    import pwd

    try:
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except KeyError as error:
        raise OSError("codex_lifecycle_account_home_unavailable") from error


def _lock_base() -> Path:
    # CLI and Desktop environments may disagree on HOME, TMPDIR or XDG paths.
    # Resolve the account through the OS so both owners use the same locks.
    return _account_home() / ".hol-guard-codex-lifecycle-locks"


def _lifecycle_lock_path(directory: Path) -> Path:
    base = _lock_base()
    target = os.path.normcase(str(directory.resolve()))
    return base / f"{sha256(os.fsencode(target)).hexdigest()}.lock"


def _unavailable_lock(stage: str, error: OSError) -> RuntimeError:
    # Preserve a bounded OS reason without disclosing a private pathname.
    if error.errno is not None:
        reason = errno.errorcode.get(error.errno, "UNKNOWN")
    else:
        token = error.args[0] if len(error.args) == 1 and isinstance(error.args[0], str) else ""
        reason = token if re.fullmatch(r"[a-z_]{1,64}", token) else "UNKNOWN"
    return RuntimeError(f"codex_lifecycle_lock_invalid: lifecycle lock {stage} is unavailable (reason={reason})")


def _lock_identity(path: Path) -> tuple[int, int] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle lock must be a regular file with one link")
    return metadata.st_dev, metadata.st_ino


@contextmanager
def _target_lock(
    directory: Path,
    *,
    deadline: float | None = None,
    allow_owned: bool = False,
    wait: bool = False,
) -> Generator[None, None, None]:
    if wait and deadline is None:
        raise ValueError("Codex lifecycle waiting requires an absolute deadline.")
    _check_deadline(deadline)
    try:
        path = _lifecycle_lock_path(directory)
    except OSError as error:
        raise _unavailable_lock("directory", error) from error
    owner_key = str(path), os.getpid(), threading.get_ident()
    if allow_owned and owner_key in _HELD_TARGETS.get():
        try:
            handle = _open_target_handles.get(owner_key)
            if handle is None or handle.closed:
                raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle owner is no longer live")
            opened = os.fstat(handle.fileno())
            if _lock_identity(path) != (opened.st_dev, opened.st_ino):
                raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle lock changed during ownership")
        except OSError as error:
            raise _unavailable_lock("file", error) from error
        _check_deadline(deadline)
        yield
        return
    try:
        path.parent.mkdir(mode=0o700, exist_ok=True)
        # lstat rejects a substituted symlink instead of following it.
        metadata = path.parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or (
            hasattr(os, "getuid") and (metadata.st_uid != os.getuid() or metadata.st_mode & 0o077)
        ):
            raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle lock directory is not private")
    except OSError as error:
        raise _unavailable_lock("directory", error) from error
    prior = _lock_identity(path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise _unavailable_lock("file", error) from error
    try:
        metadata = os.fstat(descriptor)
        identity = metadata.st_dev, metadata.st_ino
        if _lock_identity(path) != identity or (prior is not None and prior != identity):
            raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle lock changed while opening")
        with os.fdopen(descriptor, "a+b") as handle:
            descriptor = -1
            owner_pid = os.getpid()
            # Register before the kernel can grant ownership. A fork during
            # acquisition must close the child's inherited descriptor even
            # when the parent has not yet published its ContextVar owner.
            _open_target_handles[owner_key] = handle
            token = None
            acquired = False
            try:
                while not try_lock_daemon_file(handle):
                    if not wait:
                        raise RuntimeError(
                            "codex_lifecycle_busy: another lifecycle operation owns this Codex configuration"
                        )
                    _check_deadline(deadline)
                    assert deadline is not None
                    time.sleep(min(0.025, max(0, deadline - time.monotonic())))
                acquired = True
                token = _HELD_TARGETS.set(_HELD_TARGETS.get() | {owner_key})
                _check_deadline(deadline)
                yield
            finally:
                if token is not None:
                    _HELD_TARGETS.reset(token)
                try:
                    if acquired and os.getpid() == owner_pid and not handle.closed:
                        release_file_lock(handle)
                finally:
                    if _open_target_handles.get(owner_key) is handle:
                        del _open_target_handles[owner_key]
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def codex_configuration_lock(config_path: Path, *, deadline: float | None = None) -> Generator[None, None, None]:
    """Share the adapter's target exclusion with direct publication writers."""
    deadline = time.monotonic() + 5 if deadline is None else deadline
    with _target_lock(config_path.parent, deadline=deadline, allow_owned=True, wait=True):
        yield


@contextmanager
def codex_publication_locks(paths: Iterable[Path], *, deadline: float) -> Generator[None, None, None]:
    """Exclude every planned file target without waiting under a home owner.

    A busy target refuses before publication. Reentrant ownership is limited
    to the same live process/thread and checked lock inode.
    """
    targets = {os.path.normcase(str(path.parent.resolve())): path.parent for path in paths}
    with ExitStack() as stack:
        for _identity, directory in sorted(targets.items()):
            stack.enter_context(_target_lock(directory, deadline=deadline, allow_owned=True))
        yield


@contextmanager
def codex_lifecycle_locks(context: HarnessContext) -> Generator[None, None, None]:
    """Requires OS advisory locking; network account profiles are unqualified."""
    # User-private account storage avoids writing to read-only projects or
    # creating configuration directories during a no-op uninstall. Cooperating
    # owners under the same OS account share resolved configuration identities.
    # Keep lock files between calls: unlinking them could split concurrent
    # owners across different inodes. Each configuration reuses one file.
    roots = [context.home_dir]
    if context.workspace_dir is not None:
        roots.append(context.workspace_dir)
    # Resolve existing ancestors without creating an absent .codex directory.
    resolved_targets = {os.path.normcase(str((root / ".codex").resolve())): root / ".codex" for root in roots}
    targets = sorted(resolved_targets.items())
    with ExitStack() as stack:
        for _identity, root in targets:
            stack.enter_context(_target_lock(root))
        yield
