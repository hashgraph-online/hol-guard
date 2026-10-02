"""Serialize cooperating Codex lifecycle writers across installation owners."""

from __future__ import annotations

import errno
import os
import re
import stat
from collections.abc import Callable, Generator
from contextlib import ExitStack, contextmanager
from functools import wraps
from hashlib import sha256
from pathlib import Path

from ..daemon.file_locking import try_lock_daemon_file
from ..mdm.file_lock import release_file_lock
from ..windows_paths import trusted_windows_user_profile
from .base import HarnessContext


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
def _target_lock(directory: Path) -> Generator[None, None, None]:
    try:
        path = _lifecycle_lock_path(directory)
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
            if not try_lock_daemon_file(handle):
                raise RuntimeError("codex_lifecycle_busy: another lifecycle operation owns this Codex configuration")
            try:
                yield
            finally:
                release_file_lock(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


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


def serialized_codex_lifecycle(method: Callable[..., dict[str, object]]) -> Callable[..., dict[str, object]]:
    @wraps(method)
    def wrapped(self: object, context: HarnessContext) -> dict[str, object]:
        with codex_lifecycle_locks(context):
            return method(self, context)

    return wrapped
