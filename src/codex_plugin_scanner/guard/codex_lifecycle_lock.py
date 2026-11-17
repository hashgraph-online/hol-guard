"""Serialize cooperating Codex lifecycle writers across installation owners.

The resident opens, checks and holds each lifecycle lock file for this
process (see ``transition_files/lease.rs``); this module keeps which locks
the current thread already owns, so a nested writer reuses its owner's lock.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Generator, Iterable
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .harness.base import HarnessContext

_TargetOwnerKey = tuple[str, int, int]
_HELD_TARGETS: ContextVar[dict[_TargetOwnerKey, str] | None] = ContextVar("codex_lifecycle_targets", default=None)


def _after_fork_child() -> None:
    # The parent's leases stay the parent's; child operations acquire their own.
    _HELD_TARGETS.set(None)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Codex lifecycle transaction deadline exceeded.")


@contextmanager
def _target_lock(
    directory: Path,
    *,
    deadline: float | None = None,
    allow_owned: bool = False,
    wait: bool = False,
) -> Generator[None, None, None]:
    from .native_transition_files import acquire_lease, lease_held, release_lease

    if wait and deadline is None:
        raise ValueError("Codex lifecycle waiting requires an absolute deadline.")
    _check_deadline(deadline)
    owner_key = os.path.normcase(str(directory.resolve())), os.getpid(), threading.get_ident()
    held = _HELD_TARGETS.get() or {}
    if allow_owned and owner_key in held:
        if not lease_held(held[owner_key]):
            raise RuntimeError("codex_lifecycle_lock_invalid: lifecycle lock changed during ownership")
        _check_deadline(deadline)
        yield
        return
    try:
        lease = acquire_lease({"lock": "lifecycle", "directory": str(directory)}, wait=wait, deadline=deadline)
    except BlockingIOError:
        raise RuntimeError("codex_lifecycle_busy: another lifecycle operation owns this Codex configuration") from None
    except TimeoutError:
        raise TimeoutError("Codex lifecycle transaction deadline exceeded.") from None
    owner_pid = os.getpid()
    token = _HELD_TARGETS.set({**held, owner_key: lease})
    try:
        # The deadline bounds waiting for a busy lock, not the resident's first answer.
        yield
    finally:
        _HELD_TARGETS.reset(token)
        if os.getpid() == owner_pid:
            release_lease(lease)


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
