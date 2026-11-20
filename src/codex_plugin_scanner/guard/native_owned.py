"""Thin client for the native installation transaction.

The resident takes and holds every lock, journals the owner's mutations and
runs publication recovery (see ``rust/crates/guard-runtime/src/transition_files/
owned*.rs``). This module only binds the owner it returns to the calling
process and thread, so a nested caller reuses it and a forked child never
borrows it, and turns the resident's refusals into the exceptions callers
already handle.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
import uuid
from collections.abc import Generator, Iterable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .native_failure import INVALID_ANSWER, failure_from_answer

if TYPE_CHECKING:
    from .harness_context import HarnessContext

_INVALID = INVALID_ANSWER
_OVERHEAD_SECONDS = 30.0
_LOCK_INVALID = "codex_lifecycle_lock_invalid: lifecycle lock changed during ownership"
_TargetKey = tuple[str, int, int]
_process_identity = uuid.uuid4().hex


@dataclass(frozen=True)
class CodexInstallOwner:
    guard_home: Path
    operation_id: str
    target_id: str
    actor: str
    pid: int
    thread_id: int
    token: str


_OWNER: ContextVar[CodexInstallOwner | None] = ContextVar("codex_install_owner", default=None)
_HELD_TARGETS: ContextVar[dict[_TargetKey, str] | None] = ContextVar("codex_lifecycle_targets", default=None)


def _after_fork_child() -> None:
    # The resident's leases belong to the parent; a child acquires its own.
    global _process_identity
    _OWNER.set(None)
    _HELD_TARGETS.set(None)
    _process_identity = uuid.uuid4().hex


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


def _remaining_ms(deadline: float) -> int:
    return max(0, int((deadline - time.monotonic()) * 1000))


def _call(op: str, *, deadline: float | None = None, **fields: object) -> Mapping[str, object]:
    from .native_runner_authority import native_runner_authority
    from .native_transition_files import transition_context

    request: dict[str, object] = {"op": op, "client_pid": os.getpid(), **fields, **transition_context()}
    timeout = 60.0
    if deadline is not None:
        request["deadline_ms"] = _remaining_ms(deadline)
        timeout = max(timeout, deadline - time.monotonic() + _OVERHEAD_SECONDS)
    answer = native_runner_authority("transition_files", request, timeout_seconds=timeout)
    if not isinstance(answer, Mapping):
        raise RuntimeError(_INVALID)
    if answer.get("ok") is not True:
        raise failure_from_answer(answer)
    return answer


def _leases(answer: Mapping[str, object]) -> list[str]:
    leases = answer.get("leases")
    if not isinstance(leases, list) or not all(isinstance(lease, str) for lease in leases):
        raise RuntimeError(_INVALID)
    return list(leases)


def _release(leases: Iterable[str]) -> None:
    """Best effort: it runs in ``finally`` blocks, and the resident reaps a dead client's leases."""
    for lease in leases:
        try:
            _call("lease_release", lease=lease)
        except Exception:  # never mask the first error
            continue


def _lease_held(lease: str) -> bool:
    return _call("lease_check", lease=lease).get("held") is True


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("Codex lifecycle transaction deadline exceeded.")


def _target_key(directory: Path) -> _TargetKey:
    return os.path.normcase(str(directory.resolve())), os.getpid(), threading.get_ident()


@contextmanager
def _lifecycle_dirs(
    directories: Iterable[Path],
    *,
    deadline: float | None,
    allow_owned: bool,
    wait: bool,
) -> Generator[None, None, None]:
    """Lock each directory's lifecycle lock, reusing one this thread already owns."""
    if wait and deadline is None:
        raise ValueError("Codex lifecycle waiting requires an absolute deadline.")
    _check_deadline(deadline)
    held = _HELD_TARGETS.get() or {}
    fresh: dict[str, Path] = {}
    for directory in directories:
        key = _target_key(directory)
        if allow_owned and key in held:
            if not _lease_held(held[key]):
                raise RuntimeError(_LOCK_INVALID)
            _check_deadline(deadline)
            continue
        fresh.setdefault(key[0], directory)
    if not fresh:
        yield
        return
    ordered = sorted(fresh.items())
    fields: dict[str, object] = {"dirs": [str(directory) for _, directory in ordered], "wait": wait}
    leases = _leases(_call("owned_locks", deadline=deadline, **fields))
    owner_pid = os.getpid()
    if len(leases) != len(ordered):
        _release(leases)
        raise RuntimeError(_LOCK_INVALID)
    pid, thread = os.getpid(), threading.get_ident()
    owned = {(identity, pid, thread): lease for (identity, _), lease in zip(ordered, leases, strict=True)}
    token = _HELD_TARGETS.set({**held, **owned})
    try:
        yield
    finally:
        _HELD_TARGETS.reset(token)
        if os.getpid() == owner_pid:
            _release(leases)


@contextmanager
def codex_configuration_lock(config_path: Path, *, deadline: float | None = None) -> Generator[None, None, None]:
    """Share the adapter's target exclusion with direct publication writers."""
    deadline = time.monotonic() + 5 if deadline is None else deadline
    with _lifecycle_dirs((config_path.parent,), deadline=deadline, allow_owned=True, wait=True):
        yield


@contextmanager
def codex_publication_locks(paths: Iterable[Path], *, deadline: float) -> Generator[None, None, None]:
    """Exclude every planned file target without waiting under a home owner."""
    with _lifecycle_dirs((path.parent for path in paths), deadline=deadline, allow_owned=True, wait=False):
        yield


@contextmanager
def codex_lifecycle_locks(context: HarnessContext) -> Generator[None, None, None]:
    """Requires OS advisory locking; network account profiles are unqualified."""
    roots = [context.home_dir]
    if context.workspace_dir is not None:
        roots.append(context.workspace_dir)
    # Resolve existing ancestors without creating an absent .codex directory.
    with _lifecycle_dirs((root / ".codex" for root in roots), deadline=None, allow_owned=False, wait=False):
        yield


def _bound(owner: CodexInstallOwner | None, guard_home: Path | None = None) -> bool:
    return (
        owner is not None
        and owner.pid == os.getpid()
        and owner.thread_id == threading.get_ident()
        and (guard_home is None or owner.guard_home == guard_home.resolve(strict=False))
    )


def require_codex_install_owner(guard_home: Path) -> CodexInstallOwner:
    from .codex_hook_file_integrity import CodexHookIntegrityError

    owner = _OWNER.get()
    if owner is None or not _bound(owner, guard_home):
        raise CodexHookIntegrityError(
            "codex_hook_transaction_owner_missing", "Codex mutation requires exclusive installation ownership."
        )
    return owner


def owner_request(guard_home: Path, *, actor: str, deadline_seconds: float = 5.0) -> dict[str, object]:
    """The fields a native install op needs to run as, or to become, the owner of ``guard_home``.

    The owner this thread already holds is named by its token, so the op journals under it; otherwise the op
    takes the locks itself and journals its own begin and commit. ``held_dirs`` names the configuration
    directories this thread already holds, so the op shares those locks instead of waiting on them.
    """
    held = [
        {"identity": identity, "lease": lease}
        for (identity, pid, thread), lease in (_HELD_TARGETS.get() or {}).items()
        if pid == os.getpid() and thread == threading.get_ident()
    ]
    owner = _OWNER.get()
    if owner is not None and _bound(owner, guard_home):
        return {"owner": owner.token, "client_pid": owner.pid, "thread": owner.thread_id, "held_dirs": held}
    return {
        "client_pid": os.getpid(),
        "thread": threading.get_ident(),
        "actor": actor,
        "process_identity": _process_identity,
        "deadline_ms": int(deadline_seconds * 1000),
        "held_dirs": held,
    }


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
    owner = _OWNER.get()
    if not mutations or owner is None or not _bound(owner):
        return
    try:
        _call("owned_record", owner=owner.token, thread=owner.thread_id, mutations=mutations)
    except Exception:
        # Diagnostic failure cannot replace the first publication/rollback error.
        return


def _finish(owner: CodexInstallOwner, leases: list[str], *, committed: bool) -> None:
    try:
        answer = _call("owned_end", owner=owner.token, committed=committed)
    except Exception:  # never mask the first error
        _release(leases)
        return
    if answer.get("ended") is not True:
        # The resident had already forgotten this owner: the leases it held may remain.
        _release(leases)


@contextmanager
def codex_install_transaction(
    guard_home: Path,
    config_path: Path,
    *,
    actor: str,
    deadline: float | None = None,
    check_pending: bool = False,
    recover: bool = False,
) -> Generator[CodexInstallOwner, None, None]:
    """Own the Guard home's mutations: the resident holds the locks and the journal."""
    from .runtime_transition import assert_transition_mutation_allowed

    deadline = time.monotonic() + 5 if deadline is None else deadline
    home = guard_home.resolve(strict=False)
    previous = _OWNER.get()
    if previous is not None and previous.guard_home == home and _bound(previous):
        with codex_configuration_lock(config_path, deadline=deadline):
            if check_pending:
                assert_transition_mutation_allowed(home)
            if recover:
                _call("owned_recover", owner=previous.token)
            yield previous
        return
    held = _HELD_TARGETS.get() or {}
    directory = config_path.parent
    key = _target_key(directory)
    dirs: list[str] = []
    if key in held:
        if not _lease_held(held[key]):
            raise RuntimeError(_LOCK_INVALID)
        _check_deadline(deadline)
    else:
        dirs.append(str(directory))
    answer = _call(
        "owned_begin",
        deadline=deadline,
        guard_home=str(home),
        target=str(config_path),
        actor=actor,
        process_identity=_process_identity,
        thread=threading.get_ident(),
        dirs=dirs,
        check_pending=check_pending,
        recover=recover,
    )
    leases = _leases(answer)
    token = str(answer["owner"])
    owner = CodexInstallOwner(
        home,
        str(answer["operation_id"]),
        str(answer["config_target_id"]),
        actor,
        os.getpid(),
        threading.get_ident(),
        token,
    )
    owning_pid = os.getpid()
    owner_token = _OWNER.set(owner)
    held_token = _HELD_TARGETS.set({**held, key: leases[0]}) if dirs and leases else None
    try:
        yield owner
        if owning_pid != os.getpid():
            from .codex_hook_file_integrity import CodexHookIntegrityError

            raise CodexHookIntegrityError(
                "codex_hook_transaction_owner_missing",
                "Forked processes must acquire new installation ownership.",
            )
    except BaseException:
        if owning_pid == os.getpid():
            _finish(owner, leases, committed=False)
        raise
    else:
        _finish(owner, leases, committed=True)
    finally:
        if owning_pid == os.getpid():
            _OWNER.reset(owner_token)
            if held_token is not None:
                _HELD_TARGETS.reset(held_token)
