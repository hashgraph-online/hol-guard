"""Thin client for the native ``transition_files`` kind.

The resident compares, writes and publishes transition files; see
``rust/crates/guard-runtime/src/transition_files``. Each identity record the
resident hands back goes to the resident's journal append, in order, for the
install transaction this process owns. Whether a POSIX group is private to its
owner is answered from this process's account database when the resident asks.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime_transition import TransitionFile

_TIMEOUT_SECONDS = 60.0
_INVALID = "native_transition_invalid"
# Three of the resident reaper's 50 ms passes over the leases.
_RELEASE_GRACE_SECONDS = 0.15


def _remaining_ms(deadline: float | None) -> int | None:
    if deadline is None:
        return None
    return max(0, int((deadline - time.monotonic()) * 1000))


def _budget() -> dict[str, int | None]:
    from .codex_hook_file_integrity import active_hook_validation_deadline
    from .runtime_transition import _ACTIVE_TRANSITION, _INVERSE_DEADLINE

    active = _ACTIVE_TRANSITION.get()
    return {
        "inverse_ms": _remaining_ms(_INVERSE_DEADLINE.get()),
        "forward_ms": _remaining_ms(active[2] if active is not None else None),
        "hook_ms": _remaining_ms(active_hook_validation_deadline()),
    }


def _package_roots() -> list[str]:
    from .codex_hook_file_integrity import _python_package_roots

    return [str(root) for root in _python_package_roots()]


def _exception(fault: object) -> BaseException:
    from .codex_hook_file_integrity import CodexHookIntegrityError
    from .runtime_transition import TransitionError

    if not isinstance(fault, Mapping):
        return TransitionError(_INVALID)
    transition, integrity = fault.get("transition"), fault.get("integrity")
    message, os_message = fault.get("message"), fault.get("os")
    if isinstance(transition, str):
        detail = fault.get("detail")
        return TransitionError(transition, detail) if isinstance(detail, str) else TransitionError(transition)
    if isinstance(integrity, str) and isinstance(message, str):
        return CodexHookIntegrityError(integrity, message)
    if isinstance(os_message, str):
        number = fault.get("errno")
        if isinstance(number, int) and not isinstance(number, bool):
            return OSError(number, os_message)
        return OSError(os_message)
    return TransitionError(_INVALID)


def _replay(
    events: object,
    files: Sequence[TransitionFile] | None,
    on_write: Callable[[TransitionFile], None] | None,
) -> None:
    from .codex_install_transaction import record_codex_mutation_identities
    from .runtime_transition import TransitionError

    if not isinstance(events, list):
        raise TransitionError(_INVALID)
    pending: list[dict[str, object]] = []
    for event in events:
        mutation = event.get("mutation") if isinstance(event, dict) else None
        if isinstance(mutation, dict):
            pending.append(mutation)
            continue
        # Journal what was written before ``on_write`` sees the file.
        record_codex_mutation_identities(pending)
        pending = []
        index = event.get("written") if isinstance(event, dict) else None
        if files is None or not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(files):
            raise TransitionError(_INVALID)
        if on_write is not None:
            on_write(files[index])
    record_codex_mutation_identities(pending)


def _ask(
    request: dict[str, object],
    *,
    files: Sequence[TransitionFile] | None = None,
    on_write: Callable[[TransitionFile], None] | None = None,
) -> Mapping[str, object]:
    from .native_runner_authority import native_runner_authority
    from .runtime_transition import TransitionError

    request = {**request, "package_roots": _package_roots(), "budget": _budget()}
    answer = native_runner_authority("transition_files", request, timeout_seconds=_TIMEOUT_SECONDS)
    _replay(answer.get("events"), files, on_write)
    error, restore_error = answer.get("error"), answer.get("restore_error")
    if restore_error is not None:
        raise _exception(restore_error) from _exception(error)
    if error is not None:
        raise _exception(error)
    if answer.get("ok") is not True:
        raise TransitionError(_INVALID)
    return answer


def publication(op: str, home: Path, **fields: object) -> object:
    """One ``publication_*`` op on the home's Codex publication record."""

    import os

    request: dict[str, object] = {"op": f"publication_{op}", "home": os.path.abspath(home), **fields}
    return _ask(request).get("value")


def compare_files(files: list[object], generation: str, *, inverse: bool = False) -> None:
    """``RuntimeTransition._compare``: every file still holds ``generation``."""

    request: dict[str, object] = {"op": "compare", "files": files, "generation": generation, "inverse": inverse}
    _ask(request)


def write_file(change: dict[str, object], generation: str) -> None:
    """``RuntimeTransition._write_file``: publish one generation of one file."""

    _ask({"op": "write", "change": change, "generation": generation})


def publish_files(
    files: Sequence[TransitionFile],
    *,
    removals: bool,
    rollback: bool,
    on_write: Callable[[TransitionFile], None] | None,
) -> None:
    """``PreparedHarnessInstall.publish``: the whole plan, restored on failure."""

    payloads = [change.payload() for change in files]
    request: dict[str, object] = {"op": "publish", "files": payloads, "removals": removals, "rollback": rollback}
    _ask(request, files=files, on_write=on_write)


def append_journal(guard_home: Path, owner: dict[str, object], mutations: list[dict[str, object]]) -> int:
    """Append mutation identities to the Codex journal; answers the dropped-event count."""
    from .native_runner_authority import native_runner_authority

    request = {"op": "journal", "guard_home": str(guard_home), "owner": owner, "mutations": mutations}
    answer = native_runner_authority("transition_files", request, timeout_seconds=_TIMEOUT_SECONDS)
    dropped = answer.get("dropped_events")
    if answer.get("ok") is not True or not isinstance(dropped, int) or isinstance(dropped, bool):
        raise RuntimeError(_INVALID)
    return dropped


def _lease_request(request: dict[str, object]) -> dict[str, object]:
    from .native_runner_authority import native_runner_authority

    answer = native_runner_authority("transition_files", request, timeout_seconds=_TIMEOUT_SECONDS)
    if not isinstance(answer, dict):
        raise RuntimeError(_INVALID)
    return answer


def acquire_lease(lock: dict[str, object], *, wait: bool, deadline: float | None) -> str:
    """Have the resident take one Codex lock for this process; answers the lease.

    A busy lock is retried until ``deadline`` when ``wait`` is set. Without
    ``wait`` it is retried for ``_RELEASE_GRACE_SECONDS``, the time the resident
    takes to notice an owner that exited, then raises ``BlockingIOError``. A
    refusal raises the resident's reason as a ``RuntimeError`` and a busy lock
    past the deadline raises ``TimeoutError``.
    """
    import os

    request: dict[str, object] = {"op": "lease_acquire", **lock, "client_pid": os.getpid()}
    grace = time.monotonic() + _RELEASE_GRACE_SECONDS
    while True:
        answer = _lease_request(request)
        lease = answer.get("lease")
        if answer.get("ok") is True and isinstance(lease, str):
            return lease
        error = answer.get("error")
        if isinstance(error, str):
            raise RuntimeError(error)
        if answer.get("busy") is not True:
            raise RuntimeError(_INVALID)
        if not wait:
            if time.monotonic() >= grace:
                raise BlockingIOError(lock.get("lock"))
            time.sleep(0.025)
            continue
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise TimeoutError("lock deadline exceeded")
        time.sleep(0.025 if remaining is None else min(0.025, remaining))


def release_lease(lease: str) -> None:
    _lease_request({"op": "lease_release", "lease": lease})


def lease_held(lease: str) -> bool:
    return _lease_request({"op": "lease_check", "lease": lease}).get("held") is True


__all__ = [
    "acquire_lease",
    "append_journal",
    "compare_files",
    "lease_held",
    "publish_files",
    "release_lease",
    "write_file",
]
