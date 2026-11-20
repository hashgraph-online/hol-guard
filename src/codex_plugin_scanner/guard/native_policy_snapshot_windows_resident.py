"""Owner-private Windows state ops answered by the resident runtime.

A process that already holds a live resident client stream for a Guard home
sends each private-state request inside that home over that stream to the
resident, which runs the same held handles and owner/DACL checks as the
one-shot ``windows-private-state`` command without starting a process per op.
Only a stream this process already holds is borrowed, waiting briefly for one
in use to be parked: asking never starts a client stream, so it never brings
back a resident that was stopped.
``None`` means the resident is not this request's route (no idle stream here
for the home, a runtime without the operation, or a resident or transport
failure), and the caller starts the one-shot command.

The daemon host is the one caller that starts a stream: it serves this home's
resident from its first publication anyway, so ``start_private_state_resident``
opens the stream while admission runs, and the host's own private-state checks
from then on reuse it instead of starting a process each.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Iterator, Mapping
from contextvars import ContextVar
from pathlib import Path

RESIDENT_FEATURE = "native-windows-private-state-resident-v1"
_OPERATION = "windows_private_state"
_SCHEMA = "windows-private-state-resident.v1"
_TIMEOUT_SECONDS = 10.0
# A busy stream frees up within one resident round trip; this bounds the wait
# for it so an op that lands mid-request does not start a one-shot process.
_IDLE_WAIT_SECONDS = 1.0
# The Guard home whose stream this context may start; ``None`` borrows only.
_STARTING_HOME: ContextVar[Path | None] = ContextVar("native_private_state_starting_home", default=None)


def resident_private_state_answer(request: Mapping[str, object], *, output_limit: int) -> dict[str, object] | None:
    """The resident's answer to one private-state request, or ``None`` to use the command."""

    if os.name != "nt":
        return None
    from .native_resident_client import (
        native_resident_client_request,
        native_resident_guard_home_containing,
        native_resident_home_holds,
    )
    from .native_runtime import _isolated_environment, native_runtime_status

    deadline = time.monotonic() + _TIMEOUT_SECONDS
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or RESIDENT_FEATURE not in status.capabilities.features
    ):
        return None
    paths = tuple(Path(str(request[field])) for field in ("directory", "private_root") if field in request)
    starting_home = _STARTING_HOME.get()
    starts = starting_home is not None and bool(paths) and native_resident_home_holds(starting_home, paths)
    guard_home = starting_home if starts else native_resident_guard_home_containing(status.identity.path, paths)
    if guard_home is None:
        return None
    envelope = {"operation": _OPERATION, "request": {"guard_home": str(guard_home), "state": dict(request)}}
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        deadline_monotonic=deadline,
        idle_only=not starts,
        idle_wait_seconds=_IDLE_WAIT_SECONDS,
    )
    if response is None or len(response) > output_limit:
        return None
    try:
        decoded = json.loads(response)
    except ValueError:
        return None
    if not isinstance(decoded, dict) or decoded.get("schema") != _SCHEMA:
        return None
    answer = decoded.get("answer")
    return answer if isinstance(answer, dict) else None


@contextlib.contextmanager
def _starting_stream(guard_home: Path) -> Iterator[None]:
    token = _STARTING_HOME.set(Path(os.path.abspath(guard_home)))
    try:
        yield
    finally:
        _STARTING_HOME.reset(token)


def start_private_state_resident(guard_home: Path) -> None:
    """Open this process's resident stream for ``guard_home`` with one real check.

    The check ensures the home's runtime directory is owner-private, which the
    host needs before it publishes anyway. A missing directory is created by
    the one-shot command first, so the stream's state directory is pinned to
    one that exists. Only the daemon host calls this; every other caller keeps
    borrowing streams it already holds.
    """

    if os.name != "nt":
        return
    from .native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY
    from .native_policy_snapshot_windows_atomic import _windows_ensure_private_directory
    from .native_policy_snapshot_windows_support import _runtime_state_directory

    home = Path(os.path.abspath(guard_home))
    state_dir = home / NATIVE_RUNTIME_STATE_DIRECTORY
    if not state_dir.is_dir():
        _runtime_state_directory(home)
    with _starting_stream(home):
        _windows_ensure_private_directory(state_dir, private_root=home)


__all__ = ["RESIDENT_FEATURE", "resident_private_state_answer", "start_private_state_resident"]
