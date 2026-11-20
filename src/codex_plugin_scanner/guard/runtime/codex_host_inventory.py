"""Read display metadata from an existing, same-user Codex host.

Only private, same-user Codex control sockets are eligible. No host or MCP process is started,
and public tool summaries never become schemas, account evidence, or permissions.

The native ``codex_host_inventory`` runner authority owns every socket, marker, process and
protocol decision. This module sends it paths, keeps the short-lived cache of what it answered,
and renders the result.
"""

from __future__ import annotations

import copy
import logging
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

_SNAPSHOT_TTL = 30.0
# The native read answers within the host timeout; the call gets a little longer
# to carry the answer back.
_CALL_MARGIN = 2.0
_LOGGER = logging.getLogger(__name__)
_FAILURE_CODES = frozenset(
    {
        "codex_host_changed",
        "codex_host_untrusted",
        "codex_host_invalid",
        "codex_host_limit",
        "codex_host_timeout",
        "codex_host_unavailable",
    }
)
# The discovery job turns these into the banner's guidance, so they are part of
# this module's contract rather than an internal detail.
HOST_FAILURE_CODES = _FAILURE_CODES

# The private socket a snapshot came from: its resolved path, and the device and
# inode of the alias and of the target.
_Source = tuple[str, tuple[int, int, int, int]]


@dataclass(frozen=True, slots=True)
class CodexHostInventory:
    connection_id: str
    apps: tuple[dict[str, object], ...]
    metadata_complete: bool
    host_pid: int
    managed_pid: int | None
    source: _Source | None = None

    def as_payload(self) -> dict[str, object]:
        return {
            "host": "Codex",
            "connection_id": self.connection_id,
            "catalog_coverage": "host-summary",
            "account_verified": False,
            "schemas_available": False,
            "permissions_granted": False,
            "snapshot_age": "unknown",
            "metadata_complete": self.metadata_complete,
            "apps": list(self.apps),
        }


class CodexHostInventoryCache:
    """Ephemeral public metadata, outside the grant store and request hot path."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot: tuple[float, Path, _Source, int, int | None, dict[str, object]] | None = None

    def refresh(self, *, codex_home: Path, cancel: threading.Event) -> None:
        try:
            snapshot = read_codex_host_inventory(codex_home=codex_home, cancel=cancel)
        except ValueError as error:
            if str(error) == "codex_host_cancelled":
                return
            with self._lock:
                self._snapshot = None
            if isinstance(error.__cause__, FileNotFoundError):
                # No Codex host is listening: there is nothing to show or to report.
                return
            reason = str(error) if str(error) in _FAILURE_CODES else "codex_host_invalid"
            _LOGGER.warning("Codex host inventory failed (%s)", reason)
            raise ValueError(reason) from None
        if cancel.is_set():
            return
        source = snapshot.source
        if source is None:
            with self._lock:
                self._snapshot = None
            raise ValueError("codex_host_invalid")
        with self._lock:
            if not cancel.is_set():
                payload = snapshot.as_payload()
                payload["expires_at_ms"] = int((time.time() + _SNAPSHOT_TTL) * 1000)
                self._snapshot = (
                    time.monotonic(),
                    codex_home,
                    source,
                    snapshot.host_pid,
                    snapshot.managed_pid,
                    payload,
                )

    def read(self) -> dict[str, object] | None:
        with self._lock:
            snapshot = self._snapshot
        if snapshot is None:
            return None
        seen, codex_home, source, pid, managed_pid, payload = snapshot
        if time.monotonic() - seen > _SNAPSHOT_TTL:
            return None
        try:
            answer = _native(
                {
                    "check": _paths(codex_home)
                    | {
                        "target": source[0],
                        "identity": list(source[1]),
                        "pid": pid,
                        "managed_pid": managed_pid,
                    }
                },
                timeout=_CALL_MARGIN,
            )
        except ValueError:
            return None
        if answer.get("valid") is not True:
            return None
        return copy.deepcopy(payload)


def _paths(codex_home: Path) -> dict[str, object]:
    """Where this process keeps its home and temporary files, which the native side cannot know."""
    try:
        home_dir: str | None = str(Path.home())
    except (RuntimeError, OSError):
        home_dir = None
    return {"codex_home": str(codex_home), "home_dir": home_dir, "temp_dir": tempfile.gettempdir()}


def _native(request: dict[str, object], *, timeout: float) -> dict[str, object]:
    """Ask the native ``codex_host_inventory`` kind; a call it could not answer is unavailable."""
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority(
            "codex_host_inventory",
            request,
            timeout_seconds=timeout,
            deadline_monotonic=time.monotonic() + timeout,
        )
    except NativeRunnerAuthorityError as error:
        raise ValueError(
            "codex_host_limit" if str(error).endswith("_too_large") else "codex_host_unavailable"
        ) from None


def _source(value: object) -> _Source:
    entry = cast(dict[str, object], value) if isinstance(value, dict) else {}
    target, identity = entry.get("target"), entry.get("identity")
    if (
        not isinstance(target, str)
        or not isinstance(identity, list)
        or len(identity) != 4
        or not all(type(item) is int for item in identity)
    ):
        raise ValueError("codex_host_invalid")
    return target, cast(tuple[int, int, int, int], tuple(identity))


def _optional_pid(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        raise ValueError("codex_host_invalid")
    return value


def read_codex_host_inventory(
    *,
    codex_home: Path,
    timeout: float = 5.0,
    cancel: threading.Event | None = None,
) -> CodexHostInventory:
    """Read an existing host snapshot, without credentials, startup or grants.

    The native read cannot be interrupted, so a cancellation is honored before
    it starts and when it returns.
    """
    cancel = cancel if cancel is not None else threading.Event()
    if cancel.is_set():
        raise ValueError("codex_host_cancelled")
    seconds = min(max(timeout, 0.1), 10.0)
    answer = _native(
        {"read": _paths(codex_home) | {"timeout_ms": int(seconds * 1000)}},
        timeout=seconds + _CALL_MARGIN,
    )
    if answer.get("absent") is True:
        raise ValueError("codex_host_unavailable") from FileNotFoundError("codex_host_absent")
    code = answer.get("error")
    if code is not None:
        raise ValueError(code if isinstance(code, str) and code in _FAILURE_CODES else "codex_host_invalid")
    if cancel.is_set():
        raise ValueError("codex_host_cancelled")
    snapshot = answer.get("snapshot")
    if not isinstance(snapshot, dict):
        raise ValueError("codex_host_invalid")
    apps, connection_id, complete = (
        snapshot.get("apps"),
        snapshot.get("connection_id"),
        snapshot.get("metadata_complete"),
    )
    pid = snapshot.get("host_pid")
    if (
        not isinstance(apps, list)
        or not all(isinstance(app, dict) for app in apps)
        or not isinstance(connection_id, str)
        or type(complete) is not bool
        or type(pid) is not int
    ):
        raise ValueError("codex_host_invalid")
    return CodexHostInventory(
        connection_id,
        tuple(cast(list[dict[str, object]], apps)),
        complete,
        pid,
        _optional_pid(snapshot.get("managed_pid")),
        _source(snapshot.get("source")),
    )
