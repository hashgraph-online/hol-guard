"""Bounded, storage-independent daemon lifecycle evidence."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import TypedDict, cast

_JOURNAL_DIRECTORY = "daemon-lifecycle"
_MAX_JOURNAL_ENTRIES = 128
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_SAFE_LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SAFE_SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class _RequiredDaemonLifecycleEvent(TypedDict):
    version: int
    event: str
    recorded_at_ns: int
    pid: int


class DaemonLifecycleEvent(_RequiredDaemonLifecycleEvent, total=False):
    port: int
    session_id: str
    reason: str


def record_daemon_lifecycle_event(
    guard_home: Path,
    *,
    event: str,
    session_id: str | None = None,
    reason: str | None = None,
    pid: int | None = None,
    port: int | None = None,
) -> None:
    """Persist one privacy-safe lifecycle event without opening Guard SQLite."""

    if _SAFE_LABEL.fullmatch(event) is None:
        raise ValueError("Daemon lifecycle event must be a safe label.")
    if reason is not None and _SAFE_LABEL.fullmatch(reason) is None:
        raise ValueError("Daemon lifecycle reason must be a safe label.")
    if session_id is not None and _SAFE_SESSION_ID.fullmatch(session_id) is None:
        raise ValueError("Daemon lifecycle session ID must be a safe identifier.")
    resolved_pid = os.getpid() if pid is None else pid
    if resolved_pid <= 0:
        raise ValueError("Daemon lifecycle PID must be positive.")
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("Daemon lifecycle port must be valid.")
    recorded_at_ns = time.time_ns()
    payload = DaemonLifecycleEvent(
        version=1,
        event=event,
        recorded_at_ns=recorded_at_ns,
        pid=resolved_pid,
    )
    if port is not None:
        payload["port"] = port
    if session_id is not None:
        payload["session_id"] = session_id
    if reason is not None:
        payload["reason"] = reason

    journal_dir = guard_home / _JOURNAL_DIRECTORY
    if guard_home.is_symlink() or journal_dir.is_symlink():
        raise OSError("Daemon lifecycle journal paths must not be symbolic links.")
    journal_dir.mkdir(parents=True, exist_ok=True)
    if not journal_dir.is_dir():
        raise OSError("Daemon lifecycle journal path must be a directory.")
    _set_private_mode(journal_dir, _PRIVATE_DIRECTORY_MODE)
    identifier = uuid.uuid4().hex
    target = journal_dir / f"{recorded_at_ns:020d}-{payload['pid']:010d}-{identifier}.json"
    temporary = journal_dir / f".{identifier}.tmp"
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        _PRIVATE_FILE_MODE,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        _set_private_mode(target, _PRIVATE_FILE_MODE)
    finally:
        with suppress(OSError):
            temporary.unlink()
    _prune_journal(journal_dir)


def load_daemon_lifecycle_events(
    guard_home: Path,
    *,
    limit: int = 20,
) -> list[DaemonLifecycleEvent]:
    journal_dir = guard_home / _JOURNAL_DIRECTORY
    bounded_limit = max(0, min(limit, _MAX_JOURNAL_ENTRIES))
    if bounded_limit == 0 or journal_dir.is_symlink() or not journal_dir.is_dir():
        return []
    events: list[DaemonLifecycleEvent] = []
    for path in sorted(journal_dir.glob("*.json"), reverse=True)[:bounded_limit]:
        if path.is_symlink():
            continue
        try:
            value = cast(object, json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if _is_lifecycle_event(value):
            events.append(cast(DaemonLifecycleEvent, value))
    events.reverse()
    return events


def _is_lifecycle_event(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    mapping = cast(dict[object, object], value)
    event = mapping.get("event")
    recorded_at_ns = mapping.get("recorded_at_ns")
    pid = mapping.get("pid")
    session_id = mapping.get("session_id")
    reason = mapping.get("reason")
    port = mapping.get("port")
    if session_id is not None and (not isinstance(session_id, str) or _SAFE_SESSION_ID.fullmatch(session_id) is None):
        return False
    if reason is not None and (not isinstance(reason, str) or _SAFE_LABEL.fullmatch(reason) is None):
        return False
    if port is not None and (not isinstance(port, int) or not 1 <= port <= 65_535):
        return False
    return (
        mapping.get("version") == 1
        and isinstance(event, str)
        and _SAFE_LABEL.fullmatch(event) is not None
        and isinstance(recorded_at_ns, int)
        and recorded_at_ns > 0
        and isinstance(pid, int)
        and pid > 0
    )


def _prune_journal(journal_dir: Path) -> None:
    try:
        entries = sorted(journal_dir.glob("*.json"))
    except OSError:
        return
    for path in entries[:-_MAX_JOURNAL_ENTRIES]:
        with suppress(OSError):
            path.unlink()


def _set_private_mode(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    with suppress(OSError):
        path.chmod(mode)


__all__ = [
    "DaemonLifecycleEvent",
    "load_daemon_lifecycle_events",
    "record_daemon_lifecycle_event",
]
