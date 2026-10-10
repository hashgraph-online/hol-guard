"""Prune dead native-resident state: stale ``resident-v3-*`` dirs and dead sockets.

Everything here is fail-closed. An entry is removed only when it is provably
unowned; any doubt (unreadable state, live or unverifiable pid, held owner lock,
socket that still answers, wrong uid, symlink, too recent) keeps it.

Proof for a ``resident-v3-<digest>`` directory under ``<guard_home>/native-runtime``:

* it is a real directory (not a symlink) owned by the current user;
* neither it nor anything directly inside it changed within ``min_age``;
* every ``generation-*.json`` parses, and both the resident ``process_id`` and
  ``owner_process_id`` it names are gone (``kill(pid, 0)`` says no such
  process; a permission error counts as alive). A recycled pid therefore keeps
  the directory, which only delays pruning;
* the ``managed-resident-owner.v1.lock`` flock can be taken without blocking,
  and is held while the directory is renamed to a tombstone, so no live
  resident can own it at that moment.

Proof for a resident socket (``hook-v2-*.sock`` from older builds, ``h3-*.sock``
from current ones): a socket-type file owned by this user, older than
``socket_min_age``, whose ``connect()`` is refused (nothing is listening).
Stdlib-only; POSIX only (Windows reports ``unsupported``).
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import stat
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

RESIDENT_DIR_PREFIX = "resident-v3-"
OWNER_LOCK_NAME = "managed-resident-owner.v1.lock"
SOCKET_PATTERNS = ("hook-v2-", "h3-")
STALE_DIR_MIN_AGE_SECONDS = 3600.0
STALE_SOCKET_MIN_AGE_SECONDS = 600.0
UNPARSEABLE_STATE_MIN_AGE_SECONDS = 24 * 3600.0
DEFAULT_MAX_ENTRIES = 2000
DEFAULT_TIME_BUDGET_SECONDS = 30.0
_MAX_STATE_BYTES = 64 * 1024

PidAlive = Callable[[int], bool]
LockProbe = Callable[[Path], "bool | None"]
SocketProbe = Callable[[Path], str]


@dataclass
class PruneReport:
    dry_run: bool
    status: str = "ok"
    removed_dirs: list[str] = field(default_factory=list)
    removed_sockets: list[str] = field(default_factory=list)
    kept: dict[str, int] = field(default_factory=dict)
    budget_exhausted: bool = False
    errors: list[str] = field(default_factory=list)

    def keep(self, reason: str) -> None:
        self.kept[reason] = self.kept.get(reason, 0) + 1

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.status,
            "dry_run": self.dry_run,
            "stale_dirs": len(self.removed_dirs),
            "dead_sockets": len(self.removed_sockets),
            "removed_dirs": self.removed_dirs[:50],
            "removed_sockets": self.removed_sockets[:50],
            "kept": dict(self.kept),
            "budget_exhausted": self.budget_exhausted,
            "errors": self.errors[:10],
        }


def pid_is_alive(pid: int) -> bool:
    """Conservative liveness: anything but "no such process" counts as alive."""

    if pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def probe_owner_lock(directory: Path) -> bool | None:
    """True when the owner flock is free, False when held, None when unknowable.

    A missing lock file is "free": no resident ever took the lock in this dir.
    """

    try:
        import fcntl
    except ImportError:
        return None
    lock_path = directory / OWNER_LOCK_NAME
    try:
        descriptor = os.open(lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return True
    except OSError:
        return None
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        except OSError:
            return None
        return True
    finally:
        os.close(descriptor)


def probe_socket(path: Path) -> str:
    """Return ``dead`` only when connect() is refused; anything else is ``unknown``/``live``."""

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.5)
        probe.connect(str(path))
    except ConnectionRefusedError:
        return "dead"
    except FileNotFoundError:
        return "gone"
    except OSError:
        return "unknown"
    else:
        return "live"
    finally:
        probe.close()


def _owned_regular(metadata: os.stat_result, uid: int) -> bool:
    return uid < 0 or metadata.st_uid == uid


def _newest_mtime(directory: Path) -> float | None:
    try:
        newest = directory.lstat().st_mtime
        for entry in os.scandir(directory):
            newest = max(newest, entry.stat(follow_symlinks=False).st_mtime)
    except OSError:
        return None
    return newest


def _generation_pids(directory: Path) -> tuple[set[int], bool]:
    """Collect pids named by generation files; the flag is False if any is unreadable."""

    pids: set[int] = set()
    clean = True
    for state in directory.glob("generation-*.json"):
        try:
            metadata = state.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_STATE_BYTES:
                clean = False
                continue
            payload = json.loads(state.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            clean = False
            continue
        found = False
        if isinstance(payload, dict):
            for key in ("process_id", "owner_process_id"):
                value = payload.get(key)
                if type(value) is int and value > 0:
                    pids.add(value)
                    found = True
        clean = clean and found
    return pids, clean


def _stale_dir_verdict(
    directory: Path,
    *,
    now: float,
    uid: int,
    min_age: float,
    pid_alive: PidAlive,
    lock_probe: LockProbe,
) -> str:
    """Return ``stale`` or the reason the directory must be kept."""

    try:
        metadata = directory.lstat()
    except OSError:
        return "unreadable"
    if not stat.S_ISDIR(metadata.st_mode):
        return "not_directory"
    if not _owned_regular(metadata, uid):
        return "foreign_owner"
    newest = _newest_mtime(directory)
    if newest is None:
        return "unreadable"
    age = now - newest
    if age < min_age:
        return "recent"
    pids, clean = _generation_pids(directory)
    if not clean and age < UNPARSEABLE_STATE_MIN_AGE_SECONDS:
        return "unverifiable_state"
    if any(pid_alive(pid) for pid in pids):
        return "owner_alive"
    if lock_probe(directory) is not True:
        return "owner_lock_unverified"
    return "stale"


def _prune_resident_dir(directory: Path, report: PruneReport, *, dry_run: bool) -> None:
    if dry_run:
        report.removed_dirs.append(str(directory))
        return
    try:
        import fcntl
    except ImportError:
        report.keep("unsupported_platform")
        return
    try:
        descriptor = os.open(
            directory / OWNER_LOCK_NAME,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except FileNotFoundError:
        descriptor = None
    except OSError:
        report.keep("owner_lock_unverified")
        return
    tombstone = directory.with_name(f".pruned-{directory.name}-{os.getpid()}")
    try:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                report.keep("owner_lock_unverified")
                return
        try:
            directory.rename(tombstone)
        except OSError:
            report.keep("rename_failed")
            return
    finally:
        if descriptor is not None:
            os.close(descriptor)
    shutil.rmtree(tombstone, ignore_errors=True)
    if tombstone.exists():
        report.errors.append("tombstone_not_removed")
    report.removed_dirs.append(str(directory))


def _is_resident_socket_name(name: str) -> bool:
    return name.endswith(".sock") and name.startswith(SOCKET_PATTERNS)


def _prune_socket(
    path: Path,
    report: PruneReport,
    *,
    now: float,
    uid: int,
    min_age: float,
    probe: SocketProbe,
    dry_run: bool,
) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        return
    if not stat.S_ISSOCK(metadata.st_mode):
        report.keep("not_socket")
        return
    if not _owned_regular(metadata, uid):
        report.keep("foreign_owner")
        return
    if now - metadata.st_mtime < min_age:
        report.keep("recent_socket")
        return
    verdict = probe(path)
    if verdict == "gone":
        return
    if verdict != "dead":
        report.keep("socket_not_provably_dead")
        return
    if not dry_run:
        try:
            current = path.lstat()
            if not stat.S_ISSOCK(current.st_mode) or current.st_ino != metadata.st_ino:
                report.keep("socket_changed")
                return
            path.unlink()
        except OSError:
            report.errors.append("socket_unlink_failed")
            return
    report.removed_sockets.append(str(path))


def _socket_candidates(directories: Iterable[Path]) -> Iterable[Path]:
    for directory in directories:
        try:
            for entry in os.scandir(directory):
                if _is_resident_socket_name(entry.name):
                    yield Path(entry.path)
        except OSError:
            continue


def default_socket_roots() -> tuple[Path, ...]:
    """Socket directories created by the resident: ``<tmp>/hgr-*`` (never recursive)."""

    roots: list[Path] = []
    for base in (Path("/private/tmp"), Path("/tmp")):
        try:
            for entry in os.scandir(base):
                if entry.name.startswith("hgr-") and entry.is_dir(follow_symlinks=False):
                    roots.append(Path(entry.path))
        except OSError:
            continue
        if roots:
            break
    return tuple(roots)


def prune_native_runtime(
    guard_home: Path,
    *,
    dry_run: bool = False,
    now: float | None = None,
    min_age: float = STALE_DIR_MIN_AGE_SECONDS,
    socket_min_age: float = STALE_SOCKET_MIN_AGE_SECONDS,
    pid_alive: PidAlive = pid_is_alive,
    lock_probe: LockProbe = probe_owner_lock,
    socket_probe: SocketProbe = probe_socket,
    socket_roots: Iterable[Path] | None = None,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    time_budget: float = DEFAULT_TIME_BUDGET_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
) -> PruneReport:
    """Remove provably-dead resident dirs and sockets; never raises."""

    report = PruneReport(dry_run=dry_run)
    if sys.platform.startswith("win"):
        report.status = "unsupported"
        return report
    state_dir = guard_home / "native-runtime"
    moment = time.time() if now is None else now
    uid = os.getuid() if hasattr(os, "getuid") else -1
    deadline = monotonic() + time_budget
    handled = 0

    def over_budget() -> bool:
        nonlocal handled
        handled += 1
        if handled > max_entries or monotonic() > deadline:
            report.budget_exhausted = True
            return True
        return False

    resident_dirs: list[Path] = []
    state_metadata: os.stat_result | None
    try:
        state_metadata = state_dir.lstat()
    except FileNotFoundError:
        state_metadata = None
    except OSError:
        report.status = "unavailable"
        report.errors.append("state_dir_unreadable")
        return report
    state_present = state_metadata is not None
    if state_metadata is not None:
        if not stat.S_ISDIR(state_metadata.st_mode) or not _owned_regular(state_metadata, uid):
            report.status = "unavailable"
            report.errors.append("state_dir_untrusted")
            return report
        try:
            children = sorted(entry.path for entry in os.scandir(state_dir))
        except OSError:
            report.status = "unavailable"
            report.errors.append("state_dir_unreadable")
            return report
        resident_dirs = [Path(path) for path in children if os.path.basename(path).startswith(RESIDENT_DIR_PREFIX)]
    for directory in resident_dirs:
        if over_budget():
            return report
        verdict = _stale_dir_verdict(
            directory,
            now=moment,
            uid=uid,
            min_age=min_age,
            pid_alive=pid_alive,
            lock_probe=lock_probe,
        )
        if verdict == "stale":
            with contextlib.suppress(OSError):
                _prune_resident_dir(directory, report, dry_run=dry_run)
        else:
            report.keep(verdict)
    # Sockets: the state dir, each surviving resident dir, and the tmp socket dirs.
    surviving = [path for path in resident_dirs if path.exists()] if not dry_run else resident_dirs
    roots = [
        *([state_dir] if state_present else []),
        *surviving,
        *(socket_roots if socket_roots is not None else default_socket_roots()),
    ]
    for socket_path in _socket_candidates(roots):
        if over_budget():
            return report
        _prune_socket(
            socket_path,
            report,
            now=moment,
            uid=uid,
            min_age=socket_min_age,
            probe=socket_probe,
            dry_run=dry_run,
        )
    return report


__all__ = [
    "PruneReport",
    "default_socket_roots",
    "pid_is_alive",
    "probe_owner_lock",
    "probe_socket",
    "prune_native_runtime",
]
