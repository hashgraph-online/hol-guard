"""PyInstaller onefile extraction-dir ownership markers and orphan reclamation.

Onefile launches extract to ``<tempdir>/_MEIxxxxxx``; the bootloader parent
removes that directory on normal exit, but a hard-killed launch leaks it. Each
launch stamps an owner marker recording its pid and bootloader parent pid so the
resident daemon can prove a leaked directory is dead before reclaiming it.
Unmarked directories are deleted only when the caller injects an open-files
scanner and the dir is provably a Guard extraction (see ``onefile_unmarked``)
that no live process uses; otherwise they are only counted so operators can see
the legacy leak volume.

This module is imported on the frozen CLI fast path before heavy Guard imports,
so it must stay stdlib-only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .onefile_open_paths import OpenPathScanner
from .onefile_unmarked import (
    PARTIAL,
    UNMARKED_MIN_AGE,
    classify_unmarked_extraction,
)

_EXTRACTION_DIR_NAME = re.compile(r"^_MEI[0-9A-Za-z]{4,}$")

OWNER_MARKER_NAME = ".hol-guard-extraction-owner.json"
_OWNER_MARKER_SCHEMA = "guard.onefile-extraction-owner.v1"
_OWNER_MARKER_MAX_BYTES = 4096

_MAX_RECORDED_ERRORS = 8
_UNMARKED_BYTES_SAMPLE_LIMIT = 10
DEFAULT_MAX_UNMARKED_RECLAIMS = 250
DEFAULT_UNMARKED_TIME_BUDGET = timedelta(minutes=2)


def is_onefile_extraction_dir(path: Path, temp_root: Path) -> bool:
    """Return True only for a real ``_MEI*`` directory directly under temp_root."""

    if not _EXTRACTION_DIR_NAME.fullmatch(path.name):
        return False
    try:
        if path.is_symlink() or not path.is_dir():
            return False
        return path.resolve(strict=True).parent == temp_root.resolve(strict=True)
    except OSError:
        return False


def _guard_version() -> str:
    try:
        from ..version import __version__

        return __version__
    except Exception:
        return "unknown"


def record_extraction_owner(*, meipass: str | None, temp_root: Path | None = None) -> bool:
    """Stamp the current onefile extraction dir with its owning launch's pids.

    Only acts when running frozen and ``meipass`` is an actual onefile
    extraction dir under ``temp_root`` — in onedir mode ``sys._MEIPASS`` is the
    bundle's own directory and is never marked. Never raises.
    """

    try:
        if not getattr(sys, "frozen", False):
            return False
        if not isinstance(meipass, str) or not meipass:
            return False
        root = temp_root if temp_root is not None else Path(tempfile.gettempdir())
        extraction_dir = Path(meipass)
        if not is_onefile_extraction_dir(extraction_dir, root):
            return False
        payload = {
            "schema": _OWNER_MARKER_SCHEMA,
            "pid": os.getpid(),
            "parent_pid": os.getppid(),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "guard_version": _guard_version(),
        }
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        marker = extraction_dir / OWNER_MARKER_NAME
        descriptor, temp_name = tempfile.mkstemp(dir=extraction_dir, prefix=".owner-", suffix=".tmp")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, marker)
        finally:
            with suppress(OSError):
                os.unlink(temp_name)
        return True
    except Exception:
        return False


def _pid_alive(pid: int) -> bool:
    """Fail closed: a pid that cannot be proven dead counts as alive."""

    if pid <= 0:
        return True
    if os.name == "nt":
        try:
            from .windows_paths import windows_process_is_running

            return windows_process_is_running(pid)
        except Exception:
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except Exception:
        return True
    return True


@dataclass
class ExtractionReclaimResult:
    reclaimed_count: int = 0
    reclaimed_bytes: int = 0
    killed_launches: int = 0
    unmarked_count: int = 0
    unmarked_bytes_estimate: int = 0
    unmarked_reclaimed_count: int = 0
    unmarked_reclaimed_bytes: int = 0
    partial_reclaimed_count: int = 0
    # "disabled" (no scanner injected), "not_needed", "ok", or "unavailable"
    # (scan failed, so every unmarked dir was skipped).
    unmarked_scan: str = "disabled"
    unmarked_budget_exhausted: bool = False
    errors: list[str] = field(default_factory=list)


def _read_owner_marker(marker_path: Path) -> dict[str, int] | None:
    """Return the marker's ``pid``/``parent_pid`` only when the record is valid."""

    try:
        metadata = marker_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _OWNER_MARKER_MAX_BYTES:
            return None
        payload = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != _OWNER_MARKER_SCHEMA:
        return None
    pid = payload.get("pid")
    parent_pid = payload.get("parent_pid")
    if type(pid) is not int or type(parent_pid) is not int:
        return None
    return {"pid": pid, "parent_pid": parent_pid}


def _dir_bytes(root: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


def _remember_error(result: ExtractionReclaimResult, detail: str) -> None:
    if len(result.errors) < _MAX_RECORDED_ERRORS:
        result.errors.append(detail)


def _owned_by_current_user(metadata: os.stat_result) -> bool:
    getuid = getattr(os, "getuid", None)
    return getuid is not None and metadata.st_uid == getuid()


def reclaim_orphaned_extraction_dirs(
    *,
    temp_root: Path,
    current_meipass: str | None,
    now: datetime,
    min_age: timedelta = timedelta(minutes=10),
    pid_alive: Callable[[int], bool] = _pid_alive,
    should_stop: Callable[[], bool] = lambda: False,
    open_path_scanner: OpenPathScanner | None = None,
    unmarked_min_age: timedelta = UNMARKED_MIN_AGE,
    max_unmarked_reclaims: int = DEFAULT_MAX_UNMARKED_RECLAIMS,
    unmarked_time_budget: timedelta | None = DEFAULT_UNMARKED_TIME_BUDGET,
    monotonic: Callable[[], float] = time.monotonic,
    dry_run: bool = False,
) -> ExtractionReclaimResult:
    """Reclaim ``_MEI*`` dirs that are provably dead.

    Marked dirs are deleted when both the recorded pid and bootloader parent pid
    are dead. Unmarked dirs are deleted only when ``open_path_scanner`` is
    injected and every condition holds: the dir is a Guard bundle or partial
    Guard extraction (``classify_unmarked_extraction``), owned by this user, not
    the current extraction, older than ``unmarked_min_age``, and absent from the
    single system-wide open-files scan. If the scan fails every unmarked dir is
    skipped. Work per call is bounded by ``max_unmarked_reclaims`` and
    ``unmarked_time_budget``; remaining dirs are only counted. With ``dry_run``
    every proof still runs and the counters report what would be deleted, but
    nothing is removed.
    """

    result = ExtractionReclaimResult()
    try:
        resolved_root = temp_root.resolve(strict=True)
    except OSError:
        _remember_error(result, "temp_root_unavailable")
        return result
    current: Path | None = None
    if isinstance(current_meipass, str) and current_meipass:
        try:
            current = Path(current_meipass).resolve(strict=True)
        except OSError:
            current = None
    try:
        children = sorted(temp_root.iterdir())
    except OSError:
        _remember_error(result, "temp_root_listing_failed")
        return result
    now_seconds = now.timestamp()
    unmarked_sampled_count = 0
    unmarked_sampled_bytes = 0
    in_use: frozenset[str] | None = None
    scan_attempted = False
    started = monotonic()
    budget_seconds = unmarked_time_budget.total_seconds() if unmarked_time_budget is not None else None
    for child in children:
        if should_stop():
            return result
        if not _EXTRACTION_DIR_NAME.fullmatch(child.name):
            continue
        try:
            child_stat = child.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(child_stat.st_mode) or stat.S_ISLNK(child_stat.st_mode):
            continue
        try:
            resolved_child = child.resolve(strict=True)
        except OSError:
            continue
        if resolved_child.parent != resolved_root:
            continue
        if current is not None and resolved_child == current:
            continue
        age_seconds = now_seconds - child_stat.st_mtime
        if age_seconds < min_age.total_seconds():
            continue
        owner = _read_owner_marker(child / OWNER_MARKER_NAME)
        if owner is not None:
            if pid_alive(owner["pid"]) or pid_alive(owner["parent_pid"]):
                continue
            # Re-verify the marker right before deleting so a concurrent live
            # launch that rewrote it cannot be swept out from under itself.
            if _read_owner_marker(child / OWNER_MARKER_NAME) != owner:
                continue
            size = _dir_bytes(child)
            try:
                if not dry_run:
                    shutil.rmtree(child)
            except OSError as error:
                _remember_error(result, f"rmtree:{type(error).__name__}")
                continue
            result.reclaimed_count += 1
            result.reclaimed_bytes += size
            result.killed_launches += 1
            continue
        kind = classify_unmarked_extraction(child)
        if kind is None:
            continue
        reclaimable = (
            open_path_scanner is not None
            and age_seconds >= unmarked_min_age.total_seconds()
            and _owned_by_current_user(child_stat)
        )
        if reclaimable and not scan_attempted:
            scan_attempted = True
            in_use = open_path_scanner(resolved_root) if open_path_scanner is not None else None
            result.unmarked_scan = "ok" if in_use is not None else "unavailable"
            if in_use is None:
                _remember_error(result, "open_path_scan_unavailable")
        if reclaimable and in_use is not None:
            exhausted = result.unmarked_reclaimed_count >= max_unmarked_reclaims or (
                budget_seconds is not None and monotonic() - started >= budget_seconds
            )
            if exhausted:
                result.unmarked_budget_exhausted = True
            elif child.name not in in_use and _reclaim_unmarked_dir(child, child_stat, kind, result, dry_run):
                continue
        result.unmarked_count += 1
        # Walking every legacy dir on the hourly sweep is too expensive on
        # hosts with hundreds of leaks; sample a bounded set and estimate.
        if unmarked_sampled_count < _UNMARKED_BYTES_SAMPLE_LIMIT:
            unmarked_sampled_count += 1
            unmarked_sampled_bytes += _dir_bytes(child)
    if open_path_scanner is not None and not scan_attempted:
        result.unmarked_scan = "not_needed"
    if unmarked_sampled_count:
        result.unmarked_bytes_estimate = round(unmarked_sampled_bytes / unmarked_sampled_count * result.unmarked_count)
    return result


def _reclaim_unmarked_dir(
    child: Path,
    child_stat: os.stat_result,
    kind: str,
    result: ExtractionReclaimResult,
    dry_run: bool = False,
) -> bool:
    """Delete one proven-dead unmarked dir; return True when it was removed."""

    try:
        recheck = child.lstat()
    except OSError:
        return False
    # A launch that touched the dir since we listed it is alive, not leaked.
    if recheck.st_mtime != child_stat.st_mtime or recheck.st_ino != child_stat.st_ino:
        return False
    # Any marker file, even a corrupt one, means a launch claimed this dir.
    if os.path.lexists(child / OWNER_MARKER_NAME):
        return False
    size = _dir_bytes(child)
    try:
        if not dry_run:
            shutil.rmtree(child)
    except OSError as error:
        _remember_error(result, f"rmtree:{type(error).__name__}")
        return False
    result.reclaimed_count += 1
    result.reclaimed_bytes += size
    result.unmarked_reclaimed_count += 1
    result.unmarked_reclaimed_bytes += size
    if kind == PARTIAL:
        result.partial_reclaimed_count += 1
    return True
