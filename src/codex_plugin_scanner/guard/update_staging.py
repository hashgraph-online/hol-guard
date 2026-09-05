"""Pruning of updater staging that outlives the updates that created it."""

from __future__ import annotations

import contextlib
import shutil
import stat as stat_module
import time
from pathlib import Path

_STAGING_PRUNE_AGE_SECONDS = 7 * 24 * 60 * 60
_UPDATE_RUNTIME_DIR_NAME = "update-runtime"
_ACTIVITY_MARKER_NAME = "active.json"


def note_update_activity(guard_home: Path) -> None:
    """Record that a trusted update is using the staging tree right now.

    The marker's mtime is the signal: the staging sweep refuses to delete
    anything while it is fresh, because the reused staging roots keep their
    old directory mtimes even while an update writes deep inside them. A
    write failure raises so the updater treats an unmarkable tree as
    unavailable instead of running unprotected.
    """

    marker = guard_home / _UPDATE_RUNTIME_DIR_NAME / _ACTIVITY_MARKER_NAME
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text('{"staging": "active"}\n', encoding="utf-8")


def prune_stale_update_staging(
    guard_home: Path,
    *,
    age_seconds: int = _STAGING_PRUNE_AGE_SECONDS,
) -> None:
    """Best-effort cleanup of update staging left by finished or abandoned runs.

    The trusted updater runs each update with a neutral HOME and wheel staging
    under ``<guard_home>/update-runtime``; without a sweep those directories
    accumulate for the life of the install (multiple gigabytes on long-lived
    machines). Every child of the runtime tree older than the age gate is
    deleted — including subdirectories future updaters may introduce — except
    the activity marker, and the whole sweep is skipped while that marker says
    an update ran recently enough to still own the tree.
    """

    runtime = guard_home / _UPDATE_RUNTIME_DIR_NAME
    # Never traverse through a linked component: rmtree below a symlinked
    # runtime tree would delete whatever the link points at.
    try:
        reject_linked_path_components(runtime)
    except OSError:
        return
    marker = runtime / _ACTIVITY_MARKER_NAME
    try:
        if time.time() - marker.stat().st_mtime < _STAGING_PRUNE_AGE_SECONDS:
            return
    except OSError:
        pass
    cutoff = time.time() - age_seconds
    # The whole walk stays inside the guard: iterdir lists lazily, so a
    # missing or vanishing runtime directory raises mid-iteration.
    try:
        for child in runtime.iterdir():
            if child.name == _ACTIVITY_MARKER_NAME:
                continue
            try:
                if child.lstat().st_mtime > cutoff:
                    continue
            except OSError:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                with contextlib.suppress(OSError):
                    child.unlink()
    except OSError:
        return


def reject_linked_path_components(path: Path) -> None:
    """Reject any symlinked component of ``path`` (moved from the updater).

    The neutral staging directories must never resolve through a link an
    attacker could swap; shared here so the staging sweep and the updater
    validate paths identically.
    """

    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        if stat_module.S_ISLNK(metadata.st_mode) or bool(int(getattr(metadata, "st_file_attributes", 0)) & 0x400):
            raise OSError("symlinked staging path component")
