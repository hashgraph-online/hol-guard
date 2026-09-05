"""Pruning of updater staging that outlives the updates that created it."""

from __future__ import annotations

import contextlib
import shutil
import time
from pathlib import Path

_STAGING_PRUNE_AGE_SECONDS = 7 * 24 * 60 * 60
_UPDATE_RUNTIME_DIR_NAME = "update-runtime"


def prune_stale_update_staging(
    guard_home: Path,
    *,
    age_seconds: int = _STAGING_PRUNE_AGE_SECONDS,
) -> None:
    """Best-effort cleanup of update staging left by finished or abandoned runs.

    The trusted updater runs each update with a neutral HOME and wheel staging
    under ``<guard_home>/update-runtime``; without a sweep those directories
    accumulate for the life of the install (multiple gigabytes on long-lived
    machines). Entries older than the age gate are deleted, so an update that
    started recently — including one running right now — is never touched.
    """

    runtime = guard_home / _UPDATE_RUNTIME_DIR_NAME
    cutoff = time.time() - age_seconds
    for staging in (runtime / "home", runtime / "tmp", runtime / "wheels"):
        try:
            children = list(staging.iterdir())
        except OSError:
            continue
        for child in children:
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
