"""Updater staging markers and path checks.

The staging sweep itself runs in the native runtime
(``storage_retention.prune_stale_update_staging``).
"""

from __future__ import annotations

import stat as stat_module
from pathlib import Path

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
