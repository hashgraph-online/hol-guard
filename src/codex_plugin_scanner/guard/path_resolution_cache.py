"""Short-lived canonical-path memo guarded by filesystem identity.

Hook admission canonicalizes the same few directories (workspace, Guard home,
state directory, temporary roots) on every request. Each canonicalization walks
every path component. A remembered spelling is reused only while every
component of that spelling is still a non-symlink with the same device and
inode, the requested path still stats as that object, and the entry is younger
than the lifetime below. A swapped directory, a replacement symlink, or a
symlinked ancestor is resolved again. A cache hit re-checks the stored
component spellings rather than re-deriving them.
"""

from __future__ import annotations

import os
import stat
import threading
import time

_RESOLUTION_LIFETIME_SECONDS = 1.0
_MAX_REMEMBERED_PATHS = 512
_lock = threading.Lock()
_ComponentMarks = tuple[tuple[int, int], ...]
_ComponentPrefixes = tuple[str, ...]
_remembered: dict[tuple[str, bool], tuple[int, int, float, str, _ComponentMarks, _ComponentPrefixes]] = {}


def _component_prefixes(path: str) -> _ComponentPrefixes:
    """Spelling of every component walked by the identity check, root first."""

    absolute = os.path.abspath(path)
    drive, tail = os.path.splitdrive(absolute)
    current = f"{drive}{os.sep}" if drive else os.sep
    prefixes = [current]
    for piece in tail.split(os.sep):
        if piece:
            current = os.path.join(current, piece)
            prefixes.append(current)
    return tuple(prefixes)


def _component_marks(path: str) -> _ComponentMarks | None:
    """Identity of each component, or None when any component is a symlink."""

    marks: list[tuple[int, int]] = []
    for target in _component_prefixes(path):
        try:
            info = os.lstat(target)
        except (OSError, ValueError):
            return None
        if stat.S_ISLNK(info.st_mode):
            return None
        marks.append((info.st_dev, info.st_ino))
    return tuple(marks)


def _marks_unchanged(prefixes: _ComponentPrefixes, marks: _ComponentMarks) -> bool:
    """Whether every remembered component still lstat()s as the same non-symlink."""

    if len(prefixes) != len(marks):
        return False
    for target, (st_dev, st_ino) in zip(prefixes, marks, strict=True):
        try:
            info = os.lstat(target)
        except (OSError, ValueError):
            return False
        if stat.S_ISLNK(info.st_mode) or info.st_dev != st_dev or info.st_ino != st_ino:
            return False
    return True


def cached_realpath(path: str, *, strict: bool = False) -> str:
    """``os.path.realpath`` that skips the component walk for a recently seen directory."""

    key = (path, strict)
    try:
        identity = os.stat(path)
    except (OSError, ValueError):
        return os.path.realpath(path, strict=strict)
    now = time.monotonic()
    with _lock:
        remembered = _remembered.get(key)
    if (
        remembered is not None
        and remembered[0] == identity.st_dev
        and remembered[1] == identity.st_ino
        and now - remembered[2] < _RESOLUTION_LIFETIME_SECONDS
        and _marks_unchanged(remembered[5], remembered[4])
    ):
        return remembered[3]
    resolved = os.path.realpath(path, strict=strict)
    marks = _component_marks(resolved)
    if marks is None:
        return resolved
    with _lock:
        if len(_remembered) >= _MAX_REMEMBERED_PATHS:
            _remembered.clear()
        _remembered[key] = (identity.st_dev, identity.st_ino, now, resolved, marks, _component_prefixes(resolved))
    return resolved


def clear_cached_realpaths() -> None:
    with _lock:
        _remembered.clear()
