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
from collections.abc import Iterable

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


#: What one path component was when it was witnessed: the object it named, who
#: owns it, what it is, and, for a symlink, where it pointed. Identity alone is
#: not enough for an answer that depended on ownership, on the component being
#: a directory, or on where a link led.
_ComponentIdentity = tuple[int, int, int, int, int, str | None]
IdentityWitness = tuple[tuple[str, ...], tuple[_ComponentIdentity, ...]]


def _component_identity(component: str) -> _ComponentIdentity | None:
    """What this one component is, or ``None`` when it cannot be read."""

    try:
        info = os.lstat(component)
    except (OSError, ValueError):
        return None
    link: str | None = None
    if stat.S_ISLNK(info.st_mode):
        try:
            link = os.readlink(component)
        except (OSError, ValueError):
            return None
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, link)


_SEPARATORS = os.sep + (os.altsep or "")


def _witnessable_spelling(path: str) -> str | None:
    """This spelling when the walk below witnesses every component it names.

    The walk reads the components a spelling writes down. A ``..`` segment is
    not one of them: ``os.path.normpath`` removes it and the component before
    it without touching the disk, while the runtime resolves it on disk, so
    `/home/u/project/../x` is settled through `project` but would be witnessed
    without it, and repointing that link would leave the old answer standing.
    Only a spelling that is already the one the walk will witness, bar a
    trailing separator, is witnessed at all.
    """

    if not os.path.isabs(path):
        return None
    trimmed = path.rstrip(_SEPARATORS)
    if not os.path.splitdrive(trimmed)[1]:
        # A root names itself; stripping its separator would leave nothing.
        trimmed = path
    return trimmed if os.path.normpath(trimmed) == trimmed else None


def identity_witness(paths: Iterable[str]) -> IdentityWitness | None:
    """What every component of these paths is right now, or ``None``.

    ``None`` means nothing derived from these spellings may be remembered: a
    relative path names a different directory from a different working
    directory, a spelling that is not already in normal form hides components
    from the walk, and a component that cannot be read says nothing at all. A
    symlink is witnessed by where it pointed, so a repointed link ends the
    reuse rather than preventing it; every component after it is read through
    it and witnessed by the object it reached.
    """

    seen: dict[str, _ComponentIdentity] = {}
    for path in paths:
        spelling = _witnessable_spelling(path)
        if spelling is None:
            return None
        for component in _component_prefixes(spelling):
            if component in seen:
                continue
            identity = _component_identity(component)
            if identity is None:
                return None
            seen[component] = identity
    if not seen:
        return None
    return tuple(seen), tuple(seen.values())


def identity_unchanged(witness: IdentityWitness) -> bool:
    """Whether every witnessed component is still the same object, owner and kind."""

    components, identities = witness
    if len(components) != len(identities):
        return False
    for component, identity in zip(components, identities, strict=True):
        if _component_identity(component) != identity:
            return False
    return True


def clear_cached_realpaths() -> None:
    with _lock:
        _remembered.clear()
