"""Owner-private Windows state files, kept by the native runtime.

The runtime's ``windows-private-state`` command reads, replaces and deletes
each file through held directory handles and checks its owner and DACL, and
creates or repairs the private directories they live in; these wrappers
encode the request and raise its failure code.

A process that already talks to the resident runtime for the Guard home the
file lives in asks that resident; elsewhere each request starts a runtime
process. Idle workers recheck the same handful of files every second, so a
read the runtime verified is remembered for a short window while the file,
and the directory it was read from, keep the identity they had on both sides
of that read. Any write or delete through
these wrappers forgets the file, and a replaced, rewritten, created or
removed file misses at once.
"""

from __future__ import annotations

import base64
import binascii
import os
import stat
import threading
import time
from collections import OrderedDict
from pathlib import Path

from .native_policy_snapshot_constants import POLICY_SNAPSHOT_MAX_BYTES, NativePolicySnapshotError

_PRIVATE_STATE_FEATURE = "native-windows-private-state-v1"
_PRIVATE_DIRECTORY_FEATURE = "native-windows-private-directory-v1"
_PRIVATE_STATE_COMMAND = "windows-private-state"
_PRIVATE_STATE_SCHEMA = "windows-private-state.v1"
_PRIVATE_STATE_TIMEOUT_SECONDS = 10.0
_PRIVATE_STATE_ANSWER_OVERHEAD = 4096
# How long a verified read stands in for the runtime while nothing about the
# file or its directory has changed. Content changes are seen at once through
# the file identity; the window bounds how long an ACL change made in place by
# the file's owner goes unseen.
_PRIVATE_READ_RECHECK_SECONDS = 60.0
_PRIVATE_READ_MEMO_ENTRIES = 32

# (directory, name, private root, byte limit) -> (identity, content, verified at)
_ReadKey = tuple[str, str, str, int]
_Identity = tuple[tuple[int, int], tuple[int, int, int, int] | None]
_clock = time.monotonic
_private_reads_lock = threading.Lock()
_private_reads: OrderedDict[_ReadKey, tuple[_Identity, bytes | None, float]] = OrderedDict()


def _private_state_answer(
    request: dict[str, object],
    *,
    output_limit: int,
    feature: str,
) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer
    from .native_policy_snapshot_windows_resident import resident_private_state_answer

    body = {"schema": _PRIVATE_STATE_SCHEMA, **request}
    answer = resident_private_state_answer(body, output_limit=output_limit)
    if answer is not None:
        return answer
    return runtime_answer(
        feature,
        _PRIVATE_STATE_COMMAND,
        body,
        output_limit=output_limit,
        timeout_seconds=_PRIVATE_STATE_TIMEOUT_SECONDS,
    )


def _private_state(
    op: str,
    field: str,
    *,
    directory: Path,
    name: str | None,
    private_root: Path | None,
    output_limit: int = _PRIVATE_STATE_ANSWER_OVERHEAD,
    feature: str = _PRIVATE_STATE_FEATURE,
    **request: object,
) -> object:
    """The runtime's `field` answer for one file or directory, or its failure code raised."""

    body: dict[str, object] = {"op": op, "directory": str(directory), **request}
    if name is not None:
        body["name"] = name
    if private_root is not None:
        body["private_root"] = str(private_root)
    answer = _private_state_answer(body, output_limit=output_limit, feature=feature)
    if answer is None:
        raise NativePolicySnapshotError("native_windows_private_state_unavailable")
    error = answer.get("error")
    if isinstance(error, str) and error:
        raise NativePolicySnapshotError(error)
    if field not in answer:
        raise NativePolicySnapshotError("native_windows_private_state_unavailable")
    return answer[field]


def _remembers_private_reads() -> bool:
    return os.name == "nt"


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _read_key(directory: Path, name: str, private_root: Path | None, maximum_bytes: int) -> _ReadKey:
    root = "" if private_root is None else _path_key(private_root)
    return _path_key(directory), os.path.normcase(name), root, maximum_bytes


def _private_identity(directory: Path, name: str) -> _Identity | None:
    """The directory and file identity, or ``None`` when it cannot be trusted.

    A directory reached through a junction or link, a file that is a link, or
    anything that is not a plain file has no identity and is never remembered.
    A missing file in a plain directory has the file part ``None``.
    """

    from .store_base import _windows_path_is_direct

    directory_key = _path_key(directory)
    if not _windows_path_is_direct(directory_key):
        return None
    try:
        directory_stat = os.lstat(directory_key)
    except OSError:
        return None
    if not stat.S_ISDIR(directory_stat.st_mode) or not directory_stat.st_ino:
        return None
    try:
        file_stat = os.lstat(os.path.join(directory_key, name))
    except FileNotFoundError:
        return (directory_stat.st_dev, directory_stat.st_ino), None
    except OSError:
        return None
    if not stat.S_ISREG(file_stat.st_mode) or not file_stat.st_ino:
        return None
    if getattr(file_stat, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return None
    return (
        (directory_stat.st_dev, directory_stat.st_ino),
        (file_stat.st_dev, file_stat.st_ino, file_stat.st_size, file_stat.st_mtime_ns),
    )


def _remembered_read(key: _ReadKey, directory: Path, name: str) -> tuple[bool, bytes | None]:
    with _private_reads_lock:
        remembered = _private_reads.get(key)
    if remembered is None:
        return False, None
    identity, content, verified_at = remembered
    if _clock() - verified_at >= _PRIVATE_READ_RECHECK_SECONDS:
        return False, None
    if _private_identity(directory, name) != identity:
        return False, None
    return True, content


def _remember_read(key: _ReadKey, identity: _Identity, content: bytes | None, verified_at: float) -> None:
    with _private_reads_lock:
        _private_reads[key] = (identity, content, verified_at)
        _private_reads.move_to_end(key)
        while len(_private_reads) > _PRIVATE_READ_MEMO_ENTRIES:
            _private_reads.popitem(last=False)


def _forget_private_file(directory: Path, name: str) -> None:
    directory_key = _path_key(directory)
    name_key = os.path.normcase(name)
    with _private_reads_lock:
        for key in [key for key in _private_reads if key[0] == directory_key and key[1] == name_key]:
            del _private_reads[key]


def _windows_read_private_file(
    directory: Path,
    name: str,
    *,
    maximum_bytes: int,
    private_root: Path | None = None,
) -> bytes | None:
    """One owner-private file of at most `maximum_bytes`, or ``None`` when missing.

    With `private_root` the directories below it are created or repaired
    first, as a writer's are; without one the directory is only held.
    """

    if not _remembers_private_reads():
        return _runtime_read_private_file(directory, name, maximum_bytes=maximum_bytes, private_root=private_root)
    key = _read_key(directory, name, private_root, maximum_bytes)
    hit, remembered = _remembered_read(key, directory, name)
    if hit:
        return remembered
    before = _private_identity(directory, name)
    verified_at = _clock()
    content = _runtime_read_private_file(directory, name, maximum_bytes=maximum_bytes, private_root=private_root)
    # Only a file that held one identity across the whole runtime read is
    # remembered, and only when the runtime saw the same presence.
    if before is not None and (before[1] is None) == (content is None) and _private_identity(directory, name) == before:
        _remember_read(key, before, content, verified_at)
    return content


def _runtime_read_private_file(
    directory: Path,
    name: str,
    *,
    maximum_bytes: int,
    private_root: Path | None,
) -> bytes | None:
    encoded = _private_state(
        "read",
        "content_b64",
        directory=directory,
        name=name,
        private_root=private_root,
        output_limit=(maximum_bytes + 2) // 3 * 4 + _PRIVATE_STATE_ANSWER_OVERHEAD,
        maximum_bytes=maximum_bytes,
    )
    if encoded is None:
        return None
    if not isinstance(encoded, str):
        raise NativePolicySnapshotError("native_windows_private_state_invalid")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise NativePolicySnapshotError("native_windows_private_state_invalid") from error
    if not content or len(content) > maximum_bytes:
        raise NativePolicySnapshotError("native_windows_private_state_invalid")
    return content


def _windows_read_snapshot_bytes(
    path: Path,
    *,
    maximum_bytes: int = POLICY_SNAPSHOT_MAX_BYTES,
) -> bytes | None:
    """Read one owner-private state file while its directory is held."""

    return _windows_read_private_file(path.parent, path.name, maximum_bytes=maximum_bytes)


def _windows_write_private_file_atomic(
    *,
    directory: Path,
    name: str,
    payload: bytes,
    maximum_bytes: int,
    private_root: Path | None = None,
) -> None:
    """Replace one owner-private file so readers see old or new content, never a partial one.

    The directories from `private_root` (`directory` itself by default) down
    are created or repaired first.
    """

    if not payload or len(payload) > maximum_bytes:
        raise NativePolicySnapshotError("native_policy_windows_write_too_large")
    _forget_private_file(directory, name)
    try:
        _private_state(
            "write",
            "written",
            directory=directory,
            name=name,
            private_root=private_root,
            maximum_bytes=maximum_bytes,
            content_b64=base64.b64encode(payload).decode("ascii"),
        )
    finally:
        _forget_private_file(directory, name)


def _windows_delete_private_child(
    *,
    directory: Path,
    name: str,
    private_root: Path | None = None,
) -> bool:
    """Delete one owner-private file through its verified handle; whether it existed.

    A file already missing from a plain directory needs no runtime: idle
    publishers clear an acknowledgment that is usually not there.
    """

    _forget_private_file(directory, name)
    if _remembers_private_reads():
        identity = _private_identity(directory, name)
        if identity is not None and identity[1] is None:
            return False
    try:
        return (
            _private_state(
                "delete",
                "deleted",
                directory=directory,
                name=name,
                private_root=private_root,
            )
            is True
        )
    finally:
        _forget_private_file(directory, name)


def _windows_ensure_private_directory(path: Path, *, private_root: Path | None = None) -> None:
    """Create `path` and its missing ancestors, and make it owner-private.

    The directories from `private_root` (`path` itself by default) down are
    created or have their ACLs repaired; missing ancestors are created private.
    """

    _private_state(
        "ensure",
        "ensured",
        directory=Path(os.path.abspath(path)),
        name=None,
        private_root=None if private_root is None else Path(os.path.abspath(private_root)),
        feature=_PRIVATE_DIRECTORY_FEATURE,
    )


__all__ = [
    "_windows_delete_private_child",
    "_windows_ensure_private_directory",
    "_windows_read_private_file",
    "_windows_read_snapshot_bytes",
    "_windows_write_private_file_atomic",
]
