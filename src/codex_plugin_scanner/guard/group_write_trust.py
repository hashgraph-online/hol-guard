"""Group write that gives no account more than it already has.

With a 0002 umask, pip installs Guard's package files at 0664, its folders at
0775 and the bundled native runtime at 0775. The Python code that runs these
trust checks ships in the same package. Under that umask the code and its
folder have the same owner, the same group and group write. Any account that
could use the group bit to change the runtime, its manifest or the source
compiler could already rewrite the checker itself, so rejecting the bit on
those files protects nothing.

The group write bit is therefore accepted only on a file the current user owns
whose group matches the group of this module and its folder, and only while
both are owned by the current user and group-writable. The group must also be
able to reach the module from every folder it shares with the file, so a file
it can reach is never trusted while a folder it cannot enter guards the
module. Only file metadata is read; no account or group database is
consulted. A root or system install, a
0022 umask, a different group, or a module loaded without a source file falls
back to rejecting group write as before. World write is always rejected.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def _group_can_search(metadata: os.stat_result, group_gid: int, current_uid: int) -> bool:
    """Whether every member of ``group_gid`` can enter this folder.

    A member in the folder's group gets its group bits and anyone else its
    other bits, so a folder in another group needs both. Its owner can always
    restore search, so a folder owned by another account is not relied on.
    """

    mode = metadata.st_mode
    if metadata.st_uid != current_uid:
        return False
    if metadata.st_gid == group_gid:
        return bool(mode & stat.S_IXGRP)
    return bool(mode & stat.S_IXGRP and mode & stat.S_IXOTH)


def _checker_shares_group_write(target: Path, group_gid: int, current_uid: int) -> bool:
    """Whether this module and its folder are already writable through ``group_gid``.

    A folder above both the module and ``target`` stops the group from reaching
    either, so only the folders between that shared folder and the module must
    let the group in.
    """

    source = globals().get("__file__")
    if not isinstance(source, str) or not source:
        return False
    try:
        module = Path(source).resolve(strict=True)
        shared = Path(os.path.commonpath((module.parent, target.resolve(strict=True).parent)))
        expected = ((module, stat.S_ISREG), (module.parent, stat.S_ISDIR))
        for path, kind in expected:
            metadata = path.stat()
            if (
                not kind(metadata.st_mode)
                or metadata.st_uid != current_uid
                or metadata.st_gid != group_gid
                or not metadata.st_mode & stat.S_IWGRP
            ):
                return False
        for folder in (module.parent, *module.parent.parents):
            if folder == shared:
                break
            if not _group_can_search(folder.stat(), group_gid, current_uid):
                return False
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def writable_only_by_owner(metadata: os.stat_result, current_uid: int, path: Path) -> bool:
    """Whether the mode bits of the file at ``path`` give no account more than it already has.

    Owner checks stay with the caller. Group write is allowed only for a file
    the current user owns, through the group that can already write this module.
    """

    mode = stat.S_IMODE(metadata.st_mode)
    if mode & stat.S_IWOTH:
        return False
    if not mode & stat.S_IWGRP:
        return True
    return metadata.st_uid == current_uid and _checker_shares_group_write(path, metadata.st_gid, current_uid)


def trusted_owner_and_mode(metadata: os.stat_result, path: Path) -> bool:
    """Owned by root or the current user, and writable by no other account."""

    if not hasattr(os, "getuid"):
        return not stat.S_IMODE(metadata.st_mode) & 0o022
    current_uid = os.getuid()
    return metadata.st_uid in {0, current_uid} and writable_only_by_owner(metadata, current_uid, path)


__all__ = ["trusted_owner_and_mode", "writable_only_by_owner"]
