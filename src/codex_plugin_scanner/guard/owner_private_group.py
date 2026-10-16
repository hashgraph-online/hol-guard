"""Group write that only the file's owner can use.

Debian, Ubuntu and Fedora give each user a private primary group and a 0002
umask, so pip installs package files at 0664 and executables at 0775. The
group write bit then grants nothing: the owner is the group's only member.
This is the rule Debian's OpenSSH applies to ``StrictModes``.

The bit is accepted only when the file belongs to the current user and the
account database proves the group is that user's private group. Any lookup
failure, an empty or partial account listing, or any second member rejects,
as does world write.
"""

from __future__ import annotations

import os
import stat


def group_is_private_to_owner(owner_uid: int, group_gid: int) -> bool:
    """Whether ``group_gid`` is ``owner_uid``'s primary group and no one else's."""

    try:
        import grp
        import pwd

        owner = pwd.getpwuid(owner_uid)
        group = grp.getgrgid(group_gid)
        if owner.pw_gid != group_gid or not set(group.gr_mem) <= {owner.pw_name}:
            return False
        accounts = pwd.getpwall()
    except (ImportError, KeyError, OSError):
        return False
    # The listing must include the owner, or it cannot speak for the source
    # that holds the owner's account and may be missing other primary members.
    listed_owner = any(entry.pw_uid == owner_uid and entry.pw_name == owner.pw_name for entry in accounts)
    shared = any(entry.pw_gid == group_gid and entry.pw_uid != owner_uid for entry in accounts)
    return listed_owner and not shared


def writable_only_by_owner(metadata: os.stat_result, current_uid: int) -> bool:
    """Whether no account other than the owner can write through the mode bits.

    Owner checks stay with the caller. Group write is allowed only for a file
    the current user owns whose group is that user's private group.
    """

    mode = stat.S_IMODE(metadata.st_mode)
    if mode & stat.S_IWOTH:
        return False
    if not mode & stat.S_IWGRP:
        return True
    return metadata.st_uid == current_uid and group_is_private_to_owner(current_uid, metadata.st_gid)


def trusted_owner_and_mode(metadata: os.stat_result) -> bool:
    """Owned by root or the current user, and writable by no other account."""

    if not hasattr(os, "getuid"):
        return not stat.S_IMODE(metadata.st_mode) & 0o022
    current_uid = os.getuid()
    return metadata.st_uid in {0, current_uid} and writable_only_by_owner(metadata, current_uid)


__all__ = ["group_is_private_to_owner", "trusted_owner_and_mode", "writable_only_by_owner"]
