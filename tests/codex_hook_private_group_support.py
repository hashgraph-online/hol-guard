"""What the runtime decides about a file's group, read from this host.

The native ``codex_hook_file_integrity`` kind reads the real account and
group databases, so tests that depend on group privacy follow the account
running them. This mirrors ``codex_hook_private_group`` in the runtime.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _passwd_accounts() -> list[tuple[str, int]] | None:
    try:
        text = Path("/etc/passwd").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    accounts: list[tuple[str, int]] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith(("+", "-")):
            return None
        fields = line.split(":")
        if len(fields) < 4 or not fields[3].isdigit():
            return None
        accounts.append((fields[0], int(fields[3])))
    return accounts


def group_is_private_to_owner(path: Path) -> bool:
    """Whether the runtime treats ``path``'s group as private to its owner."""

    import grp
    import pwd

    facts = path.stat()
    try:
        user = pwd.getpwuid(facts.st_uid)
        group = grp.getgrgid(facts.st_gid)
    except KeyError:
        return False
    primary = user.pw_gid == group.gr_gid
    listed = user.pw_name in group.gr_mem
    if not primary and not listed:
        return False
    if any(member != user.pw_name for member in group.gr_mem):
        return False
    accounts = _passwd_accounts() if sys.platform.startswith("linux") else None
    if accounts:
        if any(gid == group.gr_gid and name != user.pw_name for name, gid in accounts):
            return False
        return listed or (user.pw_name, group.gr_gid) in accounts
    return not group.gr_mem and group.gr_name == user.pw_name and primary
