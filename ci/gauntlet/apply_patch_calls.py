"""What a Codex ``apply_patch`` call writes, read from its patch headers.

Codex makes every file change through ``apply_patch``, with the whole patch as the
call's ``command``. A write case pins one file and one kind of change, so a patch
that adds exactly one file is a ``write`` and one that updates exactly one file in
place is an ``edit``. Any other patch (several files, a move, a delete) names no
single target the case could bind.
"""

from __future__ import annotations

_ADD = "*** Add File: "
_UPDATE = "*** Update File: "
_OTHER = ("*** Delete File: ", "*** Move to: ")


def patch_target(patch: object) -> tuple[str, str] | None:
    """The catalog tool name and the file path for a single-file patch, else None."""
    if not isinstance(patch, str):
        return None
    targets: list[tuple[str, str]] = []
    for line in patch.splitlines():
        line = line.strip()
        if line.startswith(_OTHER):
            return None
        for header, tool in ((_ADD, "write"), (_UPDATE, "edit")):
            if line.startswith(header) and (path := line[len(header) :].strip()):
                targets.append((tool, path))
    return targets[0] if len(targets) == 1 else None
