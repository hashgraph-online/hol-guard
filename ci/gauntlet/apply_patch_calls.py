"""What a Codex ``apply_patch`` call writes, read from its patch headers.

Codex makes every file change through ``apply_patch``, with the whole patch as the
call's ``command``. A write case pins one file and one kind of change, so a patch
that adds exactly one file is a ``write`` and one that updates exactly one file in
place is an ``edit``. Any other patch (several files, a move, a delete) names no
single target the case could bind, and neither does an unfinished one: without its
``*** Begin Patch`` and ``*** End Patch`` lines, or with an added file's body line
not starting with ``+``, ``apply_patch`` would refuse it and write nothing.
"""

from __future__ import annotations

_ADD = "*** Add File: "
_UPDATE = "*** Update File: "
_OTHER = ("*** Delete File: ", "*** Move to: ")
_BEGIN = "*** Begin Patch"
_END = "*** End Patch"


def patch_target(patch: object) -> tuple[str, str] | None:
    """The catalog tool name and the file path for a single-file patch, else None."""
    if not isinstance(patch, str):
        return None
    lines = [line.strip() for line in patch.strip().splitlines()]
    if len(lines) < 3 or lines[0] != _BEGIN or lines[-1] != _END:
        return None
    targets: list[tuple[str, str]] = []
    adding = False
    for line in lines[1:-1]:
        if line.startswith(_OTHER) or line in (_BEGIN, _END):
            return None
        header = next(((h, t) for h, t in ((_ADD, "write"), (_UPDATE, "edit")) if line.startswith(h)), None)
        if header is not None:
            path = line[len(header[0]) :].strip()
            if not path:
                return None
            targets.append((header[1], path))
            adding = header[1] == "write"
        elif adding and not line.startswith("+"):
            return None
    return targets[0] if len(targets) == 1 else None
