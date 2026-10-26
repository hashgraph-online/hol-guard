"""Executable layouts owned by HOL Guard Desktop."""

from pathlib import Path


def executable_is_desktop_core(executable: Path) -> bool:
    try:
        resolved = executable.expanduser().resolve()
    except (OSError, RuntimeError):
        return False
    parts = tuple(part.lower() for part in resolved.parts)
    if any(
        parts[index : index + 3] == ("org.hol.guard.desktop", "core", "versions") for index in range(len(parts) - 2)
    ):
        return True
    if "hol guard.app" in parts:
        return True
    for index, part in enumerate(parts):
        if part != "bundled" or index < 2 or parts[index - 1] != "core":
            continue
        if parts[index - 2] not in {"org.hol.guard.desktop", "hol-desktop"}:
            continue
        tail = parts[index + 1 :]
        if tail and tail[-1] in {"hol-guard", "hol-guard.exe"}:
            if len(tail) == 3 and tail[1] == "bin":
                return True
            if len(tail) == 4 and tail[1:3] == ("lib", "hol-guard-core"):
                return True
    return any((resolved.parent / sibling).is_file() for sibling in ("hol-guard-desktop", "hol-guard-desktop.exe"))
