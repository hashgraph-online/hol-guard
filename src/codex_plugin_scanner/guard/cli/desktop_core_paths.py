"""Executable layouts owned by HOL Guard Desktop."""

import plistlib
from pathlib import Path

from packaging.version import InvalidVersion, Version

_DESKTOP_BUNDLE_ID = "org.hol.guard.desktop"
_DESKTOP_APP_NAME = "HOL Guard.app"


def desktop_app_bundles() -> tuple[Path, ...]:
    return (Path("/Applications") / _DESKTOP_APP_NAME, Path.home() / "Applications" / _DESKTOP_APP_NAME)


def installed_desktop_app_version() -> Version | None:
    """Version of the installed macOS Desktop app, or None when there is none.

    With more than one copy installed, the oldest decides: any of them may be
    the one that launches the Core next.
    """
    versions: list[Version] = []
    for bundle in desktop_app_bundles():
        try:
            with (bundle / "Contents" / "Info.plist").open("rb") as handle:
                info = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException, ValueError):
            continue
        if not isinstance(info, dict) or info.get("CFBundleIdentifier") != _DESKTOP_BUNDLE_ID:
            continue
        raw = info.get("CFBundleShortVersionString")
        if not isinstance(raw, str):
            continue
        try:
            versions.append(Version(raw))
        except InvalidVersion:
            continue
    return min(versions) if versions else None


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
