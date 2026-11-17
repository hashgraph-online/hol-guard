"""Codex detection inputs read once and mapped back to the caller's path form.

The native detector inventories exactly the bytes it selects the
legacy-ownership bindings from, and spells paths back the way the context did.
"""

from __future__ import annotations

from pathlib import Path

from ..native_path_anchor import anchor_to_process_directory


def read_source_bytes(path: Path) -> bytes | None:
    """File bytes, ``None`` when it is not a file, empty when it cannot be read.

    An unreadable file still counts as found and holds no hooks or servers,
    which is what an empty file means to the detector.
    """

    if not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return b""


def path_restorations(paths: tuple[Path, ...]) -> dict[str, str]:
    """Anchored (absolute) spelling to the spelling the context used."""

    restore: dict[str, str] = {}
    for path in paths:
        anchored = anchor_to_process_directory(path)
        if anchored != str(path):
            restore[anchored] = str(path)
    return restore
