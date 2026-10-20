"""Tell a CLI that Desktop has replaced from the Core Desktop now runs.

Desktop keeps every Core release under ``versions/<release>/`` and moves
``current.json`` to the newest one, and the resident follows that pointer. A
``hol-guard`` that still runs from an older release publishes policy to a resident
it cannot reach, so a contained run only learns that after waiting out every
acknowledgement window. The pointer already says so, which lets that run stop
at once with a message that names the fix.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from .stable_guard_cli import desktop_core_root_for_executable, versioned_launcher_release

_POINTER = "current.json"
_MAX_POINTER_BYTES = 64 * 1024
OUT_OF_SYNC_REASON = "guard_versions_out_of_sync"


@dataclass(frozen=True, slots=True)
class SupersededCore:
    """A Core release that Desktop has replaced with a newer one."""

    running: str
    current: str

    def message(self) -> str:
        return (
            f"Guard versions out of sync: this hol-guard is Core {self.running}, but Desktop now runs Core "
            f"{self.current}. Run `hol-guard repair`, then retry."
        )


def _selected_release(core_root: Path) -> str | None:
    """The release whose Core launcher ``current.json`` selects, or None when it cannot be judged.

    Only ``versions/<release>/hol-guard`` and ``versions/<release>/bundle/hol-guard``
    (or the Windows ``.exe``) name a launcher. Any other shape, such as a file
    inside the release tree, selects nothing and never blocks a run. The launcher
    itself may be absent locally: the pointer is what the resident follows.
    """

    pointer = core_root / _POINTER
    try:
        if pointer.is_symlink() or not pointer.is_file() or pointer.stat().st_size > _MAX_POINTER_BYTES:
            return None
        document = cast(object, json.loads(pointer.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, ValueError):
        return None
    relative = cast(dict[str, object], document).get("relativePath") if isinstance(document, dict) else None
    if not isinstance(relative, str) or not relative or "\\" in relative:
        return None
    path = PurePosixPath(relative)
    parts = path.parts
    if path.is_absolute() or len(parts) < 2 or parts[0] != "versions":
        return None
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return versioned_launcher_release(parts[1:])


def superseded_desktop_core(executable: Path | None = None) -> SupersededCore | None:
    """Report whether `executable` is a Core release that Desktop no longer selects.

    Only a launcher below ``versions/<release>/`` can be superseded, so a pip,
    pipx or source install, a bundled Core and an unreadable pointer all answer
    None and keep their current behavior. Without an argument this looks at the
    frozen executable of the running process.
    """

    if executable is None:
        if not getattr(sys, "frozen", False):
            return None
        executable = Path(sys.executable)
    located = desktop_core_root_for_executable(executable)
    if located is None:
        return None
    core_root, running = located
    selected = _selected_release(core_root)
    if selected is None or selected == running:
        return None
    return SupersededCore(running=running, current=selected)


__all__ = ["OUT_OF_SYNC_REASON", "SupersededCore", "superseded_desktop_core"]
