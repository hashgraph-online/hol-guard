"""System-wide scan for PyInstaller extraction dirs that a live process still uses.

Unmarked ``_MEI*`` dirs have no recorded owner pid, so the only proof that one
is dead is that no process has any file in it open, mapped, or as its working
directory. The native runtime's ``onefile-open-paths`` command runs that scan
in one pass over the whole machine. It is fail-closed: any error, timeout,
missing tool or missing runtime returns ``None`` and callers must then skip all
unmarked reclamation.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

_FEATURE = "native-onefile-open-paths-v1"
_COMMAND = "onefile-open-paths"
_SCHEMA = "onefile-open-paths.v1"
# The runtime waits up to 90 seconds for lsof before it gives up.
_TIMEOUT_SECONDS = 120.0
_OUTPUT_LIMIT = 1024 * 1024

OpenPathScanner = Callable[[Path], "frozenset[str] | None"]


def scan_open_extraction_dirs(temp_root: Path) -> frozenset[str] | None:
    """Names of ``_MEI*`` dirs under ``temp_root`` that some process uses.

    ``None`` means unknown, not "none in use".
    """

    from .mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _FEATURE,
        _COMMAND,
        {"schema": _SCHEMA, "temp_root": str(temp_root)},
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )
    in_use = answer.get("in_use") if answer is not None else None
    if not isinstance(in_use, list) or not all(isinstance(name, str) for name in in_use):
        return None
    return frozenset(name for name in in_use if isinstance(name, str))
