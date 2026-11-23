"""The environment every native runtime child starts with.

The child never inherits the caller's environment: it receives only the
variables named here, plus, on Windows, a PATH limited to trusted directories
for the Visual C++ CRT search.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

_ALLOWED = frozenset(
    {
        "COMSPEC",
        "HOME",
        # The desktop-notice opt-out the resident drain honours.
        "HOL_GUARD_DESKTOP_NOTIFICATIONS",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        # Dedicated opt-in for the resident's supply-chain test seams; kept
        # separate from diagnostics so diagnostics alone never enable them.
        "HOL_GUARD_RESIDENT_TEST_SEAMS",
        "LANG",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)
_CRT_NAMES = ("vcruntime140.dll", "vcruntime140_1.dll")


def windows_native_dll_directories(runtime_dir: Path) -> list[str]:
    """Trusted directories for the Windows native runtime's CRT search.

    The published runtime links the Visual C++ CRT dynamically. Windows finds
    those DLLs in System32 when the redistributable is installed machine-wide.
    An x64 wheel on ARM, or a per-user Python install, often has the CRT only
    beside the base interpreter. The isolated environment cannot inherit the
    user PATH, so the loader otherwise fails with STATUS_DLL_NOT_FOUND.
    """

    roots: list[str] = []
    system_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR")
    if system_root:
        roots.append(os.path.join(system_root, "System32"))
    base_prefix = getattr(sys, "base_prefix", "")
    if (
        isinstance(base_prefix, str)
        and base_prefix
        and any(os.path.isfile(os.path.join(base_prefix, name)) for name in _CRT_NAMES)
    ):
        roots.append(base_prefix)
    if runtime_dir.is_dir():
        roots.append(str(runtime_dir))
    unique: list[str] = []
    seen: set[str] = set()
    for root in roots:
        key = root.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def isolated_environment(dll_directories: Callable[[], list[str]]) -> dict[str, str]:
    """The allowed variables, and on Windows the trusted CRT search PATH.

    ``dll_directories`` is called only on Windows, so the runtime's location is
    looked up only where the CRT search needs it.
    """

    environment: dict[str, str] = {}
    for key in os.environ:
        upper = key.upper()
        if upper in _ALLOWED or upper.startswith("LC_"):
            environment[key] = os.environ[key]
    if os.name == "nt":
        dll_path = os.pathsep.join(dll_directories())
        if dll_path:
            environment["PATH"] = dll_path
    return environment
