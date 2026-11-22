"""Keep `hol-guard update` on one release while the installer replaces it.

The installer rewrites this package's files while the update command is still
running. A module first imported after that comes from the new release, and it
can ask a module this process already holds for a name the older copy never
had. Release 3.59.0 failed that way: the update installed, then printing the
result raised ImportError and the command exited 1.

What runs after the install reaches most of the package through function-level
imports, so a hand-kept list would drift. Importing the whole package first
takes about a second and keeps the rest of the run on the release that started
it. If an import still fails while the result is printed, the result is written
with the standard library alone, so a finished update is never reported as a
failure.
"""

from __future__ import annotations

import importlib
import json
import pkgutil
import sys
from collections.abc import Callable
from types import ModuleType
from typing import TextIO

_PACKAGE = "codex_plugin_scanner"


def load_package_before_install(package: str = _PACKAGE) -> int:
    """Import every module of `package` that imports here; return how many failed.

    A module that cannot import on this machine (an optional dependency, a
    platform-only API) is skipped: the update never needs it.
    """
    try:
        root: ModuleType = importlib.import_module(package)
    except Exception:
        return 1
    failed = 0

    def skip(_name: str) -> None:
        nonlocal failed
        failed += 1

    for module in pkgutil.walk_packages(root.__path__, f"{package}.", onerror=skip):
        try:
            importlib.import_module(module.name)
        except Exception:
            failed += 1
    return failed


def emit_update_result(
    emit: Callable[[str, dict[str, object], bool], None],
    payload: dict[str, object],
    as_json: bool,
    *,
    stream: TextIO | None = None,
) -> None:
    """Print the update result, without the renderer if a stale import breaks it."""
    try:
        emit("update", payload, as_json)
    except ImportError:
        out = stream if stream is not None else sys.stdout
        if as_json:
            out.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
            return
        message = payload.get("message")
        out.write(f"{message if isinstance(message, str) else 'Update finished.'}\n")
        out.write("Run `hol-guard status` to see the updated install.\n")
