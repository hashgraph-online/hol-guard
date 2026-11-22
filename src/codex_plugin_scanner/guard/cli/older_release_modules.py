"""Let a CLI from an older release print through this release's renderer.

`hol-guard update` replaces this package's files while the update command is
still running. Releases before 3.60.0 import `render` only when they print the
result, so they load this release's `render` while still holding their own
copies of the modules it imports. Asking those copies for a name they never
had raised ImportError, and a finished update exited 1.

`render` imports this module before anything else. When the version the
process loaded differs from the version on disk, the older release's plain
modules are dropped from `sys.modules`, so the imports that follow load this
release's files. Packages, compiled extensions, `render` and this module stay.
A process running the release on disk drops nothing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_PACKAGE = __name__.split(".", 1)[0]
_RENDER = f"{__name__.rsplit('.', 1)[0]}.render"
_VERSION_PATTERN = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.MULTILINE)


def _version_on_disk() -> str | None:
    package_file = getattr(sys.modules.get(_PACKAGE), "__file__", None)
    if not isinstance(package_file, str):
        return None
    try:
        text = (Path(package_file).parent / "version.py").read_text(encoding="utf-8")
    except OSError:
        return None
    match = _VERSION_PATTERN.search(text)
    return match.group(1) if match else None


def drop_older_release_modules() -> tuple[str, ...]:
    """Drop the older release's plain modules; return the names dropped."""
    loaded = getattr(sys.modules.get(f"{_PACKAGE}.version"), "__version__", None)
    on_disk = _version_on_disk()
    if not isinstance(loaded, str) or on_disk is None or loaded == on_disk:
        return ()
    dropped = []
    for name, module in list(sys.modules.items()):
        if not name.startswith(f"{_PACKAGE}.") or name in {__name__, _RENDER}:
            continue
        if hasattr(module, "__path__"):
            continue
        if not str(getattr(module, "__file__", "")).endswith(".py"):
            continue
        del sys.modules[name]
        dropped.append(name)
    return tuple(dropped)


DROPPED = drop_older_release_modules()
