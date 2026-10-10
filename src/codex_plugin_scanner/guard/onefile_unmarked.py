"""Identify unmarked PyInstaller extraction dirs as Guard bundles.

Older Guard launches (and any launch killed before it stamped its owner marker)
leave ``_MEI*`` dirs without ownership records. Reclaiming them requires proof
that the dir is a Guard extraction (this module) and that no live process uses
it (``onefile_open_paths``).

Signatures, checked in order, all relative to the extraction dir:

``bundle``
    The Guard dashboard ``index.html`` data file exists. It is extracted late,
    so its presence means extraction finished.
``partial``
    No sentinel, but the extraction was clearly Guard's and was cut short:
    a real top-level ``codex_plugin_scanner/`` directory exists, or a top-level
    mypyc runtime module (``<hash>__mypyc*.so`` / ``.pyd``) sits next to a
    bundled ``Python.framework`` / ``libpython*`` runtime.

Anything else (empty dirs, other PyInstaller apps, dirs killed before any
Guard file landed) is not identified and is never reclaimed.

Stdlib-only.
"""

from __future__ import annotations

import os
import stat
from datetime import timedelta
from pathlib import Path

LEGACY_BUNDLE_SENTINEL = ("codex_plugin_scanner", "guard", "daemon", "static", "index.html")
PACKAGE_DIR_NAME = "codex_plugin_scanner"

# Unmarked dirs have no pid to check, so keep a conservative floor well above a
# slow cold-start extraction.
UNMARKED_MIN_AGE = timedelta(hours=2)

BUNDLE = "bundle"
PARTIAL = "partial"


def _is_real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def classify_unmarked_extraction(extraction_dir: Path) -> str | None:
    """Return ``"bundle"``, ``"partial"``, or ``None`` when not provably Guard."""

    if extraction_dir.joinpath(*LEGACY_BUNDLE_SENTINEL).is_file():
        return BUNDLE
    if _is_real_dir(extraction_dir / PACKAGE_DIR_NAME):
        return PARTIAL
    try:
        names = os.listdir(extraction_dir)
    except OSError:
        return None
    has_mypyc = any("__mypyc" in name and name.endswith((".so", ".pyd")) for name in names)
    has_runtime = any(name == "Python.framework" or name.startswith("libpython") for name in names)
    if has_mypyc and has_runtime:
        return PARTIAL
    return None
