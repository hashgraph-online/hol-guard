"""Frozen Core package-shim launch helpers that avoid unreadable shebang paths.

Generating, attesting and classifying the shim files is the resident's job
(``shim_admin``); this module keeps only what the running shim needs: finding a
trusted generated shim when frozen Core is its shebang interpreter, and running it.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

from .stable_guard_cli import resolve_frozen_guard_cli, trusted_frozen_guard_cli_paths

FROZEN_PACKAGE_SHIM_SENTINEL = "HOL_GUARD_PACKAGE_SHIM_SENTINEL"


def package_shim_interpreter() -> str:
    """Return the Guard CLI used to exec package-manager shims.

    Unfrozen installs keep the current Python. Frozen Desktop runtimes use the
    prune-safe launcher so versioned Core paths can disappear safely.
    """

    if bool(getattr(sys, "frozen", False)):
        return resolve_frozen_guard_cli()
    return sys.executable


def _has_package_shim_layout(candidate: Path) -> bool:
    parent = candidate.parent
    grandparent = parent.parent
    return parent.name == "bin" and grandparent.name == "package-shims"


def resolve_frozen_package_shim_path(argv: list[str]) -> Path | None:
    """Return a trusted generated package shim when frozen Core is the shebang interpreter."""

    if not bool(getattr(sys, "frozen", False)) or not argv:
        return None
    from .shims import _PACKAGE_SHIM_COMMANDS

    trusted_commands = set(_PACKAGE_SHIM_COMMANDS.values())
    candidate = Path(argv[0]).expanduser()
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return None
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if resolved.parent.resolve() != candidate.parent.resolve():
        return None
    if resolved.name not in trusted_commands:
        if not (resolved.name.startswith(".") and resolved.name.endswith(".py")):
            return None
        command_name = resolved.name[1:-3]
        if command_name not in trusted_commands:
            return None
    if not _has_package_shim_layout(resolved):
        return None
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError:
        return None
    first_line = text.splitlines()[0] if text else ""
    shebang_interpreter = first_line[2:] if first_line.startswith("#!") else ""
    if shebang_interpreter not in trusted_frozen_guard_cli_paths():
        return None
    if f"{FROZEN_PACKAGE_SHIM_SENTINEL} = True" not in text:
        return None
    return resolved


def run_frozen_package_shim(shim_path: Path, shim_args: list[str]) -> int:
    """Execute a trusted generated package shim inside frozen Core."""

    original_argv = sys.argv
    try:
        sys.argv = [str(shim_path), *shim_args]
        runpy.run_path(str(shim_path), run_name="__main__")
    except SystemExit as error:
        code = error.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 1
    finally:
        sys.argv = original_argv
    return 0
