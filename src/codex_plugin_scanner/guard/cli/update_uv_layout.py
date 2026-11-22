"""Recognize a uv tool environment that lives outside uv's default tool directory.

uv writes ``uv-receipt.toml`` into every tool environment, wherever ``UV_TOOL_DIR`` puts it.
The updater still needs the directory holding the ``hol-guard`` launcher, and it accepts one
only when that launcher is a link back into this environment. That directory is named by the
environment, so it only receives the new launcher: ``uv`` itself is looked up in the account's
own ``~/.local/bin`` and the fixed system directories, never there.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

_RECEIPT_NAME = "uv-receipt.toml"
_PACKAGE_DIRECTORY_NAMES = ("hol-guard", "hol_guard")


def is_uv_tool_environment(prefix: Path) -> bool:
    """True when ``prefix`` is a virtual environment uv created with ``uv tool install``."""

    try:
        return (prefix / _RECEIPT_NAME).is_file() and (prefix / "pyvenv.cfg").is_file()
    except OSError:
        return False


def custom_uv_tool_layout(prefix: Path) -> tuple[Path, Path] | None:
    """Return ``(tool_dir, bin_dir)`` for a HOL Guard uv tool environment in a custom directory.

    Windows launchers are copies rather than links, so they cannot be tied back to this
    environment, and only the default layout is supported there.
    """

    if os.name == "nt" or prefix.name not in _PACKAGE_DIRECTORY_NAMES or not is_uv_tool_environment(prefix):
        return None
    try:
        expected = (prefix / "bin" / "hol-guard").resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    for bin_dir in _bin_dir_candidates():
        launcher = bin_dir / "hol-guard"
        try:
            if launcher.is_symlink() and launcher.resolve(strict=True) == expected:
                return prefix.parent, bin_dir
        except (OSError, RuntimeError):
            continue
    return None


def uv_tool_environment_overrides(prefix: Path) -> dict[str, str]:
    """``UV_TOOL_DIR`` (and ``UV_TOOL_BIN_DIR`` when proven) that make uv act on ``prefix`` itself.

    Without them ``uv tool`` falls back to its default directory and can act on a different
    HOL Guard installation than the one running.
    """

    if prefix.name not in _PACKAGE_DIRECTORY_NAMES or not is_uv_tool_environment(prefix):
        return {}
    overrides = {"UV_TOOL_DIR": str(prefix.parent)}
    layout = custom_uv_tool_layout(prefix)
    if layout is not None:
        overrides["UV_TOOL_BIN_DIR"] = str(layout[1])
    return overrides


def _bin_dir_candidates() -> list[Path]:
    """Where ``uv tool install`` puts launchers, in uv's order of preference."""

    candidates: list[Path] = []
    for name in ("UV_TOOL_BIN_DIR", "XDG_BIN_HOME"):
        value = os.environ.get(name, "").strip()
        if value and Path(value).is_absolute():
            candidates.append(Path(value))
    data_home = os.environ.get("XDG_DATA_HOME", "").strip()
    if data_home and Path(data_home).is_absolute():
        candidates.append(Path(data_home).parent / "bin")
    with contextlib.suppress(KeyError, OSError, RuntimeError):
        candidates.append(Path.home() / ".local" / "bin")
    return candidates


def uv_user_bin_dir() -> Path | None:
    """``~/.local/bin`` of the account running the updater, read from the password database.

    An account without a password entry, common in containers run under an arbitrary UID,
    has no such directory to offer, and only the fixed system directories are searched.
    """

    try:
        import pwd

        return Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local" / "bin"
    except (ImportError, KeyError, OSError):
        return None
