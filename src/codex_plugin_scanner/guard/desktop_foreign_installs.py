"""Find and remove HOL Guard installs that a Desktop-managed Core supersedes.

Desktop owns one Core under its app data directory. A pipx or uv tool venv, a
``pip --user`` install, or a stale link left in a bin directory keeps an older
``hol-guard`` on PATH, and a later package update from it can take the hooks
back. Desktop retires those copies so every hook and shell resolves one Core.
The native runtime's ``desktop-foreign-inventory`` command finds them; this
module removes them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

DESKTOP_PATH_SHIM_MARKER = "HOL_GUARD_DESKTOP_USER_PATH_SHIM"
_INVENTORY_TIMEOUT_SECONDS = 30.0
_INVENTORY_OUTPUT_LIMIT = 4 * 1024 * 1024
# The variables the inventory reads; the runtime runs with an isolated environment.
_ENVIRONMENT_NAMES = (
    "APPDATA",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "LOGNAME",
    "PIPX_BIN_DIR",
    "PIPX_HOME",
    "USER",
    "USERNAME",
    "USERPROFILE",
    "UV_TOOL_BIN_DIR",
    "UV_TOOL_DIR",
    "XDG_BIN_HOME",
    "XDG_DATA_HOME",
)
_PIP_UNINSTALL_TIMEOUT_SECONDS = 120.0
_USER_SITE_PROBE_TIMEOUT_SECONDS = 30.0
_NOT_INSTALLED_EXIT = 3
# Prints the user site-packages that holds hol-guard. Exits 3 when the
# interpreter has no hol-guard and 4 when the copy it imports lives elsewhere,
# so pip is never pointed at a system or distro install.
_USER_SITE_PROBE = """
import importlib.metadata as metadata, os, site, sys
try:
    location = os.path.realpath(str(metadata.distribution("hol-guard").locate_file("")))
except metadata.PackageNotFoundError:
    sys.exit(3)
user_site = os.path.realpath(site.getusersitepackages())
if location != user_site:
    sys.exit(4)
print(location)
"""


@dataclass(frozen=True)
class ToolVenv:
    """A pipx or uv tool venv that installed the hol-guard package."""

    kind: str
    root: Path
    entries: tuple[Path, ...]
    runtimes: tuple[Path, ...]


@dataclass(frozen=True)
class ForeignInventory:
    venvs: tuple[ToolVenv, ...]
    stale_entries: tuple[Path, ...]
    user_site: tuple[tuple[Path, tuple[Path, ...]], ...]
    """Each ``pip --user`` interpreter with the console scripts that run it."""

    @property
    def user_site_interpreters(self) -> tuple[Path, ...]:
        return tuple(interpreter for interpreter, _ in self.user_site)

    @property
    def empty(self) -> bool:
        return not (self.venvs or self.stale_entries or self.user_site)


@dataclass(frozen=True)
class RemovalResult:
    removed: tuple[dict[str, str], ...]
    removed_entry_dirs: frozenset[Path]
    notes: tuple[str, ...]


_NOTHING_FOUND = ForeignInventory(venvs=(), stale_entries=(), user_site=())


def inventory_foreign_installs(
    home: Path, *, path_env: str | None = None, protect_running: bool = True
) -> ForeignInventory:
    """Return every hol-guard tool venv and bin entry Desktop should retire.

    ``protect_running`` leaves out the install this process runs from; only a
    preview that removes nothing may turn it off. Without a native runtime
    nothing is reported, so nothing is removed.
    """

    from .mdm.runtime_request import runtime_answer

    try:
        cwd = os.getcwd()
    except OSError:
        return _NOTHING_FOUND
    protected = _protected_roots() if protect_running else ()
    answer = runtime_answer(
        "native-desktop-foreign-inventory-v1",
        "desktop-foreign-inventory",
        {
            "schema": "desktop-foreign-inventory.v1",
            "home": str(home),
            "cwd": cwd,
            "path": path_env if path_env is not None else os.environ.get("PATH", ""),
            "environment": {name: value for name in _ENVIRONMENT_NAMES if (value := os.environ.get(name)) is not None},
            "protected": [str(path) for path in protected],
        },
        output_limit=_INVENTORY_OUTPUT_LIMIT,
        timeout_seconds=_INVENTORY_TIMEOUT_SECONDS,
    )
    try:
        return _inventory_from_answer(answer)
    except (KeyError, TypeError, ValueError):
        return _NOTHING_FOUND


def _inventory_from_answer(answer: dict[str, object] | None) -> ForeignInventory:
    if answer is None:
        return _NOTHING_FOUND
    venvs = cast("list[dict[str, object]]", answer["venvs"])
    user_site = cast("list[dict[str, object]]", answer["user_site"])
    return ForeignInventory(
        venvs=tuple(
            ToolVenv(
                kind=str(venv["kind"]),
                root=Path(cast("str", venv["root"])),
                entries=_paths(venv["entries"]),
                runtimes=_paths(venv["runtimes"]),
            )
            for venv in venvs
        ),
        stale_entries=_paths(answer["stale_entries"]),
        user_site=tuple((Path(cast("str", item["interpreter"])), _paths(item["entries"])) for item in user_site),
    )


def _paths(value: object) -> tuple[Path, ...]:
    if not isinstance(value, list):
        raise TypeError(value)
    return tuple(Path(item) for item in cast("list[str]", value))


def remove_foreign_installs(
    inventory: ForeignInventory,
    *,
    retire_runtime: Callable[[Path], bool],
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> RemovalResult:
    """Remove each inventoried install, keeping any whose resident will not stop."""

    removed: list[dict[str, str]] = []
    entry_dirs: set[Path] = set()
    notes: list[str] = []
    for venv in inventory.venvs:
        if not all(_retire(retire_runtime, runtime) for runtime in venv.runtimes):
            notes.append(f"Kept {venv.root}: its Guard runtime is still running.")
            continue
        for entry in venv.entries:
            if _unlink(entry):
                entry_dirs.add(entry.parent)
        try:
            shutil.rmtree(venv.root)
        except OSError as error:
            notes.append(f"Could not remove {venv.root}: {error.strerror or error}.")
            continue
        removed.append({"kind": venv.kind, "path": str(venv.root)})
    for entry in inventory.stale_entries:
        if _unlink(entry):
            entry_dirs.add(entry.parent)
            removed.append({"kind": "stale_link", "path": str(entry)})
    for interpreter, entries in inventory.user_site:
        location = _user_site_location(interpreter, run)
        if location == _NOT_INSTALLED_EXIT:
            # The package is gone and only its console scripts remain.
            for entry in entries:
                if _unlink(entry):
                    entry_dirs.add(entry.parent)
                    removed.append({"kind": "stale_script", "path": str(entry)})
            continue
        if not isinstance(location, Path) or _is_relative_to(_resolve(Path(__file__)), location):
            notes.append(f"Kept hol-guard for {interpreter}: it is not a separate pip --user install.")
            continue
        command = [str(interpreter), "-m", "pip", "uninstall", "-y", "hol-guard"]
        try:
            completed = run(command, capture_output=True, text=True, timeout=_PIP_UNINSTALL_TIMEOUT_SECONDS)
        except (OSError, subprocess.SubprocessError) as error:
            notes.append(f"Could not uninstall hol-guard from {interpreter}: {error}.")
            continue
        if completed.returncode != 0:
            notes.append(f"Could not uninstall hol-guard from {interpreter}: pip exited {completed.returncode}.")
            continue
        removed.append({"kind": "pip_user", "path": str(interpreter)})
        entry_dirs.update(entry.parent for entry in entries if not entry.exists())
    return RemovalResult(removed=tuple(removed), removed_entry_dirs=frozenset(entry_dirs), notes=tuple(notes))


def _user_site_location(interpreter: Path, run: Callable[..., subprocess.CompletedProcess[str]]) -> Path | int | None:
    try:
        completed = run(
            [str(interpreter), "-c", _USER_SITE_PROBE],
            capture_output=True,
            text=True,
            timeout=_USER_SITE_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode == _NOT_INSTALLED_EXIT:
        return _NOT_INSTALLED_EXIT
    location = completed.stdout.strip() if completed.returncode == 0 else ""
    return Path(location) if location and Path(location).is_absolute() else None


def _retire(retire_runtime: Callable[[Path], bool], runtime: Path) -> bool:
    try:
        return retire_runtime(runtime)
    except Exception:
        return False


def _unlink(path: Path) -> bool:
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return True


def _protected_roots() -> tuple[Path, ...]:
    """The running interpreter's tree is never removed from under itself."""

    return tuple(dict.fromkeys([_resolve(Path(sys.executable)), _resolve(Path(sys.prefix))]))


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        _ = path.relative_to(root)
    except ValueError:
        return False
    return True


__all__ = [
    "DESKTOP_PATH_SHIM_MARKER",
    "ForeignInventory",
    "RemovalResult",
    "ToolVenv",
    "inventory_foreign_installs",
    "remove_foreign_installs",
]
