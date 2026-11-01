"""Find and remove HOL Guard installs that a Desktop-managed Core supersedes.

Desktop owns one Core under its app data directory. A pipx or uv tool venv, a
``pip --user`` install, or a stale link left in a bin directory keeps an older
``hol-guard`` on PATH, and a later package update from it can take the hooks
back. Desktop retires those copies so every hook and shell resolves one Core.
The native runtime's ``desktop-foreign-inventory`` command finds them and
``desktop-foreign-remove`` removes them once this module has stopped their
residents.
"""

from __future__ import annotations

import os
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
# Each removal step that can block: the venv and link deletions, then per
# ``pip --user`` interpreter its 30-second probe and 120-second uninstall.
_REMOVAL_BASE_TIMEOUT_SECONDS = 30.0
_REMOVAL_USER_SITE_TIMEOUT_SECONDS = 150.0
# The variables a ``pip --user`` interpreter needs to find its user site.
_REMOVAL_ENVIRONMENT_NAMES = (
    "APPDATA",
    "COMSPEC",
    "HOME",
    "LANG",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "PYTHONUSERBASE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "WINDIR",
)


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
_NOTHING_REMOVED = RemovalResult(
    removed=(),
    removed_entry_dirs=frozenset(),
    notes=("Kept every superseded install: Guard's native runtime is unavailable.",),
)


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
) -> RemovalResult:
    """Remove each inventoried install, keeping any whose resident will not stop.

    ``desktop_foreign_remove.rs`` deletes the venvs and links and uninstalls
    each confirmed ``pip --user`` copy. Without a native runtime nothing is
    removed.
    """

    from .mdm.runtime_request import runtime_answer

    if inventory.empty:
        return RemovalResult(removed=(), removed_entry_dirs=frozenset(), notes=())
    answer = runtime_answer(
        "native-desktop-foreign-remove-v1",
        "desktop-foreign-remove",
        {
            "schema": "desktop-foreign-remove.v1",
            "venvs": [
                {
                    "kind": venv.kind,
                    "root": str(venv.root),
                    "entries": [str(entry) for entry in venv.entries],
                    "retired": all(_retire(retire_runtime, runtime) for runtime in venv.runtimes),
                }
                for venv in inventory.venvs
            ],
            "stale_entries": [str(entry) for entry in inventory.stale_entries],
            "user_site": [
                {"interpreter": str(interpreter), "entries": [str(entry) for entry in entries]}
                for interpreter, entries in inventory.user_site
            ],
            "running_module": str(_resolve(Path(__file__))),
            "environment": {
                name: value for name in _REMOVAL_ENVIRONMENT_NAMES if (value := os.environ.get(name)) is not None
            },
        },
        output_limit=_INVENTORY_OUTPUT_LIMIT,
        timeout_seconds=_REMOVAL_BASE_TIMEOUT_SECONDS + _REMOVAL_USER_SITE_TIMEOUT_SECONDS * len(inventory.user_site),
    )
    try:
        return _removal_from_answer(answer)
    except (KeyError, TypeError, ValueError):
        return _NOTHING_REMOVED


def _removal_from_answer(answer: dict[str, object] | None) -> RemovalResult:
    if answer is None:
        return _NOTHING_REMOVED
    removed = cast("list[dict[str, object]]", answer["removed"])
    notes = answer["notes"]
    if not isinstance(notes, list):
        raise TypeError(notes)
    return RemovalResult(
        removed=tuple({"kind": str(item["kind"]), "path": str(item["path"])} for item in removed),
        removed_entry_dirs=frozenset(_paths(answer["removed_entry_dirs"])),
        notes=tuple(str(note) for note in cast("list[object]", notes)),
    )


def _retire(retire_runtime: Callable[[Path], bool], runtime: Path) -> bool:
    try:
        return retire_runtime(runtime)
    except Exception:
        return False


def _protected_roots() -> tuple[Path, ...]:
    """The running interpreter's tree is never removed from under itself."""

    return tuple(dict.fromkeys([_resolve(Path(sys.executable)), _resolve(Path(sys.prefix))]))


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


__all__ = [
    "DESKTOP_PATH_SHIM_MARKER",
    "ForeignInventory",
    "RemovalResult",
    "ToolVenv",
    "inventory_foreign_installs",
    "remove_foreign_installs",
]
