"""Find and remove HOL Guard installs that a Desktop-managed Core supersedes.

Desktop owns one Core under its app data directory. A pipx or uv tool venv, a
``pip --user`` install, or a stale link left in a bin directory keeps an older
``hol-guard`` on PATH, and a later package update from it can take the hooks
back. Desktop retires those copies so every hook and shell resolves one Core.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR_NAMES = frozenset({"hol-guard", "hol_guard"})
ENTRY_POINT_NAMES = (
    "hol-guard",
    "hol-guard-eval",
    "hol-guard-secrets",
    "plugin-scanner",
    "plugin-guard",
    "plugin-ecosystem-scanner",
)
DESKTOP_PATH_SHIM_MARKER = "HOL_GUARD_DESKTOP_USER_PATH_SHIM"
DESKTOP_DATA_DIR_NAME = "org.hol.guard.desktop"
_CONTENT_SCAN_LIMIT = 1024 * 1024
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


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    return Path(value).expanduser() if value else None


def _data_home(home: Path) -> Path:
    return _env_path("XDG_DATA_HOME") or home / ".local" / "share"


def pipx_venv_dirs(home: Path) -> tuple[Path, ...]:
    pipx_home = _env_path("PIPX_HOME")
    dirs = [pipx_home / "venvs"] if pipx_home else []
    dirs += [home / ".local" / "pipx" / "venvs", _data_home(home) / "pipx" / "venvs"]
    if sys.platform == "darwin":
        dirs.append(home / "Library" / "Application Support" / "pipx" / "venvs")
    if sys.platform == "win32":
        dirs.append(home / "pipx" / "venvs")
        local_appdata = _env_path("LOCALAPPDATA") or home / "AppData" / "Local"
        dirs.append(local_appdata / "pipx" / "pipx" / "venvs")
    return _unique(dirs)


def uv_tool_dirs(home: Path) -> tuple[Path, ...]:
    tool_dir = _env_path("UV_TOOL_DIR")
    dirs = [tool_dir] if tool_dir else []
    dirs.append(_data_home(home) / "uv" / "tools")
    if sys.platform == "win32":
        dirs.append((_env_path("APPDATA") or home / "AppData" / "Roaming") / "uv" / "tools")
    return _unique(dirs)


def bin_dirs(home: Path, path_env: str | None = None) -> tuple[Path, ...]:
    dirs = [path for name in ("PIPX_BIN_DIR", "UV_TOOL_BIN_DIR", "XDG_BIN_HOME") if (path := _env_path(name))]
    dirs.append(home / ".local" / "bin")
    resolved_home = _resolve(home)
    for entry in (path_env if path_env is not None else os.environ.get("PATH", "")).split(os.pathsep):
        if entry.strip() and _is_relative_to(_resolve(Path(entry).expanduser()), resolved_home):
            dirs.append(Path(entry).expanduser())
    return _unique(dirs)


def entry_file_names() -> tuple[str, ...]:
    if sys.platform != "win32":
        return ENTRY_POINT_NAMES
    return tuple(f"{name}{suffix}" for name in ENTRY_POINT_NAMES for suffix in ("", ".exe", ".cmd"))


def inventory_foreign_installs(
    home: Path, *, path_env: str | None = None, protect_running: bool = True
) -> ForeignInventory:
    """Return every hol-guard tool venv and bin entry Desktop should retire.

    ``protect_running`` leaves out the install this process runs from; only a
    preview that removes nothing may turn it off.
    """

    protected = _protected_roots() if protect_running else ()
    candidates: list[tuple[str, Path]] = []
    collections = [("pipx", root) for root in pipx_venv_dirs(home)] + [("uv", root) for root in uv_tool_dirs(home)]
    for kind, collection in collections:
        for name in sorted(PACKAGE_DIR_NAMES):
            venv = collection / name
            if venv.is_dir() and not venv.is_symlink() and not _contains_any(venv, protected):
                candidates.append((kind, venv))
    venv_entries: dict[Path, list[Path]] = {venv: [] for _, venv in candidates}
    stale: list[Path] = []
    user_site: dict[Path, list[Path]] = {}
    for entry in _bin_entries(home, path_env):
        if _desktop_owned_entry(entry):
            continue
        owner = next((venv for _, venv in candidates if _entry_belongs_to(entry, venv)), None)
        if owner is not None:
            venv_entries[owner].append(entry)
        elif _dangling_tool_link(entry, collections):
            stale.append(entry)
        elif (interpreter := _user_site_interpreter(entry)) is not None:
            user_site.setdefault(interpreter, []).append(entry)
    venvs = tuple(
        ToolVenv(kind=kind, root=venv, entries=tuple(venv_entries[venv]), runtimes=_venv_runtimes(venv))
        for kind, venv in candidates
    )
    return ForeignInventory(
        venvs=venvs,
        stale_entries=tuple(stale),
        user_site=tuple((interpreter, tuple(entries)) for interpreter, entries in user_site.items()),
    )


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


def _bin_entries(home: Path, path_env: str | None) -> Iterable[Path]:
    names = entry_file_names()
    for directory in bin_dirs(home, path_env):
        for name in names:
            entry = directory / name
            if entry.is_symlink() or entry.is_file():
                yield entry


def _protected_roots() -> tuple[Path, ...]:
    """The running interpreter's tree is never removed from under itself."""

    return tuple(_unique([_resolve(Path(sys.executable)), _resolve(Path(sys.prefix))]))


def _contains_any(root: Path, paths: Iterable[Path]) -> bool:
    resolved = _resolve(root)
    return any(path == resolved or _is_relative_to(path, resolved) for path in paths)


def _desktop_owned_entry(entry: Path) -> bool:
    if DESKTOP_DATA_DIR_NAME in _resolve(entry).parts:
        return True
    return DESKTOP_PATH_SHIM_MARKER.encode() in _head(entry)


def _entry_belongs_to(entry: Path, venv: Path) -> bool:
    if entry.is_symlink() and _is_relative_to(_link_target(entry), venv):
        return True
    if _is_relative_to(_resolve(entry), _resolve(venv)):
        return True
    content = _head(entry)
    # The trailing separator keeps a sibling venv such as ``hol-guard-dev`` out.
    needles = {f"{venv}{os.sep}", f"{_resolve(venv)}{os.sep}"}
    if sys.platform == "win32":
        lowered = content.lower()
        return any(needle.lower().encode() in lowered for needle in needles)
    return any(os.fsencode(needle) in content for needle in needles)


def _dangling_tool_link(entry: Path, collections: Iterable[tuple[str, Path]]) -> bool:
    if not entry.is_symlink() or entry.exists():
        return False
    target = _link_target(entry)
    for _, collection in collections:
        for name in PACKAGE_DIR_NAMES:
            if _is_relative_to(target, collection / name):
                return True
    return False


def _user_site_interpreter(entry: Path) -> Path | None:
    """Return the system interpreter behind a ``pip --user`` console script.

    Whether hol-guard really sits in that interpreter's user site is checked
    just before removal, so a script for a system install is left alone.
    """

    if sys.platform == "win32" or entry.is_symlink():
        return None
    content = _head(entry)
    if not content.startswith(b"#!") or b"codex_plugin_scanner" not in content:
        return None
    shebang = content[2:].split(b"\n", 1)[0].decode(errors="replace").strip().split()
    if len(shebang) != 1:
        return None
    interpreter = Path(shebang[0])
    if not interpreter.is_absolute() or not interpreter.is_file():
        return None
    # A user's own shell wrapper that calls Guard is not a pip console script.
    if re.fullmatch(r"python(\d+(\.\d+)*)?", interpreter.name) is None:
        return None
    if (interpreter.parent.parent / "pyvenv.cfg").is_file():
        return None
    return interpreter


def _venv_runtimes(venv: Path) -> tuple[Path, ...]:
    name = "hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime"
    patterns = (
        f"lib/python*/site-packages/codex_plugin_scanner/guard/_native/{name}",
        f"Lib/site-packages/codex_plugin_scanner/guard/_native/{name}",
    )
    found = [path for pattern in patterns for path in venv.glob(pattern) if path.is_file()]
    return tuple(_unique(found))


def _head(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(_CONTENT_SCAN_LIMIT)
    except OSError:
        return b""


def _link_target(entry: Path) -> Path:
    try:
        target = Path(os.readlink(entry))
    except OSError:
        return entry
    # Normalize so ``../pipx/venvs/...`` still matches once its target is gone.
    return Path(os.path.normpath(target if target.is_absolute() else entry.parent / target))


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


def _unique(paths: Iterable[Path]) -> tuple[Path, ...]:
    seen: set[Path] = set()
    result: list[Path] = []
    for path in paths:
        key = _resolve(path)
        if key not in seen:
            seen.add(key)
            result.append(path)
    return tuple(result)


__all__ = [
    "DESKTOP_PATH_SHIM_MARKER",
    "ENTRY_POINT_NAMES",
    "ForeignInventory",
    "RemovalResult",
    "ToolVenv",
    "bin_dirs",
    "entry_file_names",
    "inventory_foreign_installs",
    "pipx_venv_dirs",
    "remove_foreign_installs",
    "uv_tool_dirs",
]
