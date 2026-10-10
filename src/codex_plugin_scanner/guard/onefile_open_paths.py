"""System-wide scan for PyInstaller extraction dirs that a live process still uses.

Unmarked ``_MEI*`` dirs have no recorded owner pid, so the only proof that one
is dead is that no process has any file in it open, mapped, or as its working
directory. The scan is a single pass over the whole machine and is fail-closed:
any error, timeout, or missing tool returns ``None`` and callers must then skip
all unmarked reclamation.

Stdlib-only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

_LSOF_TIMEOUT_SECONDS = 90
_LSOF_MAX_OUTPUT_BYTES = 256 * 1024 * 1024

OpenPathScanner = Callable[[Path], "frozenset[str] | None"]


def _root_prefixes(temp_root: Path) -> tuple[str, ...]:
    prefixes = {str(temp_root).rstrip("/\\")}
    with suppress(OSError):
        prefixes.add(str(temp_root.resolve(strict=True)).rstrip("/\\"))
    return tuple(sorted(prefixes))


def _collect_extraction_name(path: str, prefixes: tuple[str, ...], found: set[str]) -> None:
    for prefix in prefixes:
        if not path.startswith(prefix + "/"):
            continue
        name = path[len(prefix) + 1 :].split("/", 1)[0]
        # Deliberately looser than the reclaim name pattern: over-reporting a
        # dir as in use only delays its reclamation.
        if name.startswith("_MEI"):
            found.add(name)
        return


def _scan_with_lsof(
    temp_root: Path,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
    lsof_path: str | None,
) -> frozenset[str] | None:
    executable = lsof_path or shutil.which("lsof")
    if executable is None:
        for candidate in ("/usr/sbin/lsof", "/usr/bin/lsof"):
            if os.path.isfile(candidate):
                executable = candidate
                break
    if executable is None:
        return None
    try:
        completed = runner(
            [executable, "-n", "-P", "-w", "-F", "n"],
            capture_output=True,
            timeout=_LSOF_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    # lsof exits 1 when it could not stat some unrelated entry; anything higher
    # (or no output at all, which would mean not even this process was seen) is
    # treated as an unusable scan.
    if completed.returncode not in (0, 1) or not completed.stdout:
        return None
    if len(completed.stdout) > _LSOF_MAX_OUTPUT_BYTES:
        return None
    prefixes = _root_prefixes(temp_root)
    found: set[str] = set()
    for raw_line in completed.stdout.split(b"\n"):
        if not raw_line.startswith(b"n"):
            continue
        _collect_extraction_name(os.fsdecode(raw_line[1:]), prefixes, found)
    return frozenset(found)


def _scan_with_proc(temp_root: Path, proc_root: Path) -> frozenset[str] | None:
    try:
        entries = [entry for entry in proc_root.iterdir() if entry.name.isdigit()]
    except OSError:
        return None
    if not entries:
        return None
    prefixes = _root_prefixes(temp_root)
    own_uid = os.getuid() if hasattr(os, "getuid") else -1
    found: set[str] = set()
    for entry in entries:
        try:
            _scan_proc_entry(entry, prefixes, found)
        except PermissionError:
            # Another user's process cannot own a dir we are allowed to delete;
            # an unreadable process of our own user is an unprovable case.
            try:
                if entry.stat().st_uid == own_uid:
                    return None
            except OSError:
                continue
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError:
            return None
    return frozenset(found)


def _scan_proc_entry(entry: Path, prefixes: tuple[str, ...], found: set[str]) -> None:
    maps_text = (entry / "maps").read_text(encoding="utf-8", errors="replace")
    for line in maps_text.splitlines():
        index = line.find("/")
        if index >= 0:
            _collect_extraction_name(line[index:].removesuffix(" (deleted)"), prefixes, found)
    for link_name in ("cwd", "exe", "root"):
        try:
            _collect_extraction_name(os.readlink(entry / link_name), prefixes, found)
        except FileNotFoundError:
            continue
    fd_dir = entry / "fd"
    for descriptor in fd_dir.iterdir():
        try:
            _collect_extraction_name(os.readlink(descriptor), prefixes, found)
        except FileNotFoundError:
            continue


def scan_open_extraction_dirs(
    temp_root: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    lsof_path: str | None = None,
    proc_root: Path = Path("/proc"),
    platform: str | None = None,
) -> frozenset[str] | None:
    """Return names of ``_MEI*`` dirs under ``temp_root`` in use by any process.

    Returns ``None`` when the scan could not be completed (including on
    Windows, where no handle-free system-wide scan exists), meaning "unknown".
    """

    current_platform = platform if platform is not None else sys.platform
    if current_platform.startswith("linux") and proc_root.is_dir():
        proc_result = _scan_with_proc(temp_root, proc_root)
        if proc_result is not None:
            return proc_result
    if current_platform == "darwin" or current_platform.startswith("linux"):
        return _scan_with_lsof(temp_root, runner, lsof_path)
    return None
