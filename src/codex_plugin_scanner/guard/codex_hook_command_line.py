"""Parse Guard-managed Codex hook command lines.

Codex hands a hook command to the session's shell: ``$SHELL -c`` on POSIX. On
Windows it uses the session shell when it knows it, usually
``powershell.exe -NoProfile -Command``, and otherwise ``%COMSPEC% /C`` (falling
back to ``cmd.exe``). A Windows hook command must therefore parse the same way
in PowerShell and in ``cmd.exe``. Neither accepts POSIX single-quote quoting,
Windows PowerShell 5.1 drops embedded double quotes when it passes arguments to
a native program, and no quoting form means the same thing in both shells.

Windows commands therefore use plain tokens only: the bridge config travels as
unpadded base64url text, and a path that would need quoting (for example one
under ``C:\\Program Files``) is replaced by its 8.3 short name when that name is
itself a plain token. Parsing maps such a short name back to the long path, so
integrity checks keep comparing the long argv. When a volume has no short
names, the command falls back to PowerShell's call operator with single-quoted
literals. That fallback only launches under a PowerShell session shell; a
``cmd.exe`` hook shell cannot run it.

The native runtime renders and splits these command lines; this module names
the host facts only Windows can answer: each path's 8.3 short form and each
short name's long form.
"""

from __future__ import annotations

import ctypes
import os
import re
from collections.abc import Callable, Sequence
from ctypes import wintypes

# An 8.3 name such as C:\PROGRA~1\python.exe; never a leading tilde.
_WINDOWS_SHORT_PATH_TOKEN = re.compile(r"[A-Za-z]:[A-Za-z0-9_.~\\-]+")


def hook_commands_use_windows_syntax(windows: bool | None = None) -> bool:
    """Return whether hook commands target the Windows shells on this host."""

    return os.name == "nt" if windows is None else windows


def _windows_path_form(function_name: str, path: str) -> str | None:
    """Return ``path`` converted by a kernel32 short/long path function, or ``None``."""

    if os.name != "nt" or "\x00" in path:
        return None
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return None
    try:
        function = getattr(win_dll("kernel32", use_last_error=True), function_name)
        function.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        function.restype = wintypes.DWORD
        size = int(function(path, None, 0))
        if size <= 0:
            return None
        buffer = ctypes.create_unicode_buffer(size)
        written = int(function(path, buffer, size))
    except (AttributeError, OSError):
        return None
    if written <= 0 or written >= size:
        return None
    return str(buffer.value)


def _windows_short_path(path: str) -> str | None:
    return _windows_path_form("GetShortPathNameW", path)


def _windows_long_path(path: str) -> str | None:
    return _windows_path_form("GetLongPathNameW", path)


# Replaceable in tests, which run on hosts without 8.3 names.
_short_path: Callable[[str], str | None] = _windows_short_path
_long_path: Callable[[str], str | None] = _windows_long_path


def short_path_facts(paths: Sequence[object]) -> dict[str, list[str | None]]:
    """Each path's 8.3 name and that name's long form, for the native renderer."""

    facts: dict[str, list[str | None]] = {}
    for path in paths:
        short = _short_path(str(path))
        facts[str(path)] = [short, None if short is None else _long_path(short)]
    return facts


def _expand_short_token(token: str) -> str:
    if "~" not in token or not _WINDOWS_SHORT_PATH_TOKEN.fullmatch(token):
        return token
    return _long_path(token) or token


def short_token_long_paths(commands: Sequence[str]) -> dict[str, str]:
    """Each 8.3 short name these commands may carry, to its long form on this host.

    The native splitter expands a whole argv token of this shape; reading the
    shape straight off the text names every such token a Guard-written
    command can hold. A name with no long form maps to the empty string.
    """

    names = {match.group(0) for command in commands for match in _WINDOWS_SHORT_PATH_TOKEN.finditer(command)}
    return {name: _long_path(name) or "" for name in sorted(names) if "~" in name}


__all__ = [
    "hook_commands_use_windows_syntax",
    "short_path_facts",
    "short_token_long_paths",
]
