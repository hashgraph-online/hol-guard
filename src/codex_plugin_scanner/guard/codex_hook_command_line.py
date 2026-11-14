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

The native runtime renders these command lines (``hook_render``); this module
parses them and names the host's 8.3 short forms the renderer asks for.
"""

from __future__ import annotations

import ctypes
import os
import re
import shlex
from collections.abc import Callable, Sequence
from ctypes import wintypes
from pathlib import Path, PureWindowsPath

from .codex_hook_bridge_runtime import decode_bridge_config_argument

# An 8.3 name such as C:\PROGRA~1\python.exe; never a leading tilde.
_WINDOWS_SHORT_PATH_TOKEN = re.compile(r"[A-Za-z]:[A-Za-z0-9_.~\\-]+")
_POWERSHELL_TOKEN = re.compile(r"'((?:[^']|'')*)'|([^\s'\"`$;|&(){}@#<>,]+)")


def hook_commands_use_windows_syntax(windows: bool | None = None) -> bool:
    """Return whether hook commands target the Windows shells on this host."""

    return os.name == "nt" if windows is None else windows


def hook_token_name(token: str, *, windows: bool | None = None) -> str:
    """Return the final path component of one hook argv token."""

    return PureWindowsPath(token).name if hook_commands_use_windows_syntax(windows) else Path(token).name


def plain_json_hook_argv(argv: Sequence[str]) -> list[str]:
    """Return ``argv`` with its config as the plain JSON earlier Windows installs wrote."""

    if not argv:
        return []
    try:
        return [*argv[:-1], decode_bridge_config_argument(argv[-1])]
    except ValueError:
        return list(argv)


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


def _split_windows_command_line(command: str) -> list[str] | None:
    """Split with the Microsoft C runtime rules that ``python.exe`` applies."""

    arguments: list[str] = []
    current: list[str] = []
    in_argument = False
    in_quotes = False
    backslashes = 0
    for character in command:
        if character == "\\":
            backslashes += 1
            in_argument = True
            continue
        if character == '"':
            current.append("\\" * (backslashes // 2))
            if backslashes % 2:
                current.append('"')
            else:
                in_quotes = not in_quotes
            backslashes = 0
            in_argument = True
            continue
        current.append("\\" * backslashes)
        backslashes = 0
        if character in " \t" and not in_quotes:
            if in_argument:
                arguments.append("".join(current))
                current = []
                in_argument = False
            continue
        current.append(character)
        in_argument = True
    current.append("\\" * backslashes)
    if in_quotes:
        return None
    if in_argument:
        arguments.append("".join(current))
    return arguments or None


def _split_powershell_call(command: str) -> list[str] | None:
    """Split ``& 'program' args`` built only from literal and bare tokens."""

    rest = command.strip()[1:]
    arguments: list[str] = []
    position = 0
    while True:
        while position < len(rest) and rest[position] in " \t":
            position += 1
        if position == len(rest):
            break
        match = _POWERSHELL_TOKEN.match(rest, position)
        if match is None or (match.end() < len(rest) and rest[match.end()] not in " \t"):
            return None
        literal, bare = match.groups()
        arguments.append(literal.replace("''", "'") if literal is not None else bare)
        position = match.end()
    return arguments or None


def is_legacy_posix_hook_command(command: str, *, windows: bool | None = None) -> bool:
    """Return whether a Windows hook still uses POSIX quoting no Windows shell can launch."""

    return hook_commands_use_windows_syntax(windows) and command.lstrip().startswith("'")


def split_hook_command_line(command: str, *, windows: bool | None = None) -> list[str] | None:
    """Parse one hook command, recognising legacy POSIX-quoted Windows entries."""

    if not hook_commands_use_windows_syntax(windows) or is_legacy_posix_hook_command(command, windows=True):
        try:
            return shlex.split(command)
        except ValueError:
            return None
    if command.lstrip().startswith("&"):
        return _split_powershell_call(command)
    arguments = _split_windows_command_line(command)
    return None if arguments is None else [_expand_short_token(argument) for argument in arguments]


def hook_command_tokens(command: str, *, windows: bool | None = None) -> list[str]:
    """Return hook argv tokens, falling back to whitespace splitting for unparsable text."""

    tokens = split_hook_command_line(command, windows=windows)
    return command.split() if tokens is None else tokens


def hook_command_launchable(command: str, *, windows: bool | None = None) -> bool:
    """Return whether the session shell can launch this hook command."""

    if is_legacy_posix_hook_command(command, windows=windows):
        return False
    return split_hook_command_line(command, windows=windows) is not None


__all__ = [
    "hook_command_launchable",
    "hook_command_tokens",
    "hook_commands_use_windows_syntax",
    "hook_token_name",
    "is_legacy_posix_hook_command",
    "plain_json_hook_argv",
    "short_path_facts",
    "split_hook_command_line",
]
