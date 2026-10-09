"""Render and parse Guard-managed Codex hook command lines.

Codex hands a hook command to the session's user shell: ``$SHELL -c`` on
POSIX, and on Windows usually ``powershell.exe -NoProfile -Command`` (or
``cmd.exe /c`` when the session shell is cmd). Neither Windows shell accepts
POSIX single-quote quoting, and Windows PowerShell 5.1 drops embedded double
quotes when it passes arguments to a native program. Windows commands
therefore carry the bridge config as unpadded base64url text and use plain
tokens that both shells read the same way. A path that needs quoting falls
back to PowerShell's call operator with single-quoted literals.
"""

from __future__ import annotations

import base64
import os
import re
import shlex
from collections.abc import Sequence
from pathlib import Path, PureWindowsPath

from .codex_hook_bridge_runtime import decode_bridge_config_argument

_WINDOWS_BARE_TOKEN = re.compile(r"[A-Za-z0-9_.:\\/-]+")
_WINDOWS_UNSAFE_CHARACTERS = frozenset("\r\n\x00")
_POWERSHELL_TOKEN = re.compile(r"'((?:[^']|'')*)'|([^\s'\"`$;|&(){}@#<>,]+)")


def hook_commands_use_windows_syntax(windows: bool | None = None) -> bool:
    """Return whether hook commands target the Windows shells on this host."""

    return os.name == "nt" if windows is None else windows


def hook_token_name(token: str, *, windows: bool | None = None) -> str:
    """Return the final path component of one hook argv token."""

    return PureWindowsPath(token).name if hook_commands_use_windows_syntax(windows) else Path(token).name


def encode_hook_config_argument(config_json: str, *, windows: bool | None = None) -> str:
    """Return the bridge config argument in a form the platform shell passes intact."""

    if not hook_commands_use_windows_syntax(windows):
        return config_json
    return base64.urlsafe_b64encode(config_json.encode("utf-8")).decode("ascii").rstrip("=")


def plain_json_hook_argv(argv: Sequence[str]) -> list[str]:
    """Return ``argv`` with its config as the plain JSON earlier Windows installs wrote."""

    if not argv:
        return []
    try:
        return [*argv[:-1], decode_bridge_config_argument(argv[-1])]
    except ValueError:
        return list(argv)


def _powershell_literal(argument: str) -> str:
    return "'" + argument.replace("'", "''") + "'"


def render_hook_command(argv: Sequence[str], *, windows: bool | None = None) -> str:
    """Return the command string Codex hands to the session shell."""

    if not hook_commands_use_windows_syntax(windows):
        return shlex.join(argv)
    if not argv or any(_WINDOWS_UNSAFE_CHARACTERS.intersection(argument) for argument in argv):
        raise ValueError("Codex hook arguments cannot be empty or contain line breaks or NUL on Windows.")
    if not argv[0].startswith("-") and all(_WINDOWS_BARE_TOKEN.fullmatch(argument) for argument in argv):
        return " ".join(argv)
    return "& " + " ".join(_powershell_literal(argument) for argument in argv)


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
    return _split_windows_command_line(command)


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
    "encode_hook_config_argument",
    "hook_command_launchable",
    "hook_command_tokens",
    "hook_commands_use_windows_syntax",
    "hook_token_name",
    "is_legacy_posix_hook_command",
    "plain_json_hook_argv",
    "render_hook_command",
    "split_hook_command_line",
]
