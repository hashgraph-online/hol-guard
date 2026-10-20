"""Parse Guard-managed Cursor hook command lines.

Cursor hook commands are rendered like Codex ones: ``shlex`` quoting on POSIX,
and on Windows plain tokens or a PowerShell ``&`` call with single-quoted
literals. Earlier Windows installs wrote POSIX single-quoted tokens; those
still parse, so repair and removal keep recognising them.
"""

from __future__ import annotations

import shlex

from ....codex_hook_command_line import split_hook_command_line


def split_cursor_hook_command(command: str) -> list[str] | None:
    """Return the argv of one Cursor hook command, or ``None`` when it does not parse."""

    if "'" in command and not command.lstrip().startswith("&"):
        try:
            return shlex.split(command)
        except ValueError:
            return None
    return split_hook_command_line(command)


def cursor_hook_command_tokens(command: str) -> list[str]:
    """Return Cursor hook argv tokens, falling back to whitespace splitting."""

    tokens = split_cursor_hook_command(command)
    return command.split() if tokens is None else tokens


__all__ = ["cursor_hook_command_tokens", "split_cursor_hook_command"]
