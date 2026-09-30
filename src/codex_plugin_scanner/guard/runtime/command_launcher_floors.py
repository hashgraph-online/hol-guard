"""Extract exact child commands from bounded command-launcher grammars."""

from __future__ import annotations

import shlex
from typing import Final

from .command_model import CanonicalCommand, parse_shell_command

_XARGS_VALUE_OPTIONS = frozenset(
    {
        "--arg-file",
        "--delimiter",
        "--eof",
        "--max-args",
        "--max-chars",
        "--max-lines",
        "--max-procs",
        "--replace",
        "-E",
        "-I",
        "-J",
        "-L",
        "-P",
        "-R",
        "-S",
        "-a",
        "-d",
        "-e",
        "-n",
        "-s",
    }
)
_PARALLEL_VALUE_OPTIONS = frozenset(
    {
        "--colsep",
        "--delay",
        "--header",
        "--joblog",
        "--jobs",
        "--load",
        "--max-procs",
        "--results",
        "--retries",
        "--sshlogin",
        "--tagstring",
        "--timeout",
        "--workdir",
        "-P",
        "-j",
    }
)
_FIND_MARKERS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_MAX_OPTION_PARSE_STATES: Final = 256


def launcher_child_commands(executable: str, arguments: tuple[str, ...]) -> tuple[CanonicalCommand, ...]:
    """Return exact nested commands, or none when the launcher grammar is unresolved."""

    children: tuple[tuple[str, ...], ...] = ()
    if executable == "xargs":
        children = _possible_children(arguments, _XARGS_VALUE_OPTIONS)
    elif executable == "parallel":
        children = _possible_children(arguments, _PARALLEL_VALUE_OPTIONS)
    elif executable == "find":
        children = _find_children(arguments)
    return tuple(parse_shell_command(shlex.join(child)) for child in children if child)


def _possible_children(arguments: tuple[str, ...], value_options: frozenset[str]) -> tuple[tuple[str, ...], ...]:
    pending = [0]
    visited: set[int] = set()
    children: set[tuple[str, ...]] = set()
    while pending:
        index = pending.pop()
        if index in visited or index >= len(arguments):
            continue
        if len(visited) >= _MAX_OPTION_PARSE_STATES:
            return tuple(arguments[cursor:] for cursor, item in enumerate(arguments) if not item.startswith("-"))
        visited.add(index)
        argument = arguments[index]
        if argument == "--":
            if arguments[index + 1 :]:
                children.add(arguments[index + 1 :])
            continue
        option, separator, _value = argument.partition("=")
        attached = _attached_short_option(argument, value_options)
        if attached is not None:
            option, separator = attached, "attached"
        if option in value_options:
            pending.append(index + (1 if separator else 2))
            continue
        if argument.startswith("-"):
            pending.append(index + 1)
            if not separator:
                pending.append(index + 2)
            continue
        children.add(arguments[index:])
    return tuple(sorted(children))


def _attached_short_option(argument: str, value_options: frozenset[str]) -> str | None:
    if len(argument) <= 2 or not argument.startswith("-") or argument.startswith("--"):
        return None
    matches = tuple(option for option in value_options if len(option) == 2 and argument.startswith(option))
    return matches[0] if len(matches) == 1 else None


def _find_children(arguments: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    children: list[tuple[str, ...]] = []
    index = 0
    while index < len(arguments):
        if arguments[index] not in _FIND_MARKERS:
            index += 1
            continue
        start = index + 1
        end = next(
            (cursor for cursor in range(start, len(arguments)) if arguments[cursor] in {";", "+"}),
            len(arguments),
        )
        if start < end:
            children.append(arguments[start:end])
        index = end + 1
    return tuple(children)


__all__ = ("launcher_child_commands",)
