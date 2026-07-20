"""Extract exact child commands from bounded command-launcher grammars."""

from __future__ import annotations

import shlex

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
        "--delay",
        "--joblog",
        "--jobs",
        "--max-procs",
        "--results",
        "--retries",
        "--sshlogin",
        "--timeout",
        "--workdir",
        "-P",
        "-j",
    }
)
_FIND_MARKERS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})


def launcher_child_commands(executable: str, arguments: tuple[str, ...]) -> tuple[CanonicalCommand, ...]:
    """Return exact nested commands, or none when the launcher grammar is unresolved."""

    children: tuple[tuple[str, ...], ...] = ()
    if executable == "xargs":
        child = _single_child(arguments, _XARGS_VALUE_OPTIONS)
        children = (child,) if child else ()
    elif executable == "parallel":
        child = _single_child(arguments, _PARALLEL_VALUE_OPTIONS)
        children = (child,) if child else ()
    elif executable == "find":
        children = _find_children(arguments)
    return tuple(parse_shell_command(shlex.join(child)) for child in children if child)


def _single_child(arguments: tuple[str, ...], value_options: frozenset[str]) -> tuple[str, ...] | None:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            index += 1
            break
        option, separator, _value = argument.partition("=")
        attached = _attached_short_option(argument, value_options)
        if attached is not None:
            option, separator = attached, "attached"
        if option in value_options:
            index += 1 if separator else 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        break
    return arguments[index:] or None


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
