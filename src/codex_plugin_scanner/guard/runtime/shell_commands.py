"""Shell command token helpers for Guard runtime detectors."""

from __future__ import annotations

import shlex
from collections.abc import Sequence

_SCP_OPTIONS_WITH_VALUES = frozenset({"-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"})


def segment_executes_command(command: str, names: set[str]) -> bool:
    tokens = command_tokens_after_env_assignments(command)
    return bool(tokens) and tokens[0].lower() in names


def command_tokens_after_env_assignments(command: str) -> tuple[str, ...]:
    return shell_tokens(strip_env_assignment_prefix(command))


def shell_tokens(command: str) -> tuple[str, ...]:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    return tuple(tokens)


def strip_env_assignment_prefix(command: str) -> str:
    index = 0
    while True:
        index = _skip_spaces(command, index)
        name_start = index
        if index >= len(command) or not (command[index].isalpha() or command[index] == "_"):
            return command[index:].lstrip()
        index += 1
        while index < len(command) and (command[index].isalnum() or command[index] == "_"):
            index += 1
        if index >= len(command) or command[index] != "=":
            return command[name_start:].lstrip()
        index = _advance_assignment_value(command, index + 1)


def scp_operands(body: str) -> tuple[str, ...]:
    tokens = shell_tokens(body)
    operands: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if token in _SCP_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        operands.append(token)
        index += 1
    return tuple(operands)


def is_scp_remote_target(value: str) -> bool:
    if value.startswith(("./", "../", "/")):
        return False
    host, separator, _path = value.partition(":")
    if not separator or not host or "/" in host:
        return False
    return not any(char.isspace() for char in host)


def npm_publish_is_dry_run(tokens: Sequence[str]) -> bool:
    dry_run = False
    for token in tokens[2:]:
        if token == "--dry-run":
            dry_run = True
            continue
        if token == "--no-dry-run":
            dry_run = False
            continue
        if token.startswith("--dry-run="):
            value = token.split("=", 1)[1].lower()
            dry_run = value not in {"false", "0", "no", "off"}
    return dry_run


def _skip_spaces(command: str, index: int) -> int:
    while index < len(command) and command[index].isspace():
        index += 1
    return index


def _advance_assignment_value(command: str, index: int) -> int:
    if command.startswith("$(", index):
        return _advance_parenthesized_assignment(command, index + 2)
    if index < len(command) and command[index] in {"'", '"'}:
        return _advance_quoted_assignment(command, index)
    while index < len(command) and not command[index].isspace():
        index += 1
    return index


def _advance_parenthesized_assignment(command: str, index: int) -> int:
    depth = 1
    quote: str | None = None
    while index < len(command):
        char = command[index]
        if char == "\\":
            index += 2
            continue
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            index += 1
            continue
        if quote is None and char == "(":
            depth += 1
        elif quote is None and char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return index


def _advance_quoted_assignment(command: str, index: int) -> int:
    quote = command[index]
    index += 1
    while index < len(command):
        if command[index] == "\\":
            index += 2
            continue
        if command[index] == quote:
            return index + 1
        index += 1
    return index
