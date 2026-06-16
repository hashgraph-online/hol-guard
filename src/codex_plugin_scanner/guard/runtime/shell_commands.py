"""Shell command token helpers for Guard runtime detectors."""

from __future__ import annotations

import shlex
from collections.abc import Collection, Sequence

from codex_plugin_scanner.guard.runtime.data_flow import extract_command_segments, extract_pipes

_SCP_OPTIONS_WITH_VALUES = frozenset({"-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"})
_GIT_OPTIONS_WITH_VALUES = frozenset({"-C", "-c", "--config-env", "--exec-path", "--git-dir", "--work-tree"})
_NPM_OPTIONS_WITH_VALUES = frozenset(
    {"-w", "--access", "--cache", "--otp", "--prefix", "--registry", "--tag", "--userconfig"}
)


def segment_executes_command(command: str, names: Collection[str]) -> bool:
    tokens = command_tokens_after_env_assignments(command)
    return bool(tokens) and tokens[0].lower() in names


def command_tokens_after_env_assignments(command: str) -> tuple[str, ...]:
    return shell_tokens(strip_env_assignment_prefix(command))


def command_execution_segments(command: str) -> tuple[str, ...]:
    segments: list[str] = []
    for segment in extract_command_segments(command):
        segments.append(segment)
        segments.extend(pipe.right for pipe in extract_pipes(segment))
    return tuple(segments)


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


def git_remote_add_url_tokens(tokens: Sequence[str]) -> tuple[str, ...]:
    if not tokens or tokens[0].lower() != "git":
        return ()
    index = _skip_options(tokens, 1, _GIT_OPTIONS_WITH_VALUES)
    if len(tokens) <= index + 3 or tuple(token.lower() for token in tokens[index : index + 2]) != ("remote", "add"):
        return ()
    return tuple(tokens[index + 3 :])


def npm_publish_index(tokens: Sequence[str]) -> int | None:
    if not tokens or tokens[0].lower() != "npm":
        return None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token.lower() == "publish":
            return index
        if token == "--" or not token.startswith("-"):
            return None
        index = _advance_option(tokens, index, _NPM_OPTIONS_WITH_VALUES)
    return None


def npm_publish_is_dry_run(tokens: Sequence[str], publish_index: int) -> bool:
    dry_run = False
    for token in tokens[publish_index + 1 :]:
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


def _skip_options(tokens: Sequence[str], index: int, options_with_values: frozenset[str]) -> int:
    while index < len(tokens) and tokens[index].startswith("-"):
        index = _advance_option(tokens, index, options_with_values)
    return index


def _advance_option(tokens: Sequence[str], index: int, options_with_values: frozenset[str]) -> int:
    token = tokens[index]
    if "=" not in token and token in options_with_values and index + 1 < len(tokens):
        return index + 2
    return index + 1


def _skip_spaces(command: str, index: int) -> int:
    while index < len(command) and command[index].isspace():
        index += 1
    return index


def _advance_assignment_value(command: str, index: int) -> int:
    if command.startswith("$(", index):
        return _advance_parenthesized_assignment(command, index + 2)
    if index < len(command) and command[index] in {"'", '"'}:
        return _advance_quoted_assignment(command, index)
    if index < len(command) and command[index] == "`":
        return _advance_backtick_assignment(command, index)
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


def _advance_backtick_assignment(command: str, index: int) -> int:
    index += 1
    while index < len(command):
        if command[index] == "\\":
            index += 2
            continue
        if command[index] == "`":
            return index + 1
        index += 1
    return index
