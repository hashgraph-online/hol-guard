"""Private lexer and path helpers for shell execution-context modeling."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SHELL_CWD_UNRESOLVED_EXPRESSION = "shell_cwd_unresolved_expression"
SHELL_CWD_MISSING_DIRECTORY = "shell_cwd_missing_directory"
SHELL_CWD_NOT_DIRECTORY = "shell_cwd_not_directory"
SHELL_CWD_UNREADABLE_DIRECTORY = "shell_cwd_unreadable_directory"
SHELL_CWD_AMBIGUOUS_STACK = "shell_cwd_ambiguous_stack"
SHELL_CWD_STACK_LIMIT = "shell_cwd_stack_limit"
SHELL_CWD_WORKSPACE_ESCAPE = "shell_cwd_workspace_escape"
SHELL_CWD_SYMLINK_ESCAPE = "shell_cwd_symlink_escape"
SHELL_CWD_UNRESOLVED_CONTROL_FLOW = "shell_cwd_unresolved_control_flow"
SHELL_CWD_UNRESOLVED_PARENT_SHELL = "shell_cwd_unresolved_parent_shell_effect"
SHELL_CWD_UNRESOLVED_SYNTAX = "shell_cwd_unresolved_syntax"
SHELL_CWD_PATH_CHANGED = "shell_cwd_path_changed"

DIRECTORY_COMMANDS = frozenset({"cd", "pushd", "popd"})
_UNMODELED_SHELL_CONTROL_WORDS = frozenset({"do", "elif", "else", "if", "then", "until", "while"})
FLOW_OPERATORS = frozenset({"&&", "||", ";", "\n", "|", "|&", "&"})
_NEWLINE_SENTINEL = "__HOL_GUARD_SHELL_NEWLINE__"
_FD_AMPERSAND_SENTINEL = "__HOL_GUARD_SHELL_FD_AMPERSAND__"
_NOCLOBBER_PIPE_SENTINEL = "__GUARD_SHELL_NOCLOBBER_PIPE__"
_FIND_PLACEHOLDER_SENTINEL = "__HOL_GUARD_FIND_PLACEHOLDER__"
_ESCAPED_SEMICOLON_SENTINEL = "__HOL_GUARD_ESCAPED_SEMICOLON__"
_SHELL_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
SHELL_DIRECTORY_COMMAND = re.compile(
    r"(?:^|(?:&&|\|\||[;|&(){}\n]))\s*"
    r"(?:(?:builtin|command|time)\s+(?:-[^\s]+\s+)*|function\s+|!\s+)?"
    r"(?:cd|pushd|popd)\b"
)
_REDIRECTION_TOKEN = re.compile(r"^(?:[012]?(?:>|>>|<|<<|<>).*)$")


@dataclass(frozen=True, slots=True)
class ShellPathIdentity:
    """Filesystem identity captured without retaining an open descriptor."""

    device: int
    inode: int
    mode: int
    change_time_ns: int
    creation_time_ns: int


def shell_path_identity_payload(identity: ShellPathIdentity | None) -> dict[str, int] | None:
    """Return the stable JSON payload for a captured shell path identity."""

    if identity is None:
        return None
    return {
        "change_time_ns": identity.change_time_ns,
        "creation_time_ns": identity.creation_time_ns,
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
    }


@dataclass(frozen=True, slots=True)
class ShellPathProof:
    """A lexical directory path bound to the target observed during modeling."""

    lexical_path: Path
    resolved_path: Path
    identity: ShellPathIdentity


@dataclass(frozen=True, slots=True)
class DirectoryOperation:
    name: str
    operand: str | None
    reason_code: str | None = None


def directory_operation(tokens: tuple[str, ...]) -> DirectoryOperation | None:
    index = 0
    while index < len(tokens) and _SHELL_ASSIGNMENT.match(tokens[index]):
        index += 1
    if index >= len(tokens):
        return None
    command = tokens[index]
    if command in _UNMODELED_SHELL_CONTROL_WORDS:
        embedded_command = next((token for token in tokens[index + 1 :] if token in DIRECTORY_COMMANDS), None)
        if embedded_command is not None:
            return DirectoryOperation(embedded_command, None, SHELL_CWD_UNRESOLVED_CONTROL_FLOW)
    if command in {"!", "builtin", "command", "function", "time"}:
        wrapped_index = next(
            (candidate for candidate in range(index + 1, len(tokens)) if tokens[candidate] in DIRECTORY_COMMANDS),
            None,
        )
        if wrapped_index is None:
            return None
        if command in {"command", "time"} and wrapped_index == index + 1:
            index = wrapped_index
            command = tokens[index]
        else:
            return DirectoryOperation(tokens[wrapped_index], None, SHELL_CWD_UNRESOLVED_EXPRESSION)
    if command not in DIRECTORY_COMMANDS:
        return None
    arguments = _directory_arguments(tokens[index + 1 :])
    if arguments is None:
        return DirectoryOperation(command, None, SHELL_CWD_UNRESOLVED_EXPRESSION)
    if command == "popd":
        if arguments:
            return DirectoryOperation(command, None, SHELL_CWD_AMBIGUOUS_STACK)
        return DirectoryOperation(command, None)
    if command == "cd" and arguments[:1] == ("--",):
        arguments = arguments[1:]
    elif arguments and arguments[0].startswith("-"):
        return DirectoryOperation(command, None, SHELL_CWD_UNRESOLVED_EXPRESSION)
    if len(arguments) != 1 or _operand_is_dynamic(arguments[0]):
        return DirectoryOperation(command, None, SHELL_CWD_UNRESOLVED_EXPRESSION)
    if command == "pushd" and re.fullmatch(r"[+-]\d+", arguments[0]):
        return DirectoryOperation(command, None, SHELL_CWD_AMBIGUOUS_STACK)
    return DirectoryOperation(command, arguments[0])


def _directory_arguments(tokens: tuple[str, ...]) -> tuple[str, ...] | None:
    arguments: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _REDIRECTION_TOKEN.match(token):
            if token in {">", ">>", "<", "<<", "0>", "1>", "2>"}:
                if index + 1 >= len(tokens):
                    return None
                index += 2
            else:
                index += 1
            continue
        arguments.append(token)
        index += 1
    return tuple(arguments)


def _operand_is_dynamic(value: str) -> bool:
    if not value or "\x00" in value or (value.startswith("~") and not value.startswith("~/")):
        return True
    return any(character in value for character in ("$", "`", "*", "?", "[", "]", "{", "}", "<", ">"))


def _path_contains_symlink(path: Path, *, workspace_root: Path) -> bool:
    try:
        relative = path.relative_to(workspace_root)
    except ValueError:
        relative = path
    current = workspace_root if not relative.is_absolute() else Path(relative.anchor)
    for part in relative.parts:
        if part in {relative.anchor, "", ".", ".."}:
            continue
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def last_flow_operator(controls: tuple[str, ...]) -> str | None:
    return next((control for control in reversed(controls) if control in FLOW_OPERATORS), None)
