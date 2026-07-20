"""Private lexer and path helpers for shell execution-context modeling."""

from __future__ import annotations

import os
import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path

from .shell_structure import extract_heredocs

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
GROUP_OPERATORS = frozenset({"(", ")", "{", "}"})
CONTROL_TOKENS = FLOW_OPERATORS | GROUP_OPERATORS
MAX_DIRECTORY_STACK_DEPTH = 32
_NEWLINE_SENTINEL = "__HOL_GUARD_SHELL_NEWLINE__"
_FD_AMPERSAND_SENTINEL = "__HOL_GUARD_SHELL_FD_AMPERSAND__"
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

    @classmethod
    def from_stat(cls, value: os.stat_result) -> ShellPathIdentity:
        birth_time = getattr(value, "st_birthtime", None)
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=stat.S_IFMT(value.st_mode),
            change_time_ns=value.st_ctime_ns,
            creation_time_ns=int(birth_time * 1_000_000_000) if isinstance(birth_time, int | float) else 0,
        )


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


def split_shell_tokens(command_text: str) -> tuple[str, ...]:
    command_text = _mask_heredoc_bodies(command_text)
    command_text = _protect_fd_redirection_ampersands(command_text)
    lexer = shlex.shlex(
        _replace_unquoted_newlines(command_text),
        posix=True,
        punctuation_chars=";&|(){}",
    )
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens: list[str] = []
    for token in lexer:
        if token == _NEWLINE_SENTINEL:
            tokens.append("\n")
        elif token and all(character in ";&|(){}" for character in token):
            tokens.extend(_split_punctuation_run(token))
        else:
            tokens.append(token.replace(_FD_AMPERSAND_SENTINEL, "&"))
    return tuple(tokens)


def _protect_fd_redirection_ampersands(command_text: str) -> str:
    if _FD_AMPERSAND_SENTINEL in command_text:
        raise ValueError("reserved shell parsing sentinel")
    result: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command_text):
        character = command_text[index]
        if escaped:
            result.append(character)
            escaped = False
            index += 1
            continue
        if character == "\\":
            result.append(character)
            escaped = True
            index += 1
            continue
        if quote is None and character in {"'", '"', "`"}:
            quote = character
            result.append(character)
            index += 1
            continue
        if quote == character:
            quote = None
            result.append(character)
            index += 1
            continue
        if quote is None and character == "&" and _is_adjacent_fd_duplication(command_text, index):
            result.append(_FD_AMPERSAND_SENTINEL)
        else:
            result.append(character)
        index += 1
    return "".join(result)


def _is_adjacent_fd_duplication(command_text: str, ampersand_index: int) -> bool:
    if ampersand_index == 0 or command_text[ampersand_index - 1] not in {"<", ">"}:
        return False
    if ampersand_index >= 2 and command_text[ampersand_index - 2] in {"<", ">"}:
        return False
    target_index = ampersand_index + 1
    if target_index >= len(command_text):
        return False
    if command_text[target_index] == "-":
        target_end = target_index + 1
    elif command_text[target_index].isdigit():
        target_end = target_index + 1
        while target_end < len(command_text) and command_text[target_end].isdigit():
            target_end += 1
    else:
        return False
    return (
        target_end == len(command_text) or command_text[target_end].isspace() or command_text[target_end] in ";&|(){}"
    )


def _mask_heredoc_bodies(command_text: str) -> str:
    heredocs = extract_heredocs(command_text)
    if not heredocs:
        return command_text
    characters = list(command_text)
    for heredoc in heredocs:
        start = max(0, heredoc.body_start - 1)
        for index in range(start, min(heredoc.end, len(characters))):
            characters[index] = " "
        if heredoc.end > 0 and heredoc.end <= len(command_text) and command_text[heredoc.end - 1] == "\n":
            characters[heredoc.end - 1] = "\n"
    return "".join(characters)


def _split_punctuation_run(token: str) -> tuple[str, ...]:
    result: list[str] = []
    index = 0
    while index < len(token):
        pair = token[index : index + 2]
        if pair in {"&&", "||", "|&"}:
            result.append(pair)
            index += 2
            continue
        result.append(token[index])
        index += 1
    return tuple(result)


def _replace_unquoted_newlines(command_text: str) -> str:
    result: list[str] = []
    quote: str | None = None
    escaped = False
    for character in command_text:
        if escaped:
            result.append(character)
            escaped = False
            continue
        if character == "\\":
            result.append(character)
            escaped = True
            continue
        if quote is None and character in {"'", '"', "`"}:
            quote = character
            result.append(character)
            continue
        if quote == character:
            quote = None
            result.append(character)
            continue
        if quote is None and character in {"\n", "\r"}:
            result.extend((" ", _NEWLINE_SENTINEL, " "))
            continue
        result.append(character)
    return "".join(result)


def ordered_segments(
    tokens: tuple[str, ...],
) -> tuple[tuple[tuple[tuple[str, ...], tuple[str, ...]], ...], tuple[str, ...]]:
    segments: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    current: list[str] = []
    pending_controls: list[str] = []
    controls_before: tuple[str, ...] = ()
    for token in tokens:
        if token in CONTROL_TOKENS or _is_unknown_control_token(token):
            if current:
                segments.append((tuple(current), controls_before))
                current = []
                controls_before = ()
            pending_controls.append(token)
            continue
        if not current:
            controls_before = tuple(pending_controls)
            pending_controls = []
        current.append(token)
    if current:
        segments.append((tuple(current), controls_before))
        pending_controls = []
    return tuple(segments), tuple(pending_controls)


def parent_shell_cwd_construct_reason(
    segments: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...],
    trailing_controls: tuple[str, ...],
) -> str | None:
    """Reject parent-shell constructs whose cwd effects cannot be modeled safely."""

    for index, (tokens, _controls_before) in enumerate(segments):
        controls_after = segments[index + 1][1] if index + 1 < len(segments) else trailing_controls
        if _is_function_definition(tokens, controls_after) and _function_body_may_change_cwd(segments, index):
            return SHELL_CWD_UNRESOLVED_PARENT_SHELL
        if _segment_has_unmodeled_parent_cwd_effect(tokens):
            return SHELL_CWD_UNRESOLVED_PARENT_SHELL
    return None


def _is_function_definition(tokens: tuple[str, ...], controls_after: tuple[str, ...]) -> bool:
    if "{" not in controls_after:
        return False
    if len(tokens) >= 2 and tokens[0] == "function":
        return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[1]))
    return (
        len(tokens) == 1
        and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[0]))
        and "(" in controls_after
        and ")" in controls_after
    )


def _function_body_may_change_cwd(
    segments: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...],
    definition_index: int,
) -> bool:
    brace_depth = 0
    for tokens, controls_before in segments[definition_index + 1 :]:
        for control in controls_before:
            if control == "{":
                brace_depth += 1
            elif control == "}":
                brace_depth -= 1
        if brace_depth <= 0:
            return False
        if directory_operation(tokens) is not None or _segment_has_unmodeled_parent_cwd_effect(tokens):
            return True
    return False


def _segment_has_unmodeled_parent_cwd_effect(tokens: tuple[str, ...]) -> bool:
    index = 0
    while index < len(tokens) and _SHELL_ASSIGNMENT.match(tokens[index]):
        index += 1
    if index >= len(tokens):
        return False
    command = tokens[index]
    if command in {".", "eval", "source"}:
        return True
    if command != "trap" or index + 2 >= len(tokens):
        return False
    handler = tokens[index + 1]
    signals = {token.upper().removeprefix("SIG") for token in tokens[index + 2 :]}
    return "DEBUG" in signals and handler not in {"", "-"}


def _is_unknown_control_token(token: str) -> bool:
    return bool(token) and all(character in ";&|(){}" for character in token)


def control_sequence_reason(controls: tuple[str, ...], *, trailing: bool = False) -> str | None:
    if any(control not in CONTROL_TOKENS for control in controls):
        return SHELL_CWD_UNRESOLVED_SYNTAX
    flows: list[str] = []
    for index, control in enumerate(controls):
        if control not in FLOW_OPERATORS:
            continue
        next_control = controls[index + 1] if index + 1 < len(controls) else None
        if next_control in {
            ")",
            "}",
        }:
            if control not in {";", "\n", "&"}:
                return SHELL_CWD_UNRESOLVED_SYNTAX
            continue
        flows.append(control)
    if trailing:
        if not flows:
            return None
        if len(flows) == 1 and flows[0] in {";", "\n", "&"}:
            return None
        return SHELL_CWD_UNRESOLVED_SYNTAX
    if len(flows) > 1:
        return SHELL_CWD_UNRESOLVED_SYNTAX
    return None


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
    if not value or "\x00" in value or value.startswith("~"):
        return True
    return any(character in value for character in ("$", "`", "*", "?", "[", "]", "{", "}", "<", ">"))


def resolve_directory_operand(
    value: str,
    *,
    current_cwd: Path,
    workspace_root: Path,
) -> tuple[Path | None, ShellPathIdentity | None, ShellPathProof | None, str | None]:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = current_cwd / candidate
    lexical_candidate = Path(os.path.abspath(candidate))
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError):
        return None, None, None, SHELL_CWD_MISSING_DIRECTORY
    except (OSError, RuntimeError):
        return None, None, None, SHELL_CWD_UNREADABLE_DIRECTORY
    try:
        value_stat = resolved.stat()
    except OSError:
        return None, None, None, SHELL_CWD_UNREADABLE_DIRECTORY
    if not stat.S_ISDIR(value_stat.st_mode):
        return None, None, None, SHELL_CWD_NOT_DIRECTORY
    if not _directory_is_readable(resolved, value_stat.st_mode):
        return None, None, None, SHELL_CWD_UNREADABLE_DIRECTORY
    if not is_within(resolved, workspace_root):
        reason = (
            SHELL_CWD_SYMLINK_ESCAPE
            if is_within(lexical_candidate, workspace_root)
            and _path_contains_symlink(lexical_candidate, workspace_root=workspace_root)
            else SHELL_CWD_WORKSPACE_ESCAPE
        )
        return None, None, None, reason
    identity = ShellPathIdentity.from_stat(value_stat)
    proof = ShellPathProof(lexical_path=lexical_candidate, resolved_path=resolved, identity=identity)
    return resolved, identity, proof, None


def existing_directory(path: Path) -> tuple[Path | None, ShellPathIdentity | None, str | None]:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError):
        return None, None, SHELL_CWD_MISSING_DIRECTORY
    except (OSError, RuntimeError):
        return None, None, SHELL_CWD_UNREADABLE_DIRECTORY
    try:
        value_stat = resolved.stat()
    except OSError:
        return None, None, SHELL_CWD_UNREADABLE_DIRECTORY
    if not stat.S_ISDIR(value_stat.st_mode):
        return None, None, SHELL_CWD_NOT_DIRECTORY
    if not _directory_is_readable(resolved, value_stat.st_mode):
        return None, None, SHELL_CWD_UNREADABLE_DIRECTORY
    return resolved, ShellPathIdentity.from_stat(value_stat), None


def _directory_is_readable(path: Path, mode: int) -> bool:
    if not (mode & 0o444) or not (mode & 0o111):
        return False
    try:
        return os.access(path, os.R_OK | os.X_OK, effective_ids=True)
    except (NotImplementedError, TypeError):
        return os.access(path, os.R_OK | os.X_OK)


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


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def last_flow_operator(controls: tuple[str, ...]) -> str | None:
    return next((control for control in reversed(controls) if control in FLOW_OPERATORS), None)
