"""Shell tokenization, wrapper, and redirection parsing."""

from __future__ import annotations

import re
import shlex

from ..env_wrapper import parse_env_wrapper
from .constants_core import (
    _DOCKER_BUILD_METADATA_FLAGS,
    _DOCKER_BUILD_SECRET_FLAGS,
    _DOCKER_GLOBAL_FLAG_OPTIONS,
    _DOCKER_GLOBAL_OPTIONS_WITH_VALUES,
)
from .constants_patterns import (
    _SHELL_ASSIGNMENT_PATTERN,
    _SHELL_COMMAND_SEPARATORS,
    _SHELL_COMMAND_WRAPPERS,
    _SHELL_NEWLINE_SEPARATOR,
    _WRAPPER_FLAGS_WITH_VALUES,
)
from .request_artifacts import (
    _docker_build_arg_is_sensitive,
    _docker_build_arg_value_is_sensitive,
    _docker_build_output_flag_matches,
    _normalized_shell_command_name,
)

_SHELL_NOCLOBBER_SENTINEL = "__HOL_GUARD_NOCLOBBER_REDIRECT__"


def _stdin_redirect_target_from_token(token: str, *, next_token: str | None) -> tuple[str | None, int]:
    if _token_is_heredoc_operator(token):
        return None, 1
    if token in {"<", "0<"}:
        if next_token is None:
            return None, 1
        return next_token, 2
    if token.count("<") != 1:
        return None, 1
    fd, target = token.split("<", 1)
    if fd not in {"", "0"} or not target:
        return None, 1
    return target, 1


def _token_is_heredoc_operator(token: str) -> bool:
    return "<<" in token


def _docker_subcommand_help_requested(args: list[str]) -> bool:
    for index, token in enumerate(args[1:], start=1):
        if token != "--help":
            continue
        return all(previous.startswith("-") for previous in args[1:index])
    return False


def _docker_subcommand_index(args: list[str]) -> int | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return index + 1 if index + 1 < len(args) else None
        if _docker_global_option_has_value(token):
            index += 1 if "=" in token else 2
            continue
        if _docker_global_flag_option_matches(token):
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--"):
            index += 1
            continue
        return index
    return None


def _docker_global_option_has_value(token: str) -> bool:
    # Accept both long attached values like --host=... and short forms like -H=....
    return token in _DOCKER_GLOBAL_OPTIONS_WITH_VALUES or any(
        token.startswith(f"{option}=") for option in _DOCKER_GLOBAL_OPTIONS_WITH_VALUES
    )


def _docker_global_flag_option_matches(token: str) -> bool:
    return token in _DOCKER_GLOBAL_FLAG_OPTIONS or any(
        token.startswith(f"{option}=") for option in _DOCKER_GLOBAL_FLAG_OPTIONS
    )


def _docker_attached_short_context_option(token: str) -> tuple[str, str] | None:
    for flag in ("-c", "-H"):
        if token.startswith(flag) and token not in {flag, f"{flag}="}:
            value = token[len(flag) :]
            if value.startswith("="):
                value = value[1:]
            return flag, value
    return None


def _docker_build_args_are_sensitive(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return False
        if token in _DOCKER_BUILD_SECRET_FLAGS or any(
            token.startswith(f"{flag}=") for flag in _DOCKER_BUILD_SECRET_FLAGS
        ):
            return True
        if _docker_build_output_flag_matches(token):
            return True
        if token == "--build-arg":
            value = args[index + 1] if index + 1 < len(args) else ""
            if _docker_build_arg_is_sensitive(value):
                return True
            index += 2
            continue
        if token.startswith("--build-arg=") and _docker_build_arg_is_sensitive(token.split("=", 1)[1]):
            return True
        if token in _DOCKER_BUILD_METADATA_FLAGS:
            value = args[index + 1] if index + 1 < len(args) else ""
            if _docker_build_metadata_value_is_sensitive(value):
                return True
            index += 2
            continue
        if token.startswith("--") and "=" in token:
            flag, value = token.split("=", 1)
            if flag in _DOCKER_BUILD_METADATA_FLAGS and _docker_build_metadata_value_is_sensitive(value):
                return True
        index += 1
    return False


def _docker_build_metadata_value_is_sensitive(value: str) -> bool:
    key, separator, assigned_value = value.partition("=")
    if not separator:
        return _docker_build_arg_value_is_sensitive(value.strip())
    return _docker_build_arg_value_is_sensitive(key.strip()) or _docker_build_arg_value_is_sensitive(
        assigned_value.strip()
    )


def _iter_shell_command_segments(parts: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current_segment: list[str] = []
    for part in parts:
        token = part.strip()
        if not token:
            continue
        if token in _SHELL_COMMAND_SEPARATORS:
            if current_segment:
                segments.append(current_segment)
                current_segment = []
            continue
        current_segment.append(token)
    if current_segment:
        segments.append(current_segment)
    return segments


def _shell_segment_primary_command(segment: list[str]) -> tuple[str | None, int | None]:
    index = 0
    while index < len(segment):
        redirect_tokens_consumed = _leading_shell_redirection_tokens_consumed(
            segment,
            index,
        )
        if redirect_tokens_consumed > 0:
            index += redirect_tokens_consumed
            continue
        normalized_token = _shell_command_token_without_attached_redirection(segment[index])
        if _SHELL_ASSIGNMENT_PATTERN.match(normalized_token):
            index += 1
            continue
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name == "env":
            parsed = parse_env_wrapper(segment[index + 1 :])
            command_index = parsed.command_index
            if parsed.complete and command_index is None:
                return command_name, index
            if not parsed.complete or parsed.split_expansions or command_index is None:
                return None, None
            index += command_index + 1
            continue
        if command_name in _SHELL_COMMAND_WRAPPERS:
            index += 1
            while index < len(segment):
                token = segment[index]
                if not token.startswith("-"):
                    break
                index += _wrapper_option_tokens_consumed(command_name, token)
            continue
        return command_name, index
    return None, None


def _leading_shell_redirection_tokens_consumed(segment: list[str], index: int) -> int:
    token = segment[index]
    redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
        token,
        next_token=segment[index + 1] if index + 1 < len(segment) else None,
    )
    if redirect_target is not None:
        return tokens_consumed
    if token in {"<<", "<<-", "<<<"}:
        return 2 if index + 1 < len(segment) else 1
    if token in {">", ">>", ">|", "0>", "0>>", "0>|", "1>", "1>>", "1>|", "2>", "2>>", "2>|"}:
        return 2 if index + 1 < len(segment) else 1
    if re.fullmatch(r"(?P<fd>[0-2]?)(?P<op>>\||>>|>)(?P<target>.+)", token):
        return 1
    return 0


def _shell_command_token_without_attached_redirection(token: str) -> str:
    normalized_token = token.lstrip("(").rstrip(")")
    for index, character in enumerate(normalized_token):
        if index == 0 or character not in {"<", ">"}:
            continue
        return normalized_token[:index]
    return normalized_token


def _split_shell_parts(command_text: str) -> list[str]:
    try:
        protected_command = _protect_unquoted_noclobber_redirects(
            _replace_unquoted_newlines_with_separators(command_text)
        )
        lexer = shlex.shlex(
            protected_command,
            posix=True,
            punctuation_chars=";&|",
        )
        lexer.whitespace_split = True
        parts = [token.replace(_SHELL_NOCLOBBER_SENTINEL, ">|") for token in lexer]
    except ValueError:
        parts = command_text.split()
    return _merge_shell_fd_redirect_parts(parts)


def _protect_unquoted_noclobber_redirects(command_text: str) -> str:
    result: list[str] = []
    quote_char: str | None = None
    escape_next = False
    index = 0
    while index < len(command_text):
        character = command_text[index]
        if escape_next:
            result.append(character)
            escape_next = False
            index += 1
            continue
        if character == "\\":
            result.append(character)
            escape_next = True
            index += 1
            continue
        if quote_char is None and character in {"'", '"', "`"}:
            quote_char = character
        elif quote_char == character:
            quote_char = None
        if quote_char is None and command_text.startswith(">|", index):
            result.append(_SHELL_NOCLOBBER_SENTINEL)
            index += 2
            continue
        result.append(character)
        index += 1
    return "".join(result)


def _merge_shell_fd_redirect_parts(parts: list[str]) -> list[str]:
    merged: list[str] = []
    index = 0
    while index < len(parts):
        token = parts[index]
        if index + 2 < len(parts) and re.fullmatch(r"[012]?>", token) and parts[index + 1] == "&":
            fd_prefix = token[:-1]
            redirect_target = parts[index + 2]
            merged.append(f"{fd_prefix}>&{redirect_target}" if fd_prefix else f">&{redirect_target}")
            index += 3
            continue
        merged.append(token)
        index += 1
    return merged


def _replace_unquoted_newlines_with_separators(command_text: str) -> str:
    result: list[str] = []
    quote_char: str | None = None
    escape_next = False
    for character in command_text:
        if escape_next:
            result.append(character)
            escape_next = False
            continue
        if character == "\\":
            result.append(character)
            escape_next = True
            continue
        if quote_char is None and character in {"'", '"', "`"}:
            quote_char = character
            result.append(character)
            continue
        if quote_char == character:
            quote_char = None
            result.append(character)
            continue
        if quote_char is None and character in {"\n", "\r"}:
            if not result or result[-1] != " ":
                result.append(" ")
            result.append("\n")
            result.append(_SHELL_NEWLINE_SEPARATOR)
            result.append("\n")
            continue
        result.append(character)
    return "".join(result)


def _wrapper_option_tokens_consumed(command_name: str, token: str) -> int:
    if not token.startswith("-"):
        return 1
    if command_name == "sudo":
        sudo_short_option_tokens = _sudo_short_option_tokens_consumed(token)
        if sudo_short_option_tokens is not None:
            return sudo_short_option_tokens
    exact_flags = _WRAPPER_FLAGS_WITH_VALUES.get(command_name, frozenset())
    if token in exact_flags:
        return 2
    if _wrapper_flag_has_attached_value(command_name, token):
        return 1
    return 1


def _sudo_short_option_tokens_consumed(token: str) -> int | None:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    for index, flag_character in enumerate(token[1:], start=1):
        if flag_character not in {"C", "D", "R", "T", "g", "h", "p", "r", "t", "u"}:
            continue
        if index < len(token) - 1:
            return 1
        return 2
    return 1


def _wrapper_flag_has_attached_value(command_name: str, token: str) -> bool:
    if command_name == "nice":
        return token.startswith("--adjustment=") or (token.startswith("-n") and token != "-n")
    if command_name == "stdbuf":
        return token.startswith(("--input=", "--output=", "--error=")) or (
            len(token) > 2 and token[:2] in {"-i", "-o", "-e"}
        )
    if command_name == "sudo":
        return token.startswith(
            (
                "--chdir=",
                "--chroot=",
                "--close-from=",
                "--command-timeout=",
                "--group=",
                "--host=",
                "--prompt=",
                "--role=",
                "--type=",
                "--user=",
            )
        ) or _sudo_short_option_has_attached_value(token)
    if command_name == "time":
        return token.startswith(("--format=", "--output=")) or (len(token) > 2 and token[:2] in {"-f", "-o"})
    return False


def _sudo_short_option_has_attached_value(token: str) -> bool:
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return False
    for index, flag_character in enumerate(token[1:], start=1):
        if flag_character not in {"C", "D", "R", "T", "g", "h", "p", "r", "t", "u"}:
            continue
        return index < len(token) - 1
    return False


__all__ = [
    "_docker_attached_short_context_option",
    "_docker_build_args_are_sensitive",
    "_docker_build_metadata_value_is_sensitive",
    "_docker_global_flag_option_matches",
    "_docker_global_option_has_value",
    "_docker_subcommand_help_requested",
    "_docker_subcommand_index",
    "_iter_shell_command_segments",
    "_leading_shell_redirection_tokens_consumed",
    "_merge_shell_fd_redirect_parts",
    "_replace_unquoted_newlines_with_separators",
    "_shell_command_token_without_attached_redirection",
    "_shell_segment_primary_command",
    "_split_shell_parts",
    "_stdin_redirect_target_from_token",
    "_sudo_short_option_has_attached_value",
    "_sudo_short_option_tokens_consumed",
    "_token_is_heredoc_operator",
    "_wrapper_flag_has_attached_value",
    "_wrapper_option_tokens_consumed",
]
