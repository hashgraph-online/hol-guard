"""Side-effect-free shell token and transparent wrapper parsing."""

from __future__ import annotations

import os
import re
import shlex

from .env_wrapper import parse_env_wrapper

_ENV_ASSIGNMENT_PATTERN = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=.*$", re.DOTALL)
_SUDO_OPTIONS_WITH_VALUES = frozenset({"-C", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-u"})
_SUDO_LONG_OPTIONS_WITH_VALUES = frozenset(
    {
        "--chdir",
        "--chroot",
        "--close-from",
        "--command-timeout",
        "--group",
        "--host",
        "--login-class",
        "--prompt",
        "--role",
        "--type",
        "--user",
    }
)


def executable_name(value: str | None) -> str | None:
    """Return a normalized executable basename."""

    if value is None:
        return None
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _windows_shell_tokens(command: str) -> tuple[str, ...]:
    """Keep unquoted Windows path separators and quoted POSIX escapes."""

    tokens: list[str] = []
    token: list[str] = []
    started = False
    quote = ""
    escaped = False
    for current in command:
        if escaped:
            if quote == '"' and current not in {'"', "\\", "$", "`"}:
                token.append("\\")
            token.append(current)
            started = True
            escaped = False
            continue
        if quote == "'":
            if current == "'":
                quote = ""
            else:
                token.append(current)
                started = True
            continue
        if quote == '"':
            if current == '"':
                quote = ""
            elif current == "\\":
                escaped = True
                started = True
            else:
                token.append(current)
                started = True
            continue
        if current == "'":
            quote = "'"
            started = True
        elif current == '"':
            quote = '"'
            started = True
        elif current == "\\":
            token.append("\\")
            started = True
        elif current in " \t\r\n":
            if started:
                tokens.append("".join(token))
                token = []
                started = False
        else:
            token.append(current)
            started = True
    if quote or escaped:
        raise ValueError("malformed shell quoting")
    if started:
        tokens.append("".join(token))
    return tuple(tokens)


def shell_tokens(command: str) -> tuple[tuple[str, ...], bool]:
    """Tokenize shell text, reporting whether strict parsing succeeded."""

    try:
        if os.name == "nt":
            return _windows_shell_tokens(command), True
        return tuple(shlex.split(command, posix=True, comments=False)), True
    except ValueError:
        return tuple(command.split()), False


def leading_environment(tokens: tuple[str, ...]) -> tuple[tuple[str, ...], int, tuple[str, ...]]:
    """Return leading environment names, executable index, and wrappers."""

    names: list[str] = []
    wrappers: list[str] = []
    index = 0
    while index < len(tokens):
        match = _ENV_ASSIGNMENT_PATTERN.fullmatch(tokens[index])
        while match is not None:
            names.append(match.group("name"))
            index += 1
            if index >= len(tokens):
                return tuple(names), index, tuple(wrappers)
            match = _ENV_ASSIGNMENT_PATTERN.fullmatch(tokens[index])
        executable = executable_name(tokens[index])
        if executable == "env":
            parsed = parse_env_wrapper(tokens[index + 1 :])
            if parsed.complete and parsed.command_index is None:
                break
            wrappers.append("env")
            names.extend(name for name, _value in parsed.environment_delta.assignments)
            if not parsed.complete or parsed.command_index is None or parsed.split_expansions:
                return tuple(names), len(tokens), tuple(wrappers)
            index += parsed.command_index + 1
            continue
        if executable == "sudo":
            wrappers.append("sudo")
            index = _after_sudo_options(tokens, index + 1)
            continue
        break
    return tuple(names), index, tuple(wrappers)


def _after_sudo_options(tokens: tuple[str, ...], index: int) -> int:
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        option_name = token.split("=", 1)[0]
        if option_name in _SUDO_OPTIONS_WITH_VALUES or option_name in _SUDO_LONG_OPTIONS_WITH_VALUES:
            index += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _ENV_ASSIGNMENT_PATTERN.fullmatch(token) is not None:
            return index
        return index
    return index
