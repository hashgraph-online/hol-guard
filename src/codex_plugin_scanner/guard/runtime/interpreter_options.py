"""Interpreter invocation option parsing used by Guard runtime detectors."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InterpreterFlagPayload:
    """An inline program plus the exact option/program argv span it consumed."""

    script_text: str
    tokens_consumed: int


_LONG_OPTIONS_WITH_VALUES = frozenset({"--init-file", "--rcfile"})


def shell_interpreter_command_payload(
    parts: list[str],
    command_index: int,
) -> InterpreterFlagPayload | None:
    """Parse one shell invocation and return its command-string operand."""

    index = command_index + 1
    while index < len(parts):
        token = parts[index].strip().lstrip("(").rstrip(")")
        if not token:
            index += 1
            continue
        if token in {"-", "--"}:
            return None
        if token.startswith("--"):
            option_name, separator, _ = token.partition("=")
            if option_name in _LONG_OPTIONS_WITH_VALUES and not separator:
                index += 2
            else:
                index += 1
            continue
        if not token.startswith(("-", "+")):
            return None

        has_command_flag, consumes_next_value = _short_shell_option_cluster(token)
        script_index = index + 1 + int(consumes_next_value)
        if has_command_flag:
            if script_index >= len(parts):
                return None
            script_text = parts[script_index].strip()
            if not script_text:
                return None
            return InterpreterFlagPayload(
                script_text=script_text,
                tokens_consumed=script_index - command_index,
            )
        index += 1 + int(consumes_next_value)
    return None


def _short_shell_option_cluster(token: str) -> tuple[bool, bool]:
    flag_text = token[1:]
    if not flag_text or not flag_text.isalpha():
        return False, False
    has_command_flag = False
    for flag_index, flag_name in enumerate(flag_text):
        if flag_name in {"O", "o"}:
            return has_command_flag, flag_index == len(flag_text) - 1
        if token.startswith("-") and flag_name == "c":
            has_command_flag = True
    return has_command_flag, False
