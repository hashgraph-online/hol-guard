"""Interpreter option DTOs projected from the native shell owner."""

from __future__ import annotations

from dataclasses import dataclass

from ..native_shell_helpers import call


@dataclass(frozen=True, slots=True)
class InterpreterFlagPayload:
    """An inline program plus its native-computed argv span."""

    script_text: str
    tokens_consumed: int


def shell_interpreter_command_payload(parts: list[str], command_index: int) -> InterpreterFlagPayload | None:
    result = call("interpreter_payload", "", parts=parts, command_index=command_index)
    return InterpreterFlagPayload(**result) if result is not None else None
