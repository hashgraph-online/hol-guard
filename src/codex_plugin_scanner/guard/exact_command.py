"""Versioned selectors over complete command bytes from supported shell inputs."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

EXACT_COMMAND_CONTRACT = "guard.exact-command.v1"
EXACT_COMMAND_MAX_BYTES = 32768
EXACT_COMMAND_BLANK_CODEPOINTS = (
    *range(0x09, 0x0E),
    *range(0x1C, 0x21),
    0x85,
    0xA0,
    0x1680,
    *range(0x2000, 0x200B),
    0x2028,
    0x2029,
    0x202F,
    0x205F,
    0x3000,
)
_BLANK = "".join(map(chr, EXACT_COMMAND_BLANK_CODEPOINTS))
_COMMAND_KEYS = frozenset({"command", "cmd", "shell_command", "shellCommand"})
_SHELL_TOOLS = frozenset({"bash", "shell", "terminal", "exec_command"})
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)


def valid_exact_command_text(value: object) -> str | None:
    """Check completeness bounds without normalizing any accepted byte."""
    if not isinstance(value, str) or not value.strip(_BLANK) or "\x00" in value:
        return None
    try:
        return value if len(value.encode("utf-8")) <= EXACT_COMMAND_MAX_BYTES else None
    except UnicodeEncodeError:
        return None


def exact_shell_command_text(tool_name: object, arguments: object) -> str | None:
    """Read one explicit command field; never synthesize or unwrap a command."""
    if not isinstance(tool_name, str) or not tool_name.isascii() or tool_name.lower() not in _SHELL_TOOLS:
        return None
    if not isinstance(arguments, Mapping):
        return None
    present = _COMMAND_KEYS.intersection(arguments)
    return valid_exact_command_text(arguments[next(iter(present))]) if len(present) == 1 else None


def exact_command_sha256(command: object) -> str | None:
    exact = valid_exact_command_text(command)
    return hashlib.sha256(exact.encode("utf-8")).hexdigest() if exact is not None else None


def validate_exact_command_selector(value: object) -> str:
    """Return a strict selector digest or reject the entire unsupported selector."""
    if not isinstance(value, Mapping) or set(value) != {"contractVersion", "sha256"}:
        raise ValueError("invalid_exact_command_selector")
    digest = value.get("sha256")
    if (
        value.get("contractVersion") != EXACT_COMMAND_CONTRACT
        or not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
    ):
        raise ValueError("invalid_exact_command_selector")
    return digest


def exact_shell_command_from_hook(payload: Mapping[str, object]) -> str | None:
    """Select unambiguous shell arguments from the actual hook input object."""
    tools = [payload[key] for key in ("tool_name", "toolName") if key in payload]
    arguments = [payload[key] for key in ("tool_input", "arguments", "tool_args", "toolArgs") if key in payload]
    return exact_shell_command_text(tools[0], arguments[0]) if len(tools) == len(arguments) == 1 else None
