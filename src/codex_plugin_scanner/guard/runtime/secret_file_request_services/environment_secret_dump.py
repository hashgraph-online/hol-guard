"""Detect commands that print process environment secrets to the agent."""

from __future__ import annotations

from pathlib import Path

from ..kubernetes_command_support import (
    interpreter_reads_sensitive_env,
    is_sensitive_env_name,
    script_dumps_process_environment,
    script_reads_sensitive_env,
)
from .constants_patterns import _SHELL_ASSIGNMENT_PATTERN
from .credential_exfiltration import _read_small_runtime_text_file
from .request_models import ToolActionRequestMatch
from .sensitive_read_pipeline import _resolved_runtime_path, _runtime_read_roots
from .shell_static_safety import _is_python_interpreter_command
from .shell_tokenization import (
    _iter_shell_command_segments,
    _shell_segment_primary_command,
    _split_shell_parts,
)

_ACTION_CLASS = "process environment secret read"
_REASON = (
    "Guard treats commands that print process environment secrets as sensitive "
    "because they can expose cloud keys and credentials to the agent."
)
_ENV_DUMP_COMMANDS = frozenset({"printenv", "env"})
_ECHO_COMMANDS = frozenset({"echo", "printf"})
_NODE_COMMANDS = frozenset({"node", "nodejs"})
_ENV_DUMP_FLAGS = frozenset({"-0", "-i", "-u", "--null", "--ignore-environment", "--unset"})


def environment_secret_dump_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    cwd: Path | None,
    home_dir: Path | None,
) -> ToolActionRequestMatch | None:
    parts = _split_shell_parts(command_text)
    if not parts:
        return None
    for segment in _iter_shell_command_segments(parts):
        if _segment_dumps_environment_secrets(segment, cwd=cwd, home_dir=home_dir):
            return ToolActionRequestMatch(
                tool_name=tool_name,
                normalized_tool_name=normalized_tool_name,
                command_text=command_text,
                action_class=_ACTION_CLASS,
                reason=_REASON,
            )
    return None


def _segment_dumps_environment_secrets(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    args = tuple(segment[command_index + 1 :])
    if command_name in _ENV_DUMP_COMMANDS:
        return _env_utility_dumps_secrets(command_name, args)
    if command_name in _ECHO_COMMANDS:
        return script_reads_sensitive_env(" ".join(args))
    if interpreter_reads_sensitive_env(command_name, args):
        return True
    if _is_python_interpreter_command(command_name) or command_name in _NODE_COMMANDS:
        script_text = _local_interpreter_script_text(args, cwd=cwd, home_dir=home_dir)
        if script_text is not None and (
            script_dumps_process_environment(script_text) or script_reads_sensitive_env(script_text)
        ):
            return True
    return False


def _env_utility_dumps_secrets(command_name: str, args: tuple[str, ...]) -> bool:
    leftover: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"-u", "--unset"} and index + 1 < len(args):
            index += 2
            continue
        if token.startswith("--unset="):
            index += 1
            continue
        if token in _ENV_DUMP_FLAGS or token.startswith("-"):
            index += 1
            continue
        if _SHELL_ASSIGNMENT_PATTERN.match(token):
            index += 1
            continue
        leftover.append(token)
        index += 1
    if command_name == "printenv":
        return not leftover or any(is_sensitive_env_name(name) for name in leftover)
    return not leftover


def _local_interpreter_script_text(
    args: tuple[str, ...],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> str | None:
    script_path = _interpreter_file_operand(args)
    if script_path is None:
        return None
    read_roots = _runtime_read_roots(cwd, home_dir)
    resolved = _resolved_runtime_path(script_path, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
    if resolved is None:
        return None
    return _read_small_runtime_text_file(resolved, allowed_roots=read_roots)


def _interpreter_file_operand(args: tuple[str, ...]) -> str | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"-c", "-e"}:
            return None
        if token.startswith("-c") or token.startswith("-e"):
            return None
        if token in {"-m"}:
            return None
        if token.startswith("-"):
            index += 1
            continue
        return token
    return None


__all__ = ["environment_secret_dump_request"]
