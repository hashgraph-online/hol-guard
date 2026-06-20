"""Detect Guard approval mutation attempts from agent-controlled shells."""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from pathlib import Path

SELF_APPROVAL_ACTION_CLASS = "Guard approval self-authorization command"
SELF_APPROVAL_REASON = (
    "Guard blocks AI agents from approving or weakening Guard approval state from inside a protected shell. "
    "Review the original request in the local approval center or native harness prompt."
)

_APPROVAL_ROOTS = frozenset({"approvals", "requests"})
_APPROVAL_MUTATION_COMMANDS = frozenset({"approve", "allow", "deny", "block", "clear-history", "unlock"})
_GUARD_BINARIES = frozenset({"hol-guard", "plugin-guard"})
_PYTHON_MODULES = frozenset({"codex_plugin_scanner", "codex_plugin_scanner.cli"})
_PYTHON_OPTIONS_WITH_VALUES = frozenset({"-W", "-X", "--check-hash-based-pycs"})
_RUN_WRAPPERS = frozenset({"hatch", "mise", "nix", "pipx", "poetry", "uv", "uvx"})
_SHELL_SEPARATORS = frozenset({";", "&&", "||", "|", "|&", "&"})
_AGENT_ENV_MARKERS = frozenset(
    {
        "HOL_GUARD_HOOK_ARGV",
        "HOL_GUARD_MANAGED_CURSOR_HOOK",
        "HOL_GUARD_CURSOR_APPROVAL_BINDING",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
        "CURSOR_SESSION_ID",
        "CURSOR_TRACE_ID",
        "CURSOR_TRANSCRIPT_PATH",
        "CLAUDECODE",
        "OPENCODE_CONFIG_CONTENT",
        "CODEX_SANDBOX",
    }
)


def is_guard_approval_mutation_command(command_text: str) -> bool:
    """Return True for commands that let an agent mutate Guard approval state."""

    parts = _split_shell_parts(command_text)
    if not parts:
        return False
    return any(_segment_is_guard_approval_mutation(segment) for segment in _shell_segments(parts))


def approval_resolution_invoked_from_agent(env: Mapping[str, str] | None = None) -> bool:
    """Detect known AI harness hook contexts for approval CLI mutation defense-in-depth."""

    source = env if env is not None else os.environ
    return any(str(source.get(key) or "").strip() for key in _AGENT_ENV_MARKERS)


def _split_shell_parts(command_text: str) -> list[str]:
    try:
        lexer = shlex.shlex(command_text.replace("\n", " ; "), posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command_text.split()


def _shell_segments(parts: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for part in parts:
        if part in _SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(part)
    if current:
        segments.append(current)
    return segments


def _segment_is_guard_approval_mutation(segment: list[str], *, depth: int = 0) -> bool:
    if depth > 3:
        return False
    index = _first_executable_index(segment)
    if index is None:
        return False
    command_name = Path(segment[index]).name.lower()
    if command_name in _GUARD_BINARIES:
        return _guard_args_mutate_approvals(segment[index + 1 :])
    if _is_python_interpreter(command_name):
        return _python_module_args_mutate_approvals(segment[index + 1 :])
    wrapper_tail = _runner_wrapper_tail(command_name, segment[index + 1 :])
    if wrapper_tail is not None:
        return _segment_is_guard_approval_mutation(wrapper_tail, depth=depth + 1)
    return False


def _first_executable_index(segment: list[str]) -> int | None:
    for index, token in enumerate(segment):
        if not token or _looks_env_assignment(token):
            continue
        return index
    return None


def _looks_env_assignment(token: str) -> bool:
    name, separator, _ = token.partition("=")
    if separator != "=" or not name:
        return False
    if name.endswith("+"):
        name = name[:-1]
    return bool(name) and (name[0].isalpha() or name[0] == "_") and all(
        character.isalnum() or character == "_" for character in name[1:]
    )


def _is_python_interpreter(command_name: str) -> bool:
    return (
        command_name in {"python", "py"}
        or command_name.startswith("python")
        or command_name.startswith("py3")
    )


def _python_module_args_mutate_approvals(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "-m" and index + 1 < len(args):
            module_name = args[index + 1].strip()
            if module_name in _PYTHON_MODULES:
                return _guard_args_mutate_approvals(args[index + 2 :])
            return False
        if token == "-c":
            return False
        if token in _PYTHON_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(token.startswith(f"{option}=") for option in _PYTHON_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return False
    return False


def _runner_wrapper_tail(command_name: str, args: list[str]) -> list[str] | None:
    if command_name not in _RUN_WRAPPERS:
        return None
    if command_name == "uv":
        if args and args[0] == "tool":
            return _tail_after_subcommand(args[1:], {"run"})
        return _tail_after_subcommand(args, {"run"})
    if command_name == "uvx":
        return args
    if command_name in {"pipx", "poetry", "hatch"}:
        return _tail_after_subcommand(args, {"run"})
    if command_name == "mise":
        return _tail_after_subcommand(args, {"exec"})
    if command_name == "nix":
        return _tail_after_flag(args, "--command")
    return None


def _tail_after_subcommand(args: list[str], subcommands: set[str]) -> list[str] | None:
    for index, token in enumerate(args):
        if token == "--":
            break
        if token in subcommands:
            tail = args[index + 1 :]
            if tail and tail[0] == "--":
                tail = tail[1:]
            return tail
    return None


def _tail_after_flag(args: list[str], flag: str) -> list[str] | None:
    for index, token in enumerate(args):
        if token == flag:
            remaining = args[index + 1 :]
            if not remaining:
                return []
            try:
                return shlex.split(" ".join(remaining))
            except ValueError:
                return remaining
        if token.startswith(f"{flag}="):
            try:
                return shlex.split(token.split("=", 1)[1])
            except ValueError:
                return []
    return None


def _guard_args_mutate_approvals(args: list[str]) -> bool:
    if args and args[0] == "guard":
        args = args[1:]
    for index, token in enumerate(args):
        if token not in _APPROVAL_ROOTS:
            continue
        return _approval_tail_has_mutation(args[index + 1 :])
    return False


def _approval_tail_has_mutation(args: list[str]) -> bool:
    for token in args:
        if token.startswith("-"):
            continue
        return token in _APPROVAL_MUTATION_COMMANDS
    return False


__all__ = [
    "SELF_APPROVAL_ACTION_CLASS",
    "SELF_APPROVAL_REASON",
    "approval_resolution_invoked_from_agent",
    "is_guard_approval_mutation_command",
]
