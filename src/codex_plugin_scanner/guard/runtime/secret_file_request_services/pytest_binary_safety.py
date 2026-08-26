"""Pytest binary and environment wrapper safety."""

from __future__ import annotations

import shlex
from pathlib import Path

from ..data_flow import extract_heredocs
from ..env_wrapper import parse_env_wrapper
from .constants_core import (
    _PYTEST_UNSAFE_ENV_KEYS,
    _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES,
    _READ_ONLY_LOOKUP_FILTERS,
    _SAFE_STATIC_SHELL_COMMANDS,
)
from .developer_inspection import _static_shell_segment_is_safe
from .interpreter_observers import (
    _python_module_may_be_shadowed,
    _shell_env_assignment_key,
    _shell_segment_sets_env_key,
)
from .pytest_config_safety import (
    _pytest_config_may_add_unsafe_options,
    _pytest_module_args_are_safe,
    _python_module_may_be_shadowed_from_execution_context,
    _python_module_root_from_args,
    _python_module_unsafe_env_keys,
    _python_segment_runs_safe_module,
    _shell_args_without_trailing_redirections,
)
from .pytest_target_detection import _segment_targets_pytest
from .python_pytest_entrypoints import _python_segment_targets_module
from .read_only_filters import _read_only_lookup_filter_segment_is_safe
from .request_artifacts import _normalized_shell_command_name
from .shell_static_safety import _is_python_interpreter_command, _shell_token_has_command_substitution
from .shell_tokenization import (
    _iter_shell_command_segments,
    _shell_command_token_without_attached_redirection,
    _shell_segment_primary_command,
    _wrapper_option_tokens_consumed,
)


def _is_literal_cat_heredoc_to_stdout(command_text: str) -> bool:
    heredocs = extract_heredocs(command_text)
    if len(heredocs) != 1:
        return False
    heredoc = heredocs[0]
    if command_text[heredoc.end :].strip():
        return False
    line_start = command_text.rfind("\n", 0, heredoc.operator_start) + 1
    header = (
        command_text[line_start : heredoc.operator_start] + command_text[heredoc.declaration_end : heredoc.body_start]
    )
    try:
        tokens = shlex.split(header, posix=True, comments=False)
    except ValueError:
        return False
    return tokens in (["cat"], ["cat", "-"])


def _looks_like_safe_python_module_invocation(parts: list[str], *, cwd: Path | None = None) -> bool:
    segments = _iter_shell_command_segments(parts)
    if not segments:
        return False
    saw_python_module = False
    for segment in segments:
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            return False
        segment_args = segment[command_index + 1 :]
        if _is_python_interpreter_command(command_name):
            module_root = _python_module_root_from_args(segment_args)
            unsafe_env_keys = _python_module_unsafe_env_keys(module_root)
            if any(_shell_segment_sets_env_key(segment, command_index, env_key) for env_key in unsafe_env_keys):
                return False
            if _shell_segment_uses_env_split_string_wrapper(segment, command_index):
                return False
            if _shell_segment_uses_cwd_changing_wrapper(segment, command_index):
                return False
            if _python_module_may_be_shadowed_from_execution_context(
                module_root,
                cwd=cwd,
                segment=segment,
                command_index=command_index,
            ):
                return False
            if not _python_segment_runs_safe_module(segment_args, cwd=cwd):
                return False
            saw_python_module = True
            continue
        if _shell_directory_setup_segment_is_safe(command_name, segment_args):
            continue
        if command_name in _READ_ONLY_LOOKUP_FILTERS and _read_only_lookup_filter_segment_is_safe(
            command_name,
            segment_args,
        ):
            continue
        if command_name in _SAFE_STATIC_SHELL_COMMANDS and _static_shell_segment_is_safe(segment_args):
            continue
        return False
    return saw_python_module


def _looks_like_bounded_python_script_invocation(parts: list[str], *, cwd: Path | None = None) -> bool:
    """Exclude ordinary workspace scripts from the destructive-shell category."""

    if cwd is None:
        return False
    segments = _iter_shell_command_segments(parts)
    if not segments:
        return False
    saw_script = False
    for segment in segments:
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            return False
        segment_args = segment[command_index + 1 :]
        if _is_python_interpreter_command(command_name):
            if saw_script or _bounded_python_script_path(segment_args, cwd=cwd) is None:
                return False
            saw_script = True
            continue
        if _shell_directory_setup_segment_is_safe(command_name, segment_args):
            continue
        return False
    return saw_script


def _looks_like_supported_python_invocation(parts: list[str], *, cwd: Path | None = None) -> bool:
    return _looks_like_bounded_python_script_invocation(parts, cwd=cwd) or _looks_like_safe_python_module_invocation(
        parts, cwd=cwd
    )


def _bounded_python_script_path(args: list[str], *, cwd: Path) -> Path | None:
    args = _shell_args_without_trailing_redirections(args)
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if arg in {"-c", "--command", "-m"} or arg.startswith(("-c", "--command=", "-m")):
            return None
        if arg in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES:
            index += 2
            continue
        if any(arg.startswith(option) and len(arg) > len(option) for option in _PYTHON_INTERPRETER_OPTIONS_WITH_VALUES):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        break
    if index >= len(args):
        return None
    operand = args[index]
    if operand == "-" or not operand.endswith(".py") or _shell_token_has_command_substitution(operand):
        return None
    candidate = Path(operand).expanduser()
    if not candidate.is_absolute():
        candidate = cwd / candidate
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(cwd.resolve(strict=True))
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None


def _contains_unsafe_pytest_environment_wrapper(parts: list[str], *, cwd: Path | None) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if not _shell_segment_uses_cwd_changing_wrapper(segment, command_index):
            continue
        if command_name == "pytest":
            if not _pytest_binary_segment_is_safe(segment[command_index], segment[command_index + 1 :], cwd=cwd):
                return True
            return True
        if _is_python_interpreter_command(command_name) and _python_segment_targets_module(
            segment[command_index + 1 :],
            "pytest",
        ):
            if not _python_segment_runs_safe_module(segment[command_index + 1 :], cwd=cwd):
                return True
            return True
    return False


def _contains_pytest_process_substitution(command_text: str, parts: list[str]) -> bool:
    if "<(" not in command_text and ">(" not in command_text:
        return False
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if _segment_targets_pytest(segment, command_name, command_index):
            return True
    return False


def _contains_prior_pytest_state_mutation(parts: list[str]) -> bool:
    saw_state_mutation = False
    exported_pytest_env_keys: set[str] = set()
    for segment in _iter_shell_command_segments(parts):
        if any(
            _shell_env_assignment_key(token) == "PATH" or _shell_env_assignment_key(token) in exported_pytest_env_keys
            for token in segment
            if _shell_env_assignment_key(token) is not None
        ):
            saw_state_mutation = True
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if _segment_targets_pytest(segment, command_name, command_index):
            return saw_state_mutation
        if command_name in {"cd", "pushd", "popd"}:
            if not _shell_directory_setup_segment_is_safe(command_name, segment[command_index + 1 :]):
                saw_state_mutation = True
            continue
        if command_name == "set" and _shell_set_exports_assignments(segment[command_index + 1 :]):
            saw_state_mutation = True
            continue
        if command_name == "export":
            for token in segment[command_index + 1 :]:
                env_key = _shell_declared_env_key(token)
                if env_key not in {"PATH", *_PYTEST_UNSAFE_ENV_KEYS}:
                    continue
                exported_pytest_env_keys.add(env_key)
                if "=" in token:
                    saw_state_mutation = True
        if command_name in {"declare", "typeset"} and _shell_declaration_exports_env(segment[command_index + 1 :]):
            for token in segment[command_index + 1 :]:
                if token.startswith("-") or token == "--":
                    continue
                env_key = _shell_declared_env_key(token)
                if env_key not in {"PATH", *_PYTEST_UNSAFE_ENV_KEYS}:
                    continue
                exported_pytest_env_keys.add(env_key)
                if "=" in token:
                    saw_state_mutation = True
    return False


def _shell_declared_env_key(token: str) -> str:
    assignment_key = _shell_env_assignment_key(token)
    if assignment_key is not None:
        return assignment_key
    return token.upper()


def _shell_declaration_exports_env(args: list[str]) -> bool:
    for token in args:
        if token == "--":
            return False
        if not token.startswith("-"):
            continue
        if token.startswith("+"):
            continue
        if "x" in token.lstrip("-"):
            return True
    return False


def _shell_set_exports_assignments(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return False
        if token in {"-a", "-k", "allexport", "keyword"}:
            return True
        if token == "-o":
            return index + 1 < len(args) and args[index + 1] in {"allexport", "keyword"}
        if token == "+o":
            index += 2
            continue
        if token.startswith("-") and not token.startswith("--") and any(flag in token[1:] for flag in {"a", "k"}):
            return True
        index += 1
    return False


def _looks_like_safe_pytest_binary_invocation(parts: list[str], *, cwd: Path | None) -> bool:
    saw_pytest = False
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            return False
        segment_args = segment[command_index + 1 :]
        if command_name == "pytest":
            if _shell_segment_sets_env_key(segment, command_index, "PATH"):
                return False
            if any(_shell_segment_sets_env_key(segment, command_index, env_key) for env_key in _PYTEST_UNSAFE_ENV_KEYS):
                return False
            if _shell_segment_uses_env_split_string_wrapper(segment, command_index):
                return False
            if _shell_segment_uses_cwd_changing_wrapper(segment, command_index):
                return False
            if not _pytest_binary_segment_is_safe(segment[command_index], segment_args, cwd=cwd):
                return False
            saw_pytest = True
            continue
        if _shell_directory_setup_segment_is_safe(command_name, segment_args):
            continue
        if command_name in _READ_ONLY_LOOKUP_FILTERS and _read_only_lookup_filter_segment_is_safe(
            command_name,
            segment_args,
        ):
            continue
        if command_name in _SAFE_STATIC_SHELL_COMMANDS and _static_shell_segment_is_safe(segment_args):
            continue
        return False
    return saw_pytest


def _pytest_binary_segment_is_safe(command_token: str, module_args: list[str], *, cwd: Path | None) -> bool:
    if "/" in command_token or "\\" in command_token:
        return False
    if _python_module_may_be_shadowed("pytest", cwd):
        return False
    if _pytest_config_may_add_unsafe_options(cwd, module_args):
        return False
    return _pytest_module_args_are_safe(module_args)


def _shell_directory_setup_segment_is_safe(command_name: str, segment_args: list[str]) -> bool:
    if command_name == "popd":
        path_args = _shell_args_without_trailing_redirections(segment_args)
        return not path_args or all(not _shell_token_has_command_substitution(token) for token in path_args)
    if command_name not in {"cd", "pushd"}:
        return False
    path_args = _shell_args_without_trailing_redirections(segment_args)
    if not path_args:
        return False
    for token in path_args:
        if token in {"-", "--"}:
            continue
        if token.startswith("-"):
            return False
        if _shell_token_has_command_substitution(token):
            return False
    return True


def _shell_segment_uses_env_split_string_wrapper(segment: list[str], command_index: int) -> bool:
    index = 0
    while index < command_index:
        normalized_token = _shell_command_token_without_attached_redirection(segment[index])
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name != "env":
            index += 1
            continue
        parsed = parse_env_wrapper(segment[index + 1 :])
        if parsed.split_expansions:
            return True
        if not parsed.complete or parsed.command_index is None:
            break
        index += parsed.command_index + 1
    return False


def _shell_segment_uses_env_chdir(segment: list[str], command_index: int) -> bool:
    index = 0
    while index < command_index:
        normalized_token = _shell_command_token_without_attached_redirection(segment[index])
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name != "env":
            index += 1
            continue
        parsed = parse_env_wrapper(segment[index + 1 :])
        if parsed.option_effects.chdir is not None:
            return True
        if not parsed.complete or parsed.command_index is None or parsed.split_expansions:
            break
        index += parsed.command_index + 1
    return False


def _shell_segment_uses_sudo_chdir(segment: list[str], command_index: int) -> bool:
    index = 0
    while index < command_index:
        normalized_token = _shell_command_token_without_attached_redirection(segment[index])
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name != "sudo":
            index += 1
            continue
        index += 1
        while index < command_index:
            token = segment[index]
            if token in {"-D", "--chdir"} or token.startswith(("-D", "--chdir=")):
                return True
            if not token.startswith("-"):
                break
            index += _wrapper_option_tokens_consumed("sudo", token)
    return False


def _shell_segment_uses_cwd_changing_wrapper(segment: list[str], command_index: int) -> bool:
    return _shell_segment_uses_env_chdir(segment, command_index) or _shell_segment_uses_sudo_chdir(
        segment,
        command_index,
    )


__all__ = [
    "_contains_prior_pytest_state_mutation",
    "_contains_pytest_process_substitution",
    "_contains_unsafe_pytest_environment_wrapper",
    "_is_literal_cat_heredoc_to_stdout",
    "_looks_like_bounded_python_script_invocation",
    "_looks_like_safe_pytest_binary_invocation",
    "_looks_like_safe_python_module_invocation",
    "_looks_like_supported_python_invocation",
    "_pytest_binary_segment_is_safe",
    "_shell_declaration_exports_env",
    "_shell_declared_env_key",
    "_shell_directory_setup_segment_is_safe",
    "_shell_segment_uses_cwd_changing_wrapper",
    "_shell_segment_uses_env_chdir",
    "_shell_segment_uses_env_split_string_wrapper",
    "_shell_segment_uses_sudo_chdir",
    "_shell_set_exports_assignments",
]
