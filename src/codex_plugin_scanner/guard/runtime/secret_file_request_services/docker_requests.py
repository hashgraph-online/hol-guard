"""Sensitive Docker and Compose request classification."""

from __future__ import annotations

import shlex

from ..env_wrapper import parse_env_wrapper
from ..executable_resolution import which_for_execution_cwd
from ..shell_execution_context import ShellExecutionContext, validate_shell_execution_segment
from .constants_core import (
    _DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS,
    _DOCKER_BUILD_SUBCOMMANDS,
    _DOCKER_BUILDX_BUILD_SUBCOMMANDS,
    _DOCKER_COMPOSE_FLAG_OPTIONS,
    _DOCKER_COMPOSE_OPTIONS_WITH_VALUES,
    _DOCKER_COMPOSE_SAFE_SUBCOMMANDS,
    _DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS,
    _DOCKER_COMPOSE_SUBCOMMAND,
    _DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS,
    _DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS,
    _DOCKER_SENSITIVE_CONTEXT_ENV_KEYS,
)
from .constants_patterns import _SHELL_ASSIGNMENT_PATTERN
from .request_artifacts import _docker_buildx_subcommand_index, _normalized_shell_command_name
from .shell_tokenization import (
    _docker_attached_short_context_option,
    _docker_build_args_are_sensitive,
    _docker_global_option_has_value,
    _docker_subcommand_help_requested,
    _docker_subcommand_index,
    _iter_shell_command_segments,
    _shell_command_token_without_attached_redirection,
    _shell_segment_primary_command,
    _split_shell_parts,
)

_which_for_execution_cwd = which_for_execution_cwd


def _shell_execution_context_validation_reason(context: ShellExecutionContext) -> str | None:
    if not context.complete:
        return context.reason_code
    for segment in context.segments:
        _effective_cwd, reason = validate_shell_execution_segment(context, segment)
        if reason is not None:
            return reason
    return None


def shell_execution_context_starts_with_literal_cd(context: ShellExecutionContext) -> bool:
    if not context.complete or not context.segments:
        return False
    first = context.segments[0]
    if first.control_before or first.directory_operation != "cd" or not first.tokens:
        return False
    return first.tokens[0].strip("\"'").lower() == "cd"


def _docker_sensitive_reason(command_text: str, *, _inherited_sensitive_env: bool = False) -> str | None:
    parts = _split_shell_parts(command_text.strip())
    exported_env_context: dict[str, bool] = {}
    for segment in _iter_shell_command_segments(parts):
        if segment and _normalized_shell_command_name(segment[0]) == "env":
            parsed_env = parse_env_wrapper(segment[1:])
            if not parsed_env.complete:
                return "env-wrapper-unresolved"
            env_sensitive = False if parsed_env.option_effects.ignore_environment else _inherited_sensitive_env
            env_sensitive = env_sensitive or _docker_env_assignments_are_sensitive(
                parsed_env.environment_delta.assignments
            )
            if parsed_env.executable_argv:
                remaining_reason = _docker_sensitive_reason(
                    shlex.join(parsed_env.executable_argv),
                    _inherited_sensitive_env=env_sensitive,
                )
                if remaining_reason is not None:
                    return remaining_reason
            continue
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name == "export" and command_index is not None:
            exported_env_context.update(_docker_exported_env_context_sensitivity(segment[:command_index]))
            exported_env_context.update(_docker_exported_env_context_sensitivity(segment[command_index + 1 :]))
            continue
        if command_name != "docker" or command_index is None:
            continue
        sensitive_env_context = (
            _inherited_sensitive_env
            or any(exported_env_context.values())
            or _docker_env_context_is_sensitive(segment[:command_index])
        )
        global_tokens = segment[command_index + 1 :]
        subcommand_index = _docker_subcommand_index(global_tokens)
        if subcommand_index is None:
            continue
        sensitive_context = sensitive_env_context or _docker_global_context_is_sensitive(
            global_tokens[:subcommand_index]
        )
        args = global_tokens[subcommand_index:]
        subcommand = args[0].lower()
        if _docker_subcommand_help_requested(args):
            continue
        if subcommand in _DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS:
            return subcommand
        if subcommand in _DOCKER_BUILD_SUBCOMMANDS and _docker_build_args_are_sensitive(args[1:]):
            return "build-sensitive-flags"
        if subcommand == _DOCKER_COMPOSE_SUBCOMMAND:
            reason = _docker_compose_sensitive_reason(args[1:], sensitive_context=sensitive_context)
            if reason is not None:
                return reason
            continue
        if subcommand == "buildx" and len(args) > 1:
            buildx_subcommand_index = _docker_buildx_subcommand_index(args[1:])
            if buildx_subcommand_index is None:
                continue
            buildx_args = args[1 + buildx_subcommand_index :]
            buildx_subcommand = buildx_args[0].lower()
            if buildx_subcommand in _DOCKER_BUILDX_BUILD_SUBCOMMANDS and _docker_build_args_are_sensitive(
                buildx_args[1:]
            ):
                return "buildx-build-sensitive-flags"
    return None


def _docker_global_context_is_sensitive(global_tokens: list[str]) -> bool:
    index = 0
    while index < len(global_tokens):
        token = global_tokens[index]
        attached_short = _docker_attached_short_context_option(token)
        if attached_short is not None:
            flag, value = attached_short
            if _docker_global_context_value_is_sensitive(flag, value):
                return True
            index += 1
            continue
        if _docker_global_option_has_value(token):
            if "=" in token:
                flag, value = token.split("=", 1)
                if _docker_global_context_value_is_sensitive(flag, value):
                    return True
                index += 1
                continue
            flag = token
            value = global_tokens[index + 1] if index + 1 < len(global_tokens) else ""
            if _docker_global_context_value_is_sensitive(flag, value):
                return True
            index += 2
            continue
        if token in _DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS or any(
            token.startswith(f"{flag}=") for flag in _DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS
        ):
            return True
        index += 1
    return False


def _docker_global_context_value_is_sensitive(flag: str, value: str) -> bool:
    if flag not in _DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS:
        return False
    normalized_value = value.strip().strip("\"'")
    if flag in {"--context", "-c"}:
        # ``default`` (and an empty value) still targets the local engine.
        return normalized_value.lower() not in {"", "default"}
    # ``--host``/``-H``, ``--config``, and TLS cert/key flags always point at a
    # non-default/remotable control plane or credential material.
    return True


def _docker_env_context_is_sensitive(prefix_tokens: list[str]) -> bool:
    env_index = next(
        (index for index, token in enumerate(prefix_tokens) if _normalized_shell_command_name(token) == "env"),
        None,
    )
    if env_index is not None:
        parsed = parse_env_wrapper(prefix_tokens[env_index + 1 :])
        if not parsed.complete:
            return True
        return _docker_env_assignments_are_sensitive(parsed.environment_delta.assignments)
    return any(
        assignment is not None and _docker_env_context_value_is_sensitive(*assignment)
        for assignment in (_docker_env_assignment(token) for token in prefix_tokens)
    )


def _docker_env_assignments_are_sensitive(assignments: tuple[tuple[str, str], ...]) -> bool:
    return any(
        name.upper() in _DOCKER_SENSITIVE_CONTEXT_ENV_KEYS
        and _docker_env_context_value_is_sensitive(name.upper(), value)
        for name, value in assignments
    )


def _docker_exported_env_context_sensitivity(args: list[str]) -> dict[str, bool]:
    exported: dict[str, bool] = {}
    for token in args:
        if token.startswith("-"):
            continue
        assignment = _docker_env_assignment(token)
        if assignment is None:
            continue
        key, value = assignment
        exported[key] = _docker_env_context_value_is_sensitive(key, value)
    return exported


def _docker_env_assignment(token: str) -> tuple[str, str] | None:
    normalized = _shell_command_token_without_attached_redirection(token).strip()
    if not _SHELL_ASSIGNMENT_PATTERN.match(normalized):
        return None
    key, _, value = normalized.partition("=")
    key = key.rstrip("+").upper()
    if key not in _DOCKER_SENSITIVE_CONTEXT_ENV_KEYS:
        return None
    return key, value.strip().strip("\"'")


def _docker_env_context_value_is_sensitive(key: str, value: str) -> bool:
    normalized_value = value.strip().strip("\"'")
    if key == "DOCKER_CONTEXT":
        return normalized_value.lower() not in {"", "default"}
    if key == "DOCKER_HOST":
        lowered = normalized_value.lower()
        return bool(normalized_value) and not lowered.startswith(("unix://", "npipe://"))
    if key == "DOCKER_TLS_VERIFY":
        return normalized_value.lower() not in {"", "0", "false", "no"}
    return bool(normalized_value)


def _docker_compose_sensitive_reason(args: list[str], *, sensitive_context: bool) -> str | None:
    if sensitive_context:
        return "compose-sensitive-context"
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            remaining = args[index + 1 :]
            if remaining:
                compose_subcommand = remaining[0].lower()
                return _docker_compose_subcommand_reason(compose_subcommand, remaining[1:])
            return None
        if _docker_compose_option_has_value(token):
            if _docker_compose_option_is_secret_bearing(token):
                return "compose-env-file"
            index += 1 if "=" in token else 2
            continue
        if _docker_compose_flag_option_matches(token):
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--"):
            index += 1
            continue
        return _docker_compose_subcommand_reason(token.lower(), args[index + 1 :])
    return None


def _docker_compose_subcommand_reason(compose_subcommand: str, subcommand_args: list[str]) -> str | None:
    if compose_subcommand in _DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS:
        return f"compose-{compose_subcommand}"
    if _docker_compose_args_include_secret_bearing_option(subcommand_args):
        return "compose-env-file"
    if compose_subcommand in _DOCKER_BUILD_SUBCOMMANDS and _docker_build_args_are_sensitive(subcommand_args):
        return "compose-build-sensitive-flags"
    if compose_subcommand in _DOCKER_COMPOSE_SAFE_SUBCOMMANDS:
        return None
    # Unknown Compose subcommands stay sensitive by default.
    return "compose-unknown-subcommand"


def _docker_compose_option_has_value(token: str) -> bool:
    return token in _DOCKER_COMPOSE_OPTIONS_WITH_VALUES or any(
        token.startswith(f"{option}=") for option in _DOCKER_COMPOSE_OPTIONS_WITH_VALUES
    )


def _docker_compose_option_is_secret_bearing(token: str) -> bool:
    return token == "--env-file" or token.startswith("--env-file=")


def _docker_compose_args_include_secret_bearing_option(args: list[str]) -> bool:
    return any(_docker_compose_option_is_secret_bearing(token) for token in args)


def _docker_compose_flag_option_matches(token: str) -> bool:
    return token in _DOCKER_COMPOSE_FLAG_OPTIONS or any(
        token.startswith(f"{option}=") for option in _DOCKER_COMPOSE_FLAG_OPTIONS
    )


__all__ = [
    "_docker_compose_args_include_secret_bearing_option",
    "_docker_compose_flag_option_matches",
    "_docker_compose_option_has_value",
    "_docker_compose_option_is_secret_bearing",
    "_docker_compose_sensitive_reason",
    "_docker_compose_subcommand_reason",
    "_docker_env_assignment",
    "_docker_env_assignments_are_sensitive",
    "_docker_env_context_is_sensitive",
    "_docker_env_context_value_is_sensitive",
    "_docker_exported_env_context_sensitivity",
    "_docker_global_context_is_sensitive",
    "_docker_global_context_value_is_sensitive",
    "_docker_sensitive_reason",
    "_shell_execution_context_validation_reason",
    "_which_for_execution_cwd",
    "shell_execution_context_starts_with_literal_cd",
]
