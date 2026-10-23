"""Sensitive file-write classification and command candidate extraction.

The artifacts these requests earn are built by the resident; nothing here
derives an artifact id, so one implementation decides what a sensitive-request
review is keyed under.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from ..secret_sensitivity import classify_secret_path
from .constants_core import (
    _COMMAND_KEYS,
    _DOCKER_BUILD_ARG_SECRET_MARKERS,
    _DOCKER_BUILD_ARG_TOKEN_PREFIXES,
    _DOCKER_BUILD_OUTPUT_FLAGS,
    _DOCKER_BUILDX_FLAG_OPTIONS,
    _DOCKER_BUILDX_OPTIONS_WITH_VALUES,
    _FILE_WRITE_TOOL_NAMES,
    COMMAND_CANDIDATE_LIST_KEYS,
    COMMAND_SEQUENCE_KEYS,
)
from .request_models import (
    FileWriteRequestMatch,
    _candidate_paths,
    _normalize_tool_name,
    _normalized_candidate_path,
)


def extract_sensitive_file_write_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    protected_paths: dict[str, str] | None = None,
) -> FileWriteRequestMatch | None:
    """Extract a sensitive file-write request from native tool arguments."""

    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name is None or normalized_tool_name not in _FILE_WRITE_TOOL_NAMES:
        return None
    requested_tool_name = str(tool_name).strip() if isinstance(tool_name, str) and str(tool_name).strip() else "Write"
    normalized_protected_paths = protected_paths or {}
    for candidate in _candidate_paths(arguments, include_apply_patch=normalized_tool_name == "apply_patch"):
        normalized_candidate = _normalized_candidate_path(candidate, cwd=cwd, home_dir=home_dir)
        if normalized_candidate is not None:
            protected_label = normalized_protected_paths.get(normalized_candidate)
            if protected_label is not None:
                return FileWriteRequestMatch(
                    tool_name=requested_tool_name,
                    normalized_tool_name=normalized_tool_name,
                    normalized_path=normalized_candidate,
                    path_class=protected_label,
                    reason=(
                        f"Guard treats writes to {protected_label} as sensitive because changing harness "
                        "configuration can weaken approvals or bypass protections before the user confirms the action."
                    ),
                    action_class="guard-managed config write",
                )
        path_match = classify_secret_path(candidate, cwd=cwd, home_dir=home_dir)
        if path_match is not None:
            return FileWriteRequestMatch(
                tool_name=requested_tool_name,
                normalized_tool_name=normalized_tool_name,
                normalized_path=path_match.normalized_path,
                path_class=path_match.path_class,
                reason=path_match.reason,
                action_class="sensitive local file write",
            )
    return None


def _candidate_command_texts(value: object) -> list[str]:
    results: list[str] = []
    _collect_candidate_commands(value, results, depth=0)
    return results


def command_list_candidate_texts(
    values: list[str],
    *,
    preserve_items: bool = False,
) -> tuple[str, ...]:
    string_values = [item.strip() for item in values if isinstance(item, str) and item.strip()]
    if not string_values:
        return ()
    if preserve_items:
        return tuple(string_values)
    if len(string_values) == 1:
        return (string_values[0],)
    return (shlex.join(string_values),)


def _collect_candidate_commands(value: object, results: list[str], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            results.append(stripped)
        return
    if isinstance(value, list):
        results.extend(command_list_candidate_texts(value))
        for child in value:
            if isinstance(child, (dict, list)):
                _collect_candidate_commands(child, results, depth=depth + 1)
        return
    if not isinstance(value, dict):
        return
    for key in _COMMAND_KEYS:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            results.append(candidate.strip())
    for key in COMMAND_CANDIDATE_LIST_KEYS:
        candidate = value.get(key)
        if isinstance(candidate, list):
            results.extend(command_list_candidate_texts(candidate, preserve_items=key in COMMAND_SEQUENCE_KEYS))
    for key, child in value.items():
        if key in COMMAND_CANDIDATE_LIST_KEYS:
            continue
        if isinstance(child, (dict, list)):
            _collect_candidate_commands(child, results, depth=depth + 1)


def _docker_buildx_subcommand_index(args: list[str]) -> int | None:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return index + 1 if index + 1 < len(args) else None
        if _docker_buildx_option_has_value(token):
            index += 1 if "=" in token else 2
            continue
        if _docker_buildx_flag_option_matches(token):
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--"):
            index += 1
            continue
        return index
    return None


def _docker_buildx_option_has_value(token: str) -> bool:
    return token in _DOCKER_BUILDX_OPTIONS_WITH_VALUES or any(
        token.startswith(f"{option}=") for option in _DOCKER_BUILDX_OPTIONS_WITH_VALUES
    )


def _docker_buildx_flag_option_matches(token: str) -> bool:
    return token in _DOCKER_BUILDX_FLAG_OPTIONS or any(
        token.startswith(f"{option}=") for option in _DOCKER_BUILDX_FLAG_OPTIONS
    )


def _docker_build_output_flag_matches(token: str) -> bool:
    if token in _DOCKER_BUILD_OUTPUT_FLAGS or any(token.startswith(f"{flag}=") for flag in _DOCKER_BUILD_OUTPUT_FLAGS):
        return True
    return token.startswith("-o") and len(token) > 2


def _docker_build_arg_is_sensitive(value: str) -> bool:
    key, separator, assigned_value = value.partition("=")
    # Normalize after splitting to tolerate unusual shell tokenization.
    normalized_key = key.strip()
    return bool(
        normalized_key
        and (
            # Bare build args pass through the caller's environment, so block
            # them even when the variable name does not look secret-like.
            not separator
            or _docker_build_arg_name_is_sensitive(normalized_key)
            or _docker_build_arg_value_is_sensitive(assigned_value.strip())
        )
    )


def _docker_build_arg_name_is_sensitive(value: str) -> bool:
    normalized = value.upper().replace("-", "_")
    parts = normalized.split("_")
    if any(part in _DOCKER_BUILD_ARG_SECRET_MARKERS for part in parts):
        return True
    substring_markers = _DOCKER_BUILD_ARG_SECRET_MARKERS - {"KEY"}
    return any(marker in normalized for marker in substring_markers)


def _docker_build_arg_value_is_sensitive(value: str) -> bool:
    lowered = value.lower().strip("\"'")
    if any(lowered.startswith(prefix) for prefix in _DOCKER_BUILD_ARG_TOKEN_PREFIXES):
        return True
    if "$(" in value or "`" in value:
        return True
    return any(_docker_build_arg_name_is_sensitive(variable_name) for variable_name in _shell_variable_names(value))


def _shell_variable_names(value: str) -> tuple[str, ...]:
    names: list[str] = []
    index = 0
    while index < len(value):
        dollar_index = value.find("$", index)
        if dollar_index == -1 or dollar_index + 1 >= len(value):
            break
        if value[dollar_index + 1] == "{":
            closing_index = value.find("}", dollar_index + 2)
            if closing_index == -1:
                index = dollar_index + 2
                continue
            variable_name = _shell_braced_variable_name(value[dollar_index + 2 : closing_index])
            if variable_name:
                names.append(variable_name)
            index = closing_index + 1
            continue
        variable_name, next_index = _shell_unbraced_variable_name(value, dollar_index + 1)
        if variable_name:
            names.append(variable_name)
        index = next_index
    return tuple(names)


def _shell_braced_variable_name(value: str) -> str:
    start = 1 if value.startswith("!") else 0
    variable_name, _ = _shell_unbraced_variable_name(value, start)
    return variable_name


def _shell_unbraced_variable_name(value: str, start: int) -> tuple[str, int]:
    if start >= len(value) or not (value[start].isalpha() or value[start] == "_"):
        return "", start + 1
    index = start + 1
    while index < len(value) and (value[index].isalnum() or value[index] == "_"):
        index += 1
    return value[start:index], index


def _normalized_shell_command_name(command_name: str) -> str:
    normalized_command = command_name.replace("\\", "/").strip()
    if "/" not in normalized_command:
        return normalized_command.lower()
    return normalized_command.rsplit("/", 1)[-1].lower()


__all__ = [
    "_candidate_command_texts",
    "_collect_candidate_commands",
    "_docker_build_arg_is_sensitive",
    "_docker_build_arg_name_is_sensitive",
    "_docker_build_arg_value_is_sensitive",
    "_docker_build_output_flag_matches",
    "_docker_buildx_flag_option_matches",
    "_docker_buildx_option_has_value",
    "_docker_buildx_subcommand_index",
    "_normalized_shell_command_name",
    "_shell_braced_variable_name",
    "_shell_unbraced_variable_name",
    "_shell_variable_names",
    "command_list_candidate_texts",
    "extract_sensitive_file_write_request",
]
