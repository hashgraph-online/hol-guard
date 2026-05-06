"""Shell variable data-flow helpers for Guard runtime detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.runtime.data_flow import extract_command_segments, extract_urls
from codex_plugin_scanner.guard.runtime.secret_sources import secret_path_matches_in_command
from codex_plugin_scanner.guard.runtime.shell_commands import command_execution_segments, segment_executes_command

_SECRET_VARIABLE_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)="
    r"(?P<value>\$\([^)]*\)|`[^`]*`|\"[^\"]*\"|'[^']*'|[^\s;&|]+)"
)
_CURL_DATA_VALUE_PATTERN = re.compile(
    r"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b[^\r\n;&|]*?"
    r"(?:--data(?:-binary|-raw|-urlencode)?|-d)(?:=|\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s;&|]+)"
)
_SHELL_VARIABLE_EXPANSION_PATTERN = re.compile(
    r"\$(?:(?P<name>[A-Za-z_][A-Za-z0-9_]*)|\{(?P<braced_name>[A-Za-z_][A-Za-z0-9_]*)\})"
)


@dataclass(frozen=True, slots=True)
class SecretVariableAssignment:
    name: str
    encoded: bool


def secret_variable_assignments(command: str, *, workspace: Path | None) -> tuple[SecretVariableAssignment, ...]:
    assignments: list[SecretVariableAssignment] = []
    for segment in extract_command_segments(command):
        assignments.extend(_segment_secret_variable_assignments(segment, workspace=workspace))
    return tuple(assignments)


def curl_data_uses_secret_variable(command: str, *, workspace: Path | None) -> bool:
    variables = secret_variable_assignments(command, workspace=workspace)
    if not variables:
        return False
    names = frozenset(assignment.name for assignment in variables)
    return any(_curl_segment_uses_variable(segment, names) for segment in command_execution_segments(command))


def curl_data_uses_encoded_secret_variable(command: str, *, workspace: Path | None) -> bool:
    variables = secret_variable_assignments(command, workspace=workspace)
    encoded_names = frozenset(assignment.name for assignment in variables if assignment.encoded)
    if not encoded_names:
        return False
    return any(_curl_segment_uses_variable(segment, encoded_names) for segment in command_execution_segments(command))


def _segment_secret_variable_assignments(
    segment: str, *, workspace: Path | None
) -> tuple[SecretVariableAssignment, ...]:
    normalized = segment.lstrip()
    if normalized.startswith("export "):
        normalized = normalized[7:].lstrip()
    assignments: list[SecretVariableAssignment] = []
    index = 0
    while index < len(normalized):
        match = _SECRET_VARIABLE_ASSIGNMENT_PATTERN.match(normalized, index)
        if match is None:
            break
        value = match.group("value")
        if secret_path_matches_in_command(value, workspace=workspace):
            assignments.append(
                SecretVariableAssignment(
                    name=match.group("name"),
                    encoded=_value_encodes_secret(value),
                )
            )
        index = match.end()
        while index < len(normalized) and normalized[index].isspace():
            index += 1
    return tuple(assignments)


def _curl_segment_uses_variable(segment: str, names: frozenset[str]) -> bool:
    if not segment_executes_command(segment, {"curl", "curl.exe"}) or not extract_urls(segment):
        return False
    return any(
        _value_uses_variable(match.group("value"), names) for match in _CURL_DATA_VALUE_PATTERN.finditer(segment)
    )


def _value_uses_variable(value: str, names: frozenset[str]) -> bool:
    if _is_single_quoted(value):
        return False
    return any(_expanded_variable_name(match) in names for match in _SHELL_VARIABLE_EXPANSION_PATTERN.finditer(value))


def _expanded_variable_name(match: re.Match[str]) -> str:
    return match.group("name") or match.group("braced_name")


def _is_single_quoted(value: str) -> bool:
    return len(value) >= 2 and value[0] == "'" and value[-1] == "'"


def _value_encodes_secret(value: str) -> bool:
    lowered = value.lower()
    return "base64" in lowered or "openssl enc" in lowered
