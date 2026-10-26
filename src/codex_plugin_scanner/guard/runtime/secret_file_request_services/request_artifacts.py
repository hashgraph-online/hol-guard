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


__all__ = [
    "_candidate_command_texts",
    "_collect_candidate_commands",
    "command_list_candidate_texts",
    "extract_sensitive_file_write_request",
]
