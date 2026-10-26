"""Request match models and sensitive path extraction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..actions import GuardActionEnvelope, apply_patch_target_paths
from ..command_model import CanonicalCommand
from ..home_path_text import expand_home, normalize_path
from ..secret_sensitivity import SecretPathMatch as SensitivePathMatch
from ..secret_sensitivity import classify_secret_path
from .constants_core import _FILE_READ_TOOL_NAMES, _PATH_KEYS, _PATH_LIST_KEYS
from .tool_action_risk_summaries import tool_action_risk_summary


@dataclass(frozen=True, slots=True)
class FileReadRequestMatch:
    """A sensitive file-read tool call."""

    tool_name: str
    normalized_tool_name: str
    path_match: SensitivePathMatch


@dataclass(frozen=True, slots=True)
class ToolActionRequestMatch:
    """A sensitive native tool action that should block before execution."""

    tool_name: str
    normalized_tool_name: str
    command_text: str
    action_class: str
    reason: str
    raw_command_text: str | None = None
    wrapper_chain: tuple[str, ...] = ()
    canonical_command: CanonicalCommand | None = None
    shell_execution_context_hash: str | None = None
    shell_execution_context_reason_code: str | None = None
    shell_execution_effective_cwds: tuple[str, ...] = ()
    guard_default_action: str | None = None
    reason_code: str | None = None
    restricted_profile_version: str | None = None
    pytest_config_identity_sha256: str | None = None
    pytest_config_sources: tuple[str, ...] = ()
    pytest_config_reason_codes: tuple[str, ...] = ()
    interpreter_executable_identities: tuple[dict[str, object], ...] = ()
    script_read_identity_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class FileWriteRequestMatch:
    """A sensitive file-write tool call."""

    tool_name: str
    normalized_tool_name: str
    normalized_path: str
    path_class: str
    reason: str
    action_class: str


def is_file_read_tool_name(tool_name: str | None) -> bool:
    """Return whether the tool name looks like a file-read tool."""

    if not isinstance(tool_name, str) or not tool_name.strip():
        return False
    return tool_name.strip().lower() in _FILE_READ_TOOL_NAMES


def classify_sensitive_path(
    path: str | None,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> SensitivePathMatch | None:
    """Classify a path if it points at a high-confidence sensitive local file."""

    return classify_secret_path(path, cwd=cwd, home_dir=home_dir)


def extract_sensitive_file_read_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> FileReadRequestMatch | None:
    """Extract a sensitive file-read request from tool arguments."""

    normalized_tool_name = _normalize_tool_name(tool_name)
    if normalized_tool_name is None or normalized_tool_name not in _FILE_READ_TOOL_NAMES:
        return None
    for candidate in _candidate_paths(arguments):
        path_match = classify_sensitive_path(candidate, cwd=cwd, home_dir=home_dir)
        if path_match is not None:
            return FileReadRequestMatch(
                tool_name=str(tool_name).strip(),
                normalized_tool_name=normalized_tool_name,
                path_match=path_match,
            )
    return None


def extract_sensitive_file_read_request_from_action(
    action: GuardActionEnvelope,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> FileReadRequestMatch | None:
    """Extract a sensitive file-read request from a normalized action envelope."""

    if action.action_type != "file_read":
        return None
    normalized_tool_name = _normalize_tool_name(action.tool_name) or "read"
    tool_name = action.tool_name.strip() if isinstance(action.tool_name, str) and action.tool_name.strip() else "Read"
    if normalized_tool_name not in _FILE_READ_TOOL_NAMES:
        return None
    for candidate in action.target_paths:
        if _is_lossy_redacted_path(candidate):
            continue
        path_match = classify_sensitive_path(candidate, cwd=cwd, home_dir=home_dir)
        if path_match is not None:
            return FileReadRequestMatch(
                tool_name=tool_name,
                normalized_tool_name=normalized_tool_name,
                path_match=path_match,
            )
    return None


def _normalized_candidate_path(
    value: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> str | None:
    stripped = value.strip().strip("'").strip('"')
    if not stripped:
        return None
    return normalize_path(expand_home(stripped, home_dir), cwd)


def _is_lossy_redacted_path(path: str) -> bool:
    return path.strip().startswith(".../")


def _candidate_paths(value: object, *, include_apply_patch: bool = False) -> list[str]:
    results: list[str] = []
    _collect_candidate_paths(value, results, depth=0)
    if include_apply_patch and isinstance(value, dict):
        results.extend(apply_patch_target_paths(value))
    return results


def _collect_candidate_paths(value: object, results: list[str], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, dict):
        for key in _PATH_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                results.append(candidate)
        for key in _PATH_LIST_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, list):
                results.extend(item for item in candidate if isinstance(item, str) and item.strip())
        for child in value.values():
            if isinstance(child, (dict, list)):
                _collect_candidate_paths(child, results, depth=depth + 1)
        return
    if isinstance(value, list):
        for child in value:
            if isinstance(child, str) and child.strip():
                results.append(child)
            elif isinstance(child, (dict, list)):
                _collect_candidate_paths(child, results, depth=depth + 1)
        return


def _normalize_tool_name(tool_name: object) -> str | None:
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None
    return tool_name.strip().lower()


__all__ = [
    "FileReadRequestMatch",
    "FileWriteRequestMatch",
    "ToolActionRequestMatch",
    "_candidate_paths",
    "_collect_candidate_paths",
    "_is_lossy_redacted_path",
    "_normalize_tool_name",
    "_normalized_candidate_path",
    "classify_sensitive_path",
    "expand_home",
    "extract_sensitive_file_read_request",
    "extract_sensitive_file_read_request_from_action",
    "is_file_read_tool_name",
    "normalize_path",
    "tool_action_risk_summary",
]
