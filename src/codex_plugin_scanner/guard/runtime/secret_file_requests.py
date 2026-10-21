"""Compatibility facade for runtime request-classification services.

The sensitive-request classifiers are answered by the resident. The remaining
exports are the artifact builders and request helpers that runtime callers
still import from here.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..native_sensitive_request import (
    native_benign_file_read,
    native_command_list_candidate_texts,
    native_read_only_lookup_target_is_safe,
    native_sensitive_file_read_request,
    native_sensitive_file_read_request_artifact,
    native_sensitive_file_read_request_artifact_from_action,
    native_sensitive_file_read_request_from_action,
    native_sensitive_file_write_request,
    native_sensitive_file_write_request_artifact,
    native_sensitive_tool_action_request,
)
from .secret_file_request_services.benign_requests import (
    build_tool_action_request_artifact as build_tool_action_request_artifact,
)
from .secret_file_request_services.constants_core import _SHELL_TOOL_NAMES as _SHELL_TOOL_NAMES
from .secret_file_request_services.constants_core import COMMAND_CANDIDATE_LIST_KEYS as COMMAND_CANDIDATE_LIST_KEYS
from .secret_file_request_services.constants_core import COMMAND_LIST_KEYS as COMMAND_LIST_KEYS
from .secret_file_request_services.constants_core import COMMAND_SEQUENCE_KEYS as COMMAND_SEQUENCE_KEYS
from .secret_file_request_services.docker_requests import (
    shell_execution_context_starts_with_literal_cd as shell_execution_context_starts_with_literal_cd,
)
from .secret_file_request_services.github_shell_capabilities import (
    classify_github_shell_capabilities as classify_github_shell_capabilities,
)
from .secret_file_request_services.request_artifacts import _candidate_command_texts as _candidate_command_texts
from .secret_file_request_services.request_models import FileReadRequestMatch as FileReadRequestMatch
from .secret_file_request_services.request_models import FileWriteRequestMatch as FileWriteRequestMatch
from .secret_file_request_services.request_models import ToolActionRequestMatch as ToolActionRequestMatch
from .secret_file_request_services.request_models import _normalize_tool_name as _normalize_tool_name
from .secret_file_request_services.request_models import classify_sensitive_path as classify_sensitive_path
from .secret_file_request_services.request_models import is_file_read_tool_name as is_file_read_tool_name
from .secret_file_request_services.shell_quote_parsing import (
    literal_cd_execution_context as literal_cd_execution_context,
)
from .secret_file_request_services.source_edit_context import (
    low_risk_compound_developer_execution_context as low_risk_compound_developer_execution_context,
)

if TYPE_CHECKING:
    from ..models import GuardArtifact
    from .actions import GuardActionEnvelope
    from .command_evaluation import CompositeCommandEvaluation
    from .command_model import CanonicalCommand


def extract_sensitive_tool_action_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    canonical_command: CanonicalCommand | None = None,
    native_evaluation: CompositeCommandEvaluation | None = None,
) -> ToolActionRequestMatch | None:
    """Ask the resident whether one tool call is a sensitive action request."""

    return native_sensitive_tool_action_request(
        tool_name,
        arguments,
        cwd=cwd,
        home_dir=home_dir,
        canonical_command=canonical_command,
        native_evaluation=native_evaluation,
    )


def extract_sensitive_file_read_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> FileReadRequestMatch | None:
    """Ask the resident whether one tool call reads a sensitive local file."""

    return native_sensitive_file_read_request(tool_name, arguments, cwd=cwd, home_dir=home_dir)


def extract_sensitive_file_read_request_from_action(
    action: GuardActionEnvelope,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> FileReadRequestMatch | None:
    """Ask the resident whether one normalized action reads a sensitive local file."""

    return native_sensitive_file_read_request_from_action(action, cwd=cwd, home_dir=home_dir)


def extract_sensitive_file_write_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    protected_paths: dict[str, str] | None = None,
) -> FileWriteRequestMatch | None:
    """Ask the resident whether one tool call writes a protected path."""

    return native_sensitive_file_write_request(
        tool_name, arguments, cwd=cwd, home_dir=home_dir, protected_paths=protected_paths
    )


def extract_sensitive_file_read_request_artifact(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    harness: str,
    config_path: str,
    source_scope: str,
) -> tuple[FileReadRequestMatch | None, GuardArtifact | None]:
    """The sensitive file read one tool call makes, and the review it earns."""

    return native_sensitive_file_read_request_artifact(
        tool_name,
        arguments,
        cwd=cwd,
        home_dir=home_dir,
        harness=harness,
        config_path=config_path,
        source_scope=source_scope,
    )


def extract_sensitive_file_read_request_artifact_from_action(
    action: GuardActionEnvelope,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    harness: str,
    config_path: str,
    source_scope: str,
) -> tuple[FileReadRequestMatch | None, GuardArtifact | None]:
    """The sensitive file read one normalized action makes, and its review."""

    return native_sensitive_file_read_request_artifact_from_action(
        action,
        cwd=cwd,
        home_dir=home_dir,
        harness=harness,
        config_path=config_path,
        source_scope=source_scope,
    )


def extract_sensitive_file_write_request_artifact(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    protected_paths: dict[str, str] | None = None,
    harness: str,
    config_path: str,
    source_scope: str,
) -> tuple[FileWriteRequestMatch | None, GuardArtifact | None]:
    """The protected path one tool call writes, and the review it earns."""

    return native_sensitive_file_write_request_artifact(
        tool_name,
        arguments,
        cwd=cwd,
        home_dir=home_dir,
        protected_paths=protected_paths,
        harness=harness,
        config_path=config_path,
        source_scope=source_scope,
    )


def command_list_candidate_texts(values: list[str], *, preserve_items: bool = False) -> tuple[str, ...]:
    """The command texts the resident reads from one argv-style list."""

    return native_command_list_candidate_texts(values, preserve_items=preserve_items)


def is_explicitly_benign_native_file_read_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    """Whether the resident proves one native ``Read`` target existing and non-sensitive."""

    return native_benign_file_read(tool_name, arguments, cwd=cwd, home_dir=home_dir)


def _read_only_lookup_target_is_safe(target: str, *, allow_dirs: bool, home_dir: Path | None = None) -> bool:
    return native_read_only_lookup_target_is_safe(target, allow_dirs=allow_dirs, home_dir=home_dir)


__all__ = [
    "COMMAND_CANDIDATE_LIST_KEYS",
    "COMMAND_LIST_KEYS",
    "COMMAND_SEQUENCE_KEYS",
    "_SHELL_TOOL_NAMES",
    "FileReadRequestMatch",
    "FileWriteRequestMatch",
    "ToolActionRequestMatch",
    "_candidate_command_texts",
    "_normalize_tool_name",
    "_read_only_lookup_target_is_safe",
    "build_tool_action_request_artifact",
    "classify_github_shell_capabilities",
    "classify_sensitive_path",
    "command_list_candidate_texts",
    "extract_sensitive_file_read_request",
    "extract_sensitive_file_read_request_artifact",
    "extract_sensitive_file_read_request_artifact_from_action",
    "extract_sensitive_file_read_request_from_action",
    "extract_sensitive_file_write_request",
    "extract_sensitive_file_write_request_artifact",
    "extract_sensitive_tool_action_request",
    "is_explicitly_benign_native_file_read_request",
    "is_file_read_tool_name",
    "literal_cd_execution_context",
    "low_risk_compound_developer_execution_context",
    "shell_execution_context_starts_with_literal_cd",
]
