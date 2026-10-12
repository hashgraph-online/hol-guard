"""Compatibility facade for runtime request-classification services.

The sensitive-request classifiers are answered by the resident; the remaining
exports are artifact builders and helpers whose callers have not moved yet.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..native_sensitive_request import (
    native_benign_file_read,
    native_command_list_candidate_texts,
    native_read_only_lookup_target_is_safe,
    native_sensitive_file_read_request,
    native_sensitive_file_read_request_from_action,
    native_sensitive_file_write_request,
    native_sensitive_tool_action_request,
)
from .secret_file_request_services import benign_requests as _benign_requests

# Preserve private diagnostic helpers for existing runtime callers while migrations complete.
from .secret_file_request_services import constants_core as _constants_core
from .secret_file_request_services import constants_patterns as _constants_patterns
from .secret_file_request_services import credential_exfiltration as _credential_exfiltration
from .secret_file_request_services import destructive_shell_detection as _destructive_shell_detection
from .secret_file_request_services import developer_inspection as _developer_inspection
from .secret_file_request_services import docker_requests as _docker_requests
from .secret_file_request_services import encoded_payloads as _encoded_payloads
from .secret_file_request_services import github_pr_body_safety as _github_pr_body_safety
from .secret_file_request_services import github_pr_ephemeral_body as _github_pr_ephemeral_body
from .secret_file_request_services import github_pr_expansion as _github_pr_expansion
from .secret_file_request_services import github_shell_capabilities as _github_shell_capabilities
from .secret_file_request_services import interpreter_identity as _interpreter_identity
from .secret_file_request_services import interpreter_launch as _interpreter_launch
from .secret_file_request_services import interpreter_observers as _interpreter_observers
from .secret_file_request_services import interpreter_trust as _interpreter_trust
from .secret_file_request_services import local_read_operands as _local_read_operands
from .secret_file_request_services import network_upload_detection as _network_upload_detection
from .secret_file_request_services import node_generated_workflows as _node_generated_workflows
from .secret_file_request_services import node_heredoc_safety as _node_heredoc_safety
from .secret_file_request_services import perl_read_only as _perl_read_only
from .secret_file_request_services import pytest_binary_safety as _pytest_binary_safety
from .secret_file_request_services import pytest_config_safety as _pytest_config_safety
from .secret_file_request_services import pytest_target_detection as _pytest_target_detection
from .secret_file_request_services import python_pytest_entrypoints as _python_pytest_entrypoints
from .secret_file_request_services import read_only_filters as _read_only_filters
from .secret_file_request_services import request_artifacts as _request_artifacts
from .secret_file_request_services import request_models as _request_models
from .secret_file_request_services import sensitive_read_pipeline as _sensitive_read_pipeline
from .secret_file_request_services import shell_quote_parsing as _shell_quote_parsing
from .secret_file_request_services import shell_request_classifier as _shell_request_classifier
from .secret_file_request_services import shell_static_safety as _shell_static_safety
from .secret_file_request_services import shell_stdin_sources as _shell_stdin_sources
from .secret_file_request_services import shell_tokenization as _shell_tokenization
from .secret_file_request_services import source_edit_context as _source_edit_context
from .secret_file_request_services import tool_action_requests as _tool_action_requests
from .secret_file_request_services import typescript_graphql_safety as _typescript_graphql_safety
from .secret_file_request_services import upload_arguments as _upload_arguments
from .secret_file_request_services.benign_requests import (
    build_tool_action_request_artifact as build_tool_action_request_artifact,
)
from .secret_file_request_services.constants_core import _SHELL_TOOL_NAMES as _SHELL_TOOL_NAMES
from .secret_file_request_services.constants_core import COMMAND_CANDIDATE_LIST_KEYS as COMMAND_CANDIDATE_LIST_KEYS
from .secret_file_request_services.constants_core import COMMAND_LIST_KEYS as COMMAND_LIST_KEYS
from .secret_file_request_services.constants_core import COMMAND_SEQUENCE_KEYS as COMMAND_SEQUENCE_KEYS
from .secret_file_request_services.credential_exfiltration import (
    _read_small_runtime_text_file as _read_small_runtime_text_file,
)
from .secret_file_request_services.docker_requests import (
    shell_execution_context_starts_with_literal_cd as shell_execution_context_starts_with_literal_cd,
)
from .secret_file_request_services.github_pr_expansion import (
    _gh_pr_create_body_has_shell_command_substitution as _gh_pr_create_body_has_shell_command_substitution,
)
from .secret_file_request_services.github_shell_capabilities import (
    classify_github_shell_capabilities as classify_github_shell_capabilities,
)
from .secret_file_request_services.interpreter_trust import _pytest_args_from_segment as _pytest_args_from_segment
from .secret_file_request_services.read_only_filters import (
    _read_only_lookup_filter_grep_args_are_safe as _read_only_lookup_filter_grep_args_are_safe,
)
from .secret_file_request_services.read_only_filters import (
    _split_attached_redirection_token as _split_attached_redirection_token,
)
from .secret_file_request_services.request_artifacts import _candidate_command_texts as _candidate_command_texts
from .secret_file_request_services.request_artifacts import (
    build_file_read_request_artifact as build_file_read_request_artifact,
)
from .secret_file_request_services.request_artifacts import (
    build_file_write_request_artifact as build_file_write_request_artifact,
)
from .secret_file_request_services.request_models import FileReadRequestMatch as FileReadRequestMatch
from .secret_file_request_services.request_models import FileWriteRequestMatch as FileWriteRequestMatch
from .secret_file_request_services.request_models import ToolActionRequestMatch as ToolActionRequestMatch
from .secret_file_request_services.request_models import _normalize_tool_name as _normalize_tool_name
from .secret_file_request_services.request_models import classify_sensitive_path as classify_sensitive_path
from .secret_file_request_services.request_models import is_file_read_tool_name as is_file_read_tool_name
from .secret_file_request_services.sensitive_read_pipeline import _resolved_runtime_path as _resolved_runtime_path
from .secret_file_request_services.sensitive_read_pipeline import _runtime_entry_for_name as _runtime_entry_for_name
from .secret_file_request_services.shell_quote_parsing import (
    literal_cd_execution_context as literal_cd_execution_context,
)
from .secret_file_request_services.shell_static_safety import (
    _path_text_is_within_root_text as _path_text_is_within_root_text,
)
from .secret_file_request_services.shell_static_safety import (
    _script_has_aliased_risky_import as _script_has_aliased_risky_import,
)
from .secret_file_request_services.source_edit_context import (
    low_risk_compound_developer_execution_context as low_risk_compound_developer_execution_context,
)

_SERVICE_MODULES = (
    _constants_core,
    _constants_patterns,
    _request_models,
    _request_artifacts,
    _shell_tokenization,
    _docker_requests,
    _shell_static_safety,
    _read_only_filters,
    _github_shell_capabilities,
    _local_read_operands,
    _developer_inspection,
    _source_edit_context,
    _shell_quote_parsing,
    _github_pr_expansion,
    _github_pr_ephemeral_body,
    _python_pytest_entrypoints,
    _pytest_target_detection,
    _github_pr_body_safety,
    _sensitive_read_pipeline,
    _credential_exfiltration,
    _destructive_shell_detection,
    _interpreter_observers,
    _pytest_config_safety,
    _pytest_binary_safety,
    _typescript_graphql_safety,
    _node_generated_workflows,
    _node_heredoc_safety,
    _perl_read_only,
    _encoded_payloads,
    _upload_arguments,
    _network_upload_detection,
    _shell_stdin_sources,
    _interpreter_trust,
    _interpreter_launch,
    _interpreter_identity,
    _shell_request_classifier,
    _tool_action_requests,
    _benign_requests,
)
if TYPE_CHECKING:
    from .actions import GuardActionEnvelope
    from .command_evaluation import CompositeCommandEvaluation
    from .command_model import CanonicalCommand

for _service_module in _SERVICE_MODULES:
    _service_exports = getattr(_service_module, "__all__", None)
    if not isinstance(_service_exports, (list, tuple)) or not all(isinstance(name, str) for name in _service_exports):
        raise RuntimeError(f"invalid service export contract: {_service_module.__name__}")
    for _service_name in cast("tuple[str, ...] | list[str]", _service_exports):
        if not hasattr(_service_module, _service_name):
            raise RuntimeError(f"missing service export: {_service_module.__name__}.{_service_name}")
        globals().setdefault(_service_name, getattr(_service_module, _service_name))


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
    "_gh_pr_create_body_has_shell_command_substitution",
    "_normalize_tool_name",
    "_path_text_is_within_root_text",
    "_pytest_args_from_segment",
    "_read_only_lookup_filter_grep_args_are_safe",
    "_read_only_lookup_target_is_safe",
    "_read_small_runtime_text_file",
    "_resolved_runtime_path",
    "_runtime_entry_for_name",
    "_script_has_aliased_risky_import",
    "_split_attached_redirection_token",
    "build_file_read_request_artifact",
    "build_file_write_request_artifact",
    "build_tool_action_request_artifact",
    "classify_github_shell_capabilities",
    "classify_sensitive_path",
    "command_list_candidate_texts",
    "extract_sensitive_file_read_request",
    "extract_sensitive_file_read_request_from_action",
    "extract_sensitive_file_write_request",
    "extract_sensitive_tool_action_request",
    "is_explicitly_benign_native_file_read_request",
    "is_file_read_tool_name",
    "literal_cd_execution_context",
    "low_risk_compound_developer_execution_context",
    "shell_execution_context_starts_with_literal_cd",
]
