"""Compatibility facade for runtime request-classification services.

The sensitive-request classifier is answered by the resident. The remaining
exports are the artifact builder and request helpers that runtime callers
still import from here.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..native_sensitive_request import native_sensitive_tool_action_request
from .secret_file_request_services.benign_requests import (
    build_tool_action_request_artifact as build_tool_action_request_artifact,
)
from .secret_file_request_services.github_shell_capabilities import (
    classify_github_shell_capabilities as classify_github_shell_capabilities,
)
from .secret_file_request_services.request_models import ToolActionRequestMatch as ToolActionRequestMatch
from .secret_file_request_services.source_edit_context import (
    low_risk_compound_developer_execution_context as low_risk_compound_developer_execution_context,
)

if TYPE_CHECKING:
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


__all__ = [
    "ToolActionRequestMatch",
    "build_tool_action_request_artifact",
    "classify_github_shell_capabilities",
    "extract_sensitive_tool_action_request",
    "low_risk_compound_developer_execution_context",
]
