"""Transport native classification, failing closed on every shell-context outage."""

from __future__ import annotations

from pathlib import Path

from ..shell_execution_context import ShellExecutionContext, model_shell_execution_context
from .request_models import ToolActionRequestMatch

_ACTION_CLASS = "process environment secret read"
_REASON = (
    "Guard treats commands that print process environment secrets as sensitive "
    "because they can expose cloud keys and credentials to the agent."
)


def environment_secret_dump_request(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    cwd: Path | None,
    home_dir: Path | None,
    execution_context: ShellExecutionContext | None = None,
) -> ToolActionRequestMatch | None:
    context = execution_context or model_shell_execution_context(
        command_text, cwd=cwd, workspace_root=cwd, home_dir=home_dir, classify_environment_secrets=True
    )
    if (
        context.native is None
        or context.environment_secret_scope != (command_text, cwd, home_dir)
        or type(context.environment_secret_dump) is not bool
    ):
        raise ValueError("native_environment_secret_dump_unavailable:invalid_result")
    if not context.environment_secret_dump:
        return None
    return ToolActionRequestMatch(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        action_class=_ACTION_CLASS,
        reason=_REASON,
    )


__all__ = ["environment_secret_dump_request"]
