"""The sensitive tool-action request model."""

from __future__ import annotations

from dataclasses import dataclass

from ..command_model import CanonicalCommand


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


__all__ = ["ToolActionRequestMatch"]
