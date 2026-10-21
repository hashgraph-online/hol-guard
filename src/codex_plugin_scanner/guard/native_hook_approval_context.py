"""Transport for native hook approval-context composition.

The resident's ``runtime_hook_approval_context`` and
``generic_hook_approval_context`` kinds own the whole saved-approval binding:
path normalization, shell execution-context branches, configured-environment
proof, launch identity, reuse nonces and the five-component token. This module
only projects Python objects into JSON request fields and returns the token.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from .native_context import context_digest_guard_home, native_context_digest

if TYPE_CHECKING:
    from .config import GuardConfig
    from .models import GuardArtifact
    from .runtime.actions import GuardActionEnvelope
    from .runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord

_METADATA_KEYS = (
    "command_security_identity",
    "env_keys",
    "env_values_hash",
    "envValuesHash",
    "interpreter_executable_identities",
    "shell_execution_context_complete",
    "shell_execution_context_hash",
    "shell_execution_context_hashes",
    "shell_execution_context_reason_code",
    "shell_execution_context_reason_codes",
    "shell_execution_effective_cwds",
    "tool_name",
)
_PAYLOAD_KEYS = (
    "artifact_hash",
    "changed_capabilities",
    "command",
    "event",
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "source_scope",
    "tool_name",
)


def _host() -> dict[str, object]:
    tilde_home = os.path.expanduser("~")
    try:
        cwd: str | None = os.getcwd()
    except OSError:
        cwd = None
    return {"tilde_home": None if tilde_home.startswith("~") else tilde_home, "cwd": cwd}


def _optional_path(path: Path | None) -> str | None:
    return str(path) if path is not None else None


def _envelope(action_envelope: GuardActionEnvelope | None) -> dict[str, object] | None:
    if action_envelope is None:
        return None
    raw_payload = action_envelope.raw_payload_redacted
    return {
        "action_type": action_envelope.action_type,
        "command": action_envelope.command,
        "event_name": action_envelope.event_name,
        "mcp_server": action_envelope.mcp_server,
        "mcp_tool": action_envelope.mcp_tool,
        "network_hosts": list(action_envelope.network_hosts),
        "package_intent_kind": action_envelope.package_intent_kind,
        "package_manager": action_envelope.package_manager,
        "package_name": action_envelope.package_name,
        "package_targets": list(action_envelope.package_targets),
        "permission_mode": raw_payload.get("permission_mode"),
        "permissionMode": raw_payload.get("permissionMode"),
        "script_name": action_envelope.script_name,
        "target_paths": list(action_envelope.target_paths),
        "tool_name": action_envelope.tool_name,
        "workspace": action_envelope.workspace,
        "workspace_hash": action_envelope.workspace_hash,
    }


def _evidence_payload(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    to_dict = getattr(value, "to_dict", None)
    return to_dict() if callable(to_dict) else str(value)


def _metadata(metadata: object) -> dict[str, object]:
    source = metadata if isinstance(metadata, dict) else {}
    projected = {key: source[key] for key in _METADATA_KEYS if key in source}
    environment = source.get("env")
    if isinstance(environment, Mapping):
        projected["env"] = [
            [key, value] for key, value in environment.items() if isinstance(key, str) and isinstance(value, str)
        ]
    for key in ("env_keys", "shell_execution_effective_cwds"):
        value = projected.get(key)
        if key not in projected:
            continue
        # Only string items can bind; ``effective_cwds`` was list-only.
        sequence = isinstance(value, list) or (
            key == "env_keys" and isinstance(value, Sequence) and not isinstance(value, str)
        )
        projected[key] = [item for item in value if isinstance(item, str)] if sequence and value is not None else None
    return projected


def runtime_hook_approval_context_inputs(
    *,
    artifact: GuardArtifact,
    content_hash: str,
    runtime_workspace: Path | None,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    policy_config: Mapping[str, object],
    evaluator_policy_version: str,
    composition: Mapping[str, object],
    current_action: str,
    risk_classes: Sequence[str],
    data_flow_signals: Sequence[object],
    scanner_evidence: Sequence[object],
    workflow_approval_record: GitHubWorkflowApprovalRecord | None,
) -> dict[str, object]:
    """Project one runtime hook evaluation into the native request fields."""

    from .runtime.extension_control_runtime import current_extension_control_binding_digest

    inputs: dict[str, object] = {
        "host": _host(),
        "extension_control_digest": current_extension_control_binding_digest(),
        "artifact": {
            "args": list(artifact.args),
            "artifact_id": artifact.artifact_id,
            "artifact_type": artifact.artifact_type,
            "command": artifact.command,
            "config_path": artifact.config_path,
            "harness": artifact.harness,
            "name": artifact.name,
            "publisher": artifact.publisher,
            "source_scope": artifact.source_scope,
            "transport": artifact.transport,
        },
        "metadata": _metadata(artifact.metadata),
        "content_hash": content_hash,
        "runtime_workspace": _optional_path(runtime_workspace),
        "configured_workspace": _optional_path(config.workspace),
        "guard_home": str(config.guard_home),
        "envelope": _envelope(action_envelope),
        "workflow_record": workflow_approval_record.to_dict() if workflow_approval_record is not None else None,
        "risk_classes": list(risk_classes),
        "data_flow_signals": [_evidence_payload(item) for item in data_flow_signals],
        "scanner_evidence": [_evidence_payload(item) for item in scanner_evidence],
        "policy_config": dict(policy_config),
        "evaluator_policy_version": evaluator_policy_version,
        "composition": dict(composition),
        "current_action": current_action,
        "sandbox_analysis": config.sandbox_analysis,
    }
    if not _launch_free(inputs):
        # Only a launch identity reads the environment; launch-free contexts
        # never transported it.
        inputs["ambient_env"] = dict(os.environ)
    return inputs


def generic_hook_approval_context_inputs(
    *,
    action_envelope: GuardActionEnvelope | None,
    artifact_id: str,
    artifact_name: str,
    canonical_harness: str,
    harness: str,
    publisher: str | None,
    home_dir: Path | None,
    runtime_workspace: Path | None,
    payload: Mapping[str, object],
    tool_command: str | None,
    config: GuardConfig,
    policy_config: Mapping[str, object],
    evaluator_policy_version: str,
    composition: Mapping[str, object],
    current_action: str,
) -> dict[str, object]:
    """Project one generic hook evaluation into the native request fields."""

    from .runtime.extension_control_runtime import current_extension_control_binding_digest

    return {
        "host": _host(),
        "ambient_env": dict(os.environ),
        "extension_control_digest": current_extension_control_binding_digest(),
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "canonical_harness": canonical_harness,
        "harness": harness,
        "publisher": publisher,
        "home_dir": _optional_path(home_dir),
        "runtime_workspace": _optional_path(runtime_workspace),
        "payload": {key: payload[key] for key in _PAYLOAD_KEYS if key in payload},
        # The whole payload, for the content digest the resident computes. The
        # projection above stays: the rest of the composition reads named
        # fields, and only the digest reads every key the harness sent.
        "payload_content": dict(payload),
        "tool_command": tool_command,
        "envelope": _envelope(action_envelope),
        "policy_config": dict(policy_config),
        "evaluator_policy_version": evaluator_policy_version,
        "composition": dict(composition),
        "current_action": current_action,
        "sandbox_analysis": config.sandbox_analysis,
    }


def _launch_free(inputs: Mapping[str, object]) -> bool:
    """Whether the old builder could finish without a launch-identity call."""

    metadata = inputs.get("metadata")
    if not isinstance(metadata, Mapping):
        return False
    shell_present = bool(metadata.get("shell_execution_context_hash") or metadata.get("shell_execution_context_hashes"))
    unresolved = shell_present and metadata.get("shell_execution_context_complete") is not True
    return unresolved or inputs.get("workflow_record") is not None


def native_hook_approval_context_token(kind: str, inputs: dict[str, object]) -> str:
    """Return the resident-built approval-context token for ``kind``.

    An unreachable resident degrades to the unbound sentinel only where the
    retired builder did (no launch identity needed); otherwise it raises, as
    the retired launch-identity call did.
    """

    from .runtime.approval_context import _context_digest_guard_home, _unbound_context_digest

    guard_home = context_digest_guard_home() or _context_digest_guard_home(str(Path.home()))
    result = native_context_digest(kind, {"inputs": inputs}, guard_home=guard_home)
    if result is None:
        if kind == "runtime_hook_approval_context" and _launch_free(inputs):
            return _unbound_context_digest("approval-context-token", material=inputs)
        raise ValueError("native_hook_approval_context_unavailable")
    token = result.get("token")
    if result.get("status") != "ok" or not isinstance(token, str):
        raise ValueError(f"native_hook_approval_context_rejected:{result.get('code')}")
    return token


__all__ = [
    "generic_hook_approval_context_inputs",
    "native_hook_approval_context_token",
    "runtime_hook_approval_context_inputs",
]
