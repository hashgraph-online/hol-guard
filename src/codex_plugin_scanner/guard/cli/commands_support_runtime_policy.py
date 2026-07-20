"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _HOOK_DAEMON_UNREACHABLE_REASON_MARKER, _now
    from .commands_support_prompts import _prompt_request_classes, _prompt_requires_hard_block


from ..action_lattice import coerce_guard_action, most_restrictive_guard_action, normalize_guard_action
from ..models import GuardAction
from ..proxy._env import _build_scrubbed_env
from ..runtime.approval_context import (
    approval_context_tokens_validation_reason,
    build_approval_context_token,
    build_configured_environment_hash,
    build_runtime_launch_identity,
)
from ..runtime.command_extensions import risk_classes_for_command_action
from ..store import _runtime_scoped_exact_match_key, runtime_tool_action_exact_match_context
from ..text import ensure_terminal_punctuation as _ensure_terminal_punctuation
from ._commands_shared import *
from .commands_parser_helpers import *

# Bump when runtime scanner or action-composition semantics change. Product and
# approval-surface versions deliberately do not participate in this identity.
_RUNTIME_HOOK_EVALUATOR_POLICY_VERSION = "runtime-hook-evaluation-v1"
_LOCAL_REVIEW_INSTRUCTION_RE = re.compile(
    re.escape("Review this request in HOL Guard, then retry."),
    re.IGNORECASE,
)
_LOCAL_APPROVAL_REQUEST_URL_RE = re.compile(r"https?://[^\s]+/requests(?:/[^\s]*)?", re.IGNORECASE)


def _runtime_artifacts_module():
    return importlib.import_module(".commands_support_runtime_artifacts", __package__)


def _interaction_module():
    return importlib.import_module(".commands_support_interaction", __package__)


def _runtime_resolution_module():
    return importlib.import_module(".commands_support_runtime_resolution", __package__)


def _optional_string(value: object | None) -> str | None:
    return _runtime_artifacts_module()._optional_string(value)


def _preferred_approval_review_url(response_payload: Mapping[str, object], *, harness: str) -> str | None:
    return _interaction_module()._preferred_approval_review_url(response_payload, harness=harness)


def _canonical_harness_name(value: str) -> str:
    return _runtime_resolution_module()._canonical_harness_name(value)


def _runtime_request_summary(artifact: GuardArtifact) -> str | None:
    return _runtime_resolution_module()._runtime_request_summary(artifact)


def _claude_notification_tool_name(payload: dict[str, object]) -> str | None:
    direct_name = _optional_string(payload.get("tool_name"))
    if direct_name is not None:
        return direct_name
    for key in ("message", "title"):
        value = _optional_string(payload.get(key))
        if value is None:
            continue
        match = re.search(r"\buse\s+([A-Za-z][A-Za-z0-9_]*)\b", value)
        if match is not None:
            return match.group(1)
    return None

def _claude_notification_tool_display_name(payload: dict[str, object]) -> str | None:
    tool_name = _claude_notification_tool_name(payload)
    if tool_name and tool_name.strip():
        return tool_name.strip()
    return None

def _approval_delivery_payload(
    harness: str,
    *,
    managed_install: dict[str, object] | None = None,
) -> dict[str, object]:
    return approval_delivery_payload(approval_prompt_flow(harness, managed_install=managed_install))

def _native_hook_reason(*values: object | None) -> str:
    messages: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            candidate = value.strip()
            if candidate not in messages:
                messages.append(candidate)
    if messages:
        return " ".join(messages)
    return "HOL Guard flagged this tool call for review."

def _native_hook_reason_for_harness(harness: str, *values: object | None) -> str:
    reason = _native_hook_reason(*values)
    if harness != "codex":
        return reason
    if "open hol guard to approve or keep this blocked:" in reason.lower():
        return reason
    if "approve it in hol guard, then retry." in reason.lower():
        return reason
    if _HOOK_DAEMON_UNREACHABLE_REASON_MARKER in reason.lower():
        return f"{reason} Restart HOL Guard, then retry."
    return f"{reason} Approve it in HOL Guard, then retry."

def _native_approval_center_context(response_payload: dict[str, object], *, harness: str) -> str | None:
    approval_center_url = response_payload.get("approval_center_url")
    if not isinstance(approval_center_url, str) or not approval_center_url.strip():
        return None
    review_url = _preferred_approval_review_url(response_payload, harness=harness) or approval_center_url.strip()
    canonical_harness = _canonical_harness_name(harness)
    harness_label = {
        "claude-code": "Claude Code",
        "codex": "Codex",
        "copilot": "Copilot",
        "guard-cli": "package install",
        "opencode": "OpenCode",
        "kimi": "Kimi",
        "grok": "Grok",
        "pi": "Pi",
    }.get(canonical_harness, "the harness")
    if canonical_harness in {
        "npm",
        "npx",
        "pnpm",
        "yarn",
        "bun",
        "pip",
        "pip3",
        "pipenv",
        "pipx",
        "poetry",
        "uv",
        "uvx",
        "cargo",
        "go",
        "composer",
        "bundle",
        "mvn",
        "gradle",
        "brew",
    }:
        harness_label = "package install"
    return (
        f"Open HOL Guard to approve or keep this blocked: {review_url}. "
        f"After you choose, retry the same {harness_label} action."
    )

def _localize_pending_approval_copy(response_payload: dict[str, object], *, harness: str) -> None:
    review_context = _native_approval_center_context(response_payload, harness=harness)
    if review_context is None:
        return
    queued = response_payload.get("approval_requests")
    review_url = _preferred_approval_review_url(response_payload, harness=harness)
    if review_url is None:
        return
    decision_v2 = response_payload.get("decision_v2_json")
    if isinstance(decision_v2, dict):
        _localize_decision_v2_review_copy(decision_v2, review_context)
    supply_chain_evaluation = response_payload.get("supply_chain_evaluation")
    if isinstance(supply_chain_evaluation, dict):
        user_copy = supply_chain_evaluation.get("user_copy")
        if isinstance(user_copy, dict):
            harness_message = _optional_string(user_copy.get("harness_message"))
            if harness_message is not None:
                user_copy["harness_message"] = _approval_center_routed_message(harness_message, review_context)
            user_copy["dashboard_url"] = review_url
    if isinstance(queued, list):
        for item in queued:
            if not isinstance(item, dict):
                continue
            decision_v2 = item.get("decision_v2_json")
            if isinstance(decision_v2, dict):
                _localize_decision_v2_review_copy(decision_v2, review_context)

def _localize_decision_v2_review_copy(decision_v2: dict[str, object], review_context: str) -> None:
    harness_message = _optional_string(decision_v2.get("harness_message"))
    if harness_message is not None:
        decision_v2["harness_message"] = _approval_center_routed_message(harness_message, review_context)
    action = _optional_string(decision_v2.get("action"))
    if action in {"ask", "block"}:
        decision_v2["retry_instruction"] = review_context

def _approval_center_routed_message(message: str, review_context: str) -> str:
    normalized = _strip_cloud_inbox_urls(message)
    normalized = normalized.replace("Review this request in HOL Guard, then retry.", "").strip()
    normalized = _strip_legacy_approval_center_sentence(normalized)
    normalized = " ".join(normalized.split())
    normalized = _strip_review_evidence_tail(normalized)
    if not normalized:
        return review_context
    return f"{_ensure_terminal_punctuation(normalized)} {review_context}"

def _terminal_action_message(message: str) -> str:
    normalized = _strip_cloud_inbox_urls(message)
    normalized = _strip_legacy_approval_center_sentence(normalized)
    normalized = _LOCAL_REVIEW_INSTRUCTION_RE.sub("", normalized)
    normalized = _LOCAL_APPROVAL_REQUEST_URL_RE.sub("", normalized)
    normalized = " ".join(normalized.split())
    return _strip_review_evidence_tail(normalized)

def _terminalize_runtime_action_copy(response_payload: dict[str, object]) -> None:
    decision_v2 = response_payload.get("decision_v2_json")
    if isinstance(decision_v2, dict):
        harness_message = _optional_string(decision_v2.get("harness_message"))
        if harness_message is not None:
            decision_v2["harness_message"] = _terminal_action_message(harness_message)
        decision_v2.pop("retry_instruction", None)
    supply_chain_evaluation = response_payload.get("supply_chain_evaluation")
    if isinstance(supply_chain_evaluation, dict):
        user_copy = supply_chain_evaluation.get("user_copy")
        if isinstance(user_copy, dict):
            harness_message = _optional_string(user_copy.get("harness_message"))
            if harness_message is not None:
                user_copy["harness_message"] = _terminal_action_message(harness_message)
            user_copy["dashboard_url"] = None

def _strip_review_evidence_tail(message: str) -> str:
    stripped = message.strip()
    lower_stripped = stripped.lower()
    for suffix in ("Review evidence: .", "Review evidence:.", "Review evidence:"):
        if lower_stripped.endswith(suffix.lower()):
            return stripped[: -len(suffix)].rstrip()
    return stripped

def _strip_legacy_approval_center_sentence(message: str) -> str:
    lower_message = message.lower()
    start = lower_message.find("open hol guard to approve or keep this blocked:")
    if start == -1:
        return message.strip()
    retry_start = lower_message.find("after you choose, retry the same ", start)
    if retry_start == -1:
        return message[:start].strip()
    end = lower_message.find(" action.", retry_start)
    if end == -1:
        return message[:start].strip()
    end += len(" action.")
    return f"{message[:start]} {message[end:]}".strip()

def _strip_cloud_inbox_urls(message: str) -> str:
    kept_tokens: list[str] = []
    for token in message.split():
        candidate = token.strip("([{<'\"")
        candidate = candidate.rstrip(")]}>'\".,;:!?")
        if _is_cloud_inbox_url(candidate):
            continue
        kept_tokens.append(token)
    return " ".join(kept_tokens).strip()

def _is_cloud_inbox_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return parsed.scheme in {"http", "https"} and parsed.path.rstrip("/") == "/guard/inbox"

def _runtime_stored_policy_decision(
    *,
    store: GuardStore,
    harness: str,
    artifact: GuardArtifact,
    artifact_id: str,
    artifact_hash: str,
    workspace: str | None,
    decision_lookup: Mapping[str, object] | None = None,
    consume_one_shot: bool = True,
) -> Mapping[str, object] | None:
    """Return a matching saved decision without conflating it with current policy.

    Runtime launch paths pass ``consume_one_shot=False`` and claim an accepted
    approval only after recomputing all current policy and scanner inputs.  The
    consuming default preserves the compatibility contract for older direct
    callers that use this helper outside the authoritative runtime path.
    """

    runtime_exact_match_context = _runtime_artifact_exact_match_context(artifact)
    ignored_local_integrity: Mapping[str, object] | None = None
    if isinstance(decision_lookup, Mapping):
        raw_decision = decision_lookup.get("decision")
        decision = raw_decision if isinstance(raw_decision, Mapping) else None
        raw_ignored_local_integrity = decision_lookup.get("ignored_local_integrity")
        ignored_local_integrity = (
            raw_ignored_local_integrity if isinstance(raw_ignored_local_integrity, Mapping) else None
        )
    else:
        if consume_one_shot:
            decision = store.resolve_policy_decision(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=artifact.publisher,
                runtime_exact_match_context=runtime_exact_match_context,
            )
        else:
            decision = store.resolve_policy_decision(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=artifact.publisher,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=False,
            )
    if decision is None and runtime_exact_match_context is not None and ignored_local_integrity is None:
        if consume_one_shot:
            legacy_decision = store.resolve_policy_decision(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=artifact.publisher,
            )
        else:
            legacy_decision = store.resolve_policy_decision(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=artifact.publisher,
                consume_one_shot=False,
            )
        if _optional_string((legacy_decision or {}).get("scope")) in {"harness", "global"}:
            decision = legacy_decision
    if decision is None:
        return None
    action = _optional_string(decision.get("action"))
    if action is None:
        return None
    scope = _optional_string(decision.get("scope"))
    if action == "allow" and approval_context_tokens_validation_reason(
        decision.get("artifact_hash"),
        artifact_hash,
    ) is None:
        # A valid v1 token already binds the exact request context. Broad
        # scopes are selectors only; they must not discard that exact token.
        return decision
    if (
        action in {"allow", "warn", "review"}
        and scope in {"workspace", "publisher", "harness", "global"}
        and _runtime_artifact_risk_classes(artifact)
    ):
        decision_artifact_id = _optional_string(decision.get("artifact_id"))
        if scope == "workspace":
            decision_artifact_hash = _optional_string(decision.get("artifact_hash"))
            if decision_artifact_id == artifact_id and (
                decision_artifact_hash is None or decision_artifact_hash == artifact_hash
            ):
                return decision
            return None
        if scope in {"harness", "global"}:
            decision_artifact_hash = _optional_string(decision.get("artifact_hash"))
            exact_match_keys = {
                key
                for key in (
                    _runtime_scoped_exact_match_key(artifact_id),
                    _runtime_scoped_exact_match_key(artifact_id, runtime_exact_match_context),
                )
                if key is not None
            }
            if not exact_match_keys:
                return decision if decision_artifact_id is not None else None
            return decision if decision_artifact_hash in exact_match_keys else None
        return None
    return decision


def _runtime_stored_policy_action(
    *,
    store: GuardStore,
    harness: str,
    artifact: GuardArtifact,
    artifact_id: str,
    artifact_hash: str,
    workspace: str | None,
    decision_lookup: Mapping[str, object] | None = None,
    consume_one_shot: bool = True,
) -> str | None:
    """Compatibility projection for callers that only need the saved action."""

    decision = _runtime_stored_policy_decision(
        store=store,
        harness=harness,
        artifact=artifact,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        workspace=workspace,
        decision_lookup=decision_lookup,
        consume_one_shot=consume_one_shot,
    )
    return _optional_string(decision.get("action")) if decision is not None else None


def _runtime_saved_allow_validation_reason(
    decision: Mapping[str, object],
    *,
    artifact: GuardArtifact,
    artifact_hash: str,
) -> str | None:
    """Require saved runtime allows to carry the complete current v1 context."""

    if _optional_string(decision.get("action")) != "allow":
        return None
    stored_hash = _optional_string(decision.get("artifact_hash"))
    return approval_context_tokens_validation_reason(stored_hash, artifact_hash)


def _runtime_hook_approval_context_token(
    *,
    artifact: GuardArtifact,
    content_hash: str,
    runtime_workspace: Path | None,
    action_envelope: GuardActionEnvelope | None,
    config: GuardConfig,
    current_config_action: GuardAction,
    trusted_cli_action: GuardAction | None,
    untrusted_payload_action: GuardAction | None,
    package_action: GuardAction | None,
    data_flow_action: GuardAction | None,
    scanner_action: GuardAction | None,
    current_action: GuardAction,
    data_flow_signals: Sequence[object],
    scanner_evidence: Sequence[object],
) -> str:
    """Bind a saved hook approval to the exact reviewed runtime context.

    The returned token intentionally partitions context into independently
    comparable dimensions.  Values are hashed by ``approval_context`` and are
    never serialized into the stored token itself.
    """

    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    shell_context_present = bool(
        metadata.get("shell_execution_context_hash") or metadata.get("shell_execution_context_hashes")
    )
    # Reuse requires the producer's explicit completeness proof.  Missing or
    # malformed legacy metadata fails closed instead of being inferred from a
    # separate reason-code field.
    shell_context_complete = metadata.get("shell_execution_context_complete") is True
    raw_effective_cwds = metadata.get("shell_execution_effective_cwds")
    effective_cwd_values = raw_effective_cwds if isinstance(raw_effective_cwds, list) else []
    shell_effective_cwds = tuple(
        _normalized_runtime_context_path(Path(value))
        for value in effective_cwd_values
        if isinstance(value, str) and value.strip()
    )
    launch_cwd = Path(shell_effective_cwds[-1]) if shell_effective_cwds else runtime_workspace or Path.cwd()
    if shell_effective_cwds:
        effective_cwd = shell_effective_cwds[-1]
    elif shell_context_present:
        effective_cwd = None
    else:
        effective_cwd = _normalized_runtime_context_path(runtime_workspace or Path.cwd())
    configured_workspace = (
        _normalized_runtime_context_path(config.workspace) if config.workspace is not None else None
    )
    envelope_workspace = (
        _normalized_runtime_context_path(Path(action_envelope.workspace))
        if action_envelope is not None and action_envelope.workspace is not None
        else None
    )
    executable_identity: object
    shell_executable_identities: tuple[dict[str, object], ...] | None = None
    if shell_context_present and not shell_context_complete:
        executable_identity = {
            "status": "unresolved_shell_execution_context",
            "reason_code": metadata.get("shell_execution_context_reason_code")
            or metadata.get("shell_execution_context_reason_codes"),
            "reuse_nonce": secrets.token_hex(16),
        }
        shell_executable_identities = (
            {
                "cwd": None,
                "identity": executable_identity,
            },
        )
    else:
        executable_identity = _runtime_hook_executable_identity(
            artifact,
            launch_cwd=launch_cwd,
        )
        if shell_context_present:
            shell_executable_identities = tuple(
                {
                    "cwd": cwd,
                    "identity": _runtime_hook_executable_identity(
                        artifact,
                        launch_cwd=Path(cwd),
                    ),
                }
                for cwd in shell_effective_cwds
            )
    return build_approval_context_token(
        identity={
            "artifact_id": artifact.artifact_id,
            "artifact_name": artifact.name,
            "artifact_type": artifact.artifact_type,
            "config_path": artifact.config_path,
            "configured_workspace": configured_workspace,
            "cwd": effective_cwd,
            "shell_effective_cwds": shell_effective_cwds,
            "shell_executables": shell_executable_identities,
            "envelope_workspace": envelope_workspace,
            "envelope_workspace_hash": action_envelope.workspace_hash if action_envelope is not None else None,
            "executable": executable_identity,
            "guard_home": _normalized_runtime_context_path(config.guard_home),
            "harness": artifact.harness,
            "publisher": artifact.publisher,
            "source_scope": artifact.source_scope,
        },
        content={
            "artifact_content_hash": content_hash,
            "command_security_identity": metadata.get("command_security_identity"),
            "shell_execution_context_hash": metadata.get("shell_execution_context_hash"),
            "shell_execution_context_hashes": metadata.get("shell_execution_context_hashes"),
            "shell_execution_context_reason_code": metadata.get("shell_execution_context_reason_code"),
            "shell_execution_context_reason_codes": metadata.get("shell_execution_context_reason_codes"),
        },
        capabilities={
            "action_envelope": _runtime_hook_action_capabilities(action_envelope),
            "artifact_type": artifact.artifact_type,
            "data_flow_signals": [_runtime_hook_evidence_payload(item) for item in data_flow_signals],
            "risk_classes": _runtime_artifact_risk_classes(artifact),
            "scanner_evidence": [_runtime_hook_evidence_payload(item) for item in scanner_evidence],
            "transport": artifact.transport,
        },
        policy={
            "config": _runtime_hook_effective_policy_config(config),
            "evaluator_policy_version": _RUNTIME_HOOK_EVALUATOR_POLICY_VERSION,
            "composition": {
                "current_action": current_action,
                "current_config_action": current_config_action,
                "data_flow_action": data_flow_action,
                "package_action": package_action,
                "scanner_action": scanner_action,
                "trusted_cli_action": trusted_cli_action,
                "untrusted_payload_action": untrusted_payload_action,
            },
        },
        sandbox={
            "analysis": config.sandbox_analysis,
            "required": current_action == "sandbox-required",
        },
    )


def _runtime_hook_effective_policy_config(config: GuardConfig) -> dict[str, object]:
    """Return effective settings that can change enforcement or risk evidence."""

    return {
        "artifact_actions": dict(config.artifact_actions or {}),
        "changed_hash_action": config.changed_hash_action,
        "default_action": config.default_action,
        "harness_actions": dict(config.harness_actions or {}),
        "harness_risk_actions": {
            harness: dict(actions) for harness, actions in (config.harness_risk_actions or {}).items()
        },
        "install_owner": config.install_owner,
        "managed_locked_settings": list(config.managed_locked_settings),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        "new_network_domain_action": config.new_network_domain_action,
        "publisher_actions": dict(config.publisher_actions or {}),
        "risk_actions": dict(config.risk_actions or {}),
        "runtime_detector_disabled_ids": list(config.runtime_detector_disabled_ids),
        "runtime_detector_registry": config.runtime_detector_registry,
        "runtime_detector_timeout_ms": config.runtime_detector_timeout_ms,
        "security_level": config.security_level,
        "subprocess_action": config.subprocess_action,
        "unknown_publisher_action": config.unknown_publisher_action,
    }


def _runtime_hook_action_capabilities(action_envelope: GuardActionEnvelope | None) -> dict[str, object] | None:
    if action_envelope is None:
        return None
    return {
        "action_type": action_envelope.action_type,
        "mcp_server": action_envelope.mcp_server,
        "mcp_tool": action_envelope.mcp_tool,
        "network_hosts": list(action_envelope.network_hosts),
        "package_intent_kind": action_envelope.package_intent_kind,
        "package_manager": action_envelope.package_manager,
        "package_name": action_envelope.package_name,
        "package_targets": list(action_envelope.package_targets),
        "script_name": action_envelope.script_name,
        "target_paths": list(action_envelope.target_paths),
        "tool_name": action_envelope.tool_name,
    }


def _runtime_hook_evidence_payload(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    to_dict = getattr(value, "to_dict", None)
    return to_dict() if callable(to_dict) else str(value)


def _runtime_hook_executable_identity(
    artifact: GuardArtifact,
    *,
    launch_cwd: Path,
) -> dict[str, object]:
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    raw_environment = metadata.get("env")
    configured_environment = (
        {
            str(key): str(value)
            for key, value in raw_environment.items()
            if isinstance(key, str) and isinstance(value, str)
        }
        if isinstance(raw_environment, Mapping)
        else {}
    )
    raw_env_keys = metadata.get("env_keys")
    configured_env_keys = tuple(
        sorted(
            {
                *configured_environment,
                *(
                    (item for item in raw_env_keys if isinstance(item, str) and item)
                    if isinstance(raw_env_keys, Sequence) and not isinstance(raw_env_keys, str)
                    else ()
                ),
            }
        )
    )
    provided_env_values_hash = _optional_string(
        metadata.get("env_values_hash") or metadata.get("envValuesHash")
    )
    computed_env_values_hash = (
        build_configured_environment_hash(
            configured_environment,
            configured_keys=configured_env_keys,
        )
        if configured_environment or not configured_env_keys
        else None
    )
    launch_env = _build_scrubbed_env(configured_environment)
    launch_identity = build_runtime_launch_identity(
        artifact.command,
        args=artifact.args,
        structured_command=artifact.artifact_type != "tool_action_request",
        search_path=launch_env.get("PATH"),
        cwd=launch_cwd,
        launch_env=launch_env,
    )
    missing_value_keys = tuple(key for key in configured_env_keys if key not in configured_environment)
    unavailable_values = bool(missing_value_keys) and provided_env_values_hash is None
    code_loading_keys = {"BASH_ENV", "ENV", "NODE_OPTIONS", "PYTHONINSPECT", "PYTHONPATH", "ZDOTDIR"}
    unresolved_code_loading_environment = bool(code_loading_keys.intersection(missing_value_keys))
    configured_environment_identity: dict[str, object] = {
        "computed_values_hash": computed_env_values_hash,
        "keys": list(configured_env_keys),
        "provided_values_hash": provided_env_values_hash,
        "values_hash": provided_env_values_hash if missing_value_keys else computed_env_values_hash,
        "provided_values_hash_matches": (
            provided_env_values_hash == computed_env_values_hash
            if provided_env_values_hash is not None and computed_env_values_hash is not None
            else None
        ),
        "status": (
            "unproven"
            if unavailable_values or unresolved_code_loading_environment
            else "verified"
        ),
    }
    if unavailable_values or unresolved_code_loading_environment:
        configured_environment_identity["reuse_nonce"] = secrets.token_hex(16)
    return {
        "artifact_command": artifact.command,
        "artifact_tool": metadata.get("tool_name"),
        "configured_environment": configured_environment_identity,
        "launch_argv_sha256": launch_identity["argv_sha256"],
        "launch_cwd": launch_identity["launch_cwd"],
        "resolved_artifact_command": launch_identity["executable"],
        "resolved_entrypoint": launch_identity["entrypoint"],
        "transport": artifact.transport,
    }


def _normalized_runtime_context_path(path: Path) -> str:
    try:
        return str(path.expanduser().resolve(strict=False))
    except (OSError, RuntimeError):
        return str(path.expanduser().absolute())


def _remembered_rule_rejection_reason(
    *,
    response_payload: dict[str, object],
    artifact: GuardArtifact,
) -> str | None:
    rejection = response_payload.get("remembered_rule_rejection")
    if not isinstance(rejection, Mapping):
        return None
    trust_status = rejection.get("trust_status")
    remembered_rules = (
        str(trust_status.get("remembered_rules") or "unknown") if isinstance(trust_status, Mapping) else "unknown"
    )
    if remembered_rules != "disabled_degraded":
        return None
    integrity_message = _optional_string(rejection.get("integrity_message"))
    artifact_summary = _runtime_request_summary(artifact) or artifact.name
    if isinstance(integrity_message, str) and integrity_message.strip():
        message = integrity_message.strip()
        detail = f" {message if message.endswith('.') else message + '.'}"
    else:
        detail = ""
    return (
        f"HOL Guard kept {artifact_summary} in review because a remembered local rule was ignored while local trust "
        f"is degraded.{detail} One-time approvals still work, but broader remembered rules stay limited until local "
        f"trust is protected."
    )


def _runtime_artifact_exact_match_context(artifact: GuardArtifact) -> str | None:
    if artifact.artifact_type != "tool_action_request":
        return None
    raw_command_text = artifact.metadata.get("raw_command_text")
    wrapper_chain = artifact.metadata.get("wrapper_chain")
    normalized_wrapper_chain = (
        wrapper_chain if isinstance(wrapper_chain, Sequence) and not isinstance(wrapper_chain, str) else None
    )
    return runtime_tool_action_exact_match_context(
        config_path=artifact.config_path,
        source_scope=artifact.source_scope,
        raw_command_text=raw_command_text if isinstance(raw_command_text, str) else None,
        wrapper_chain=normalized_wrapper_chain,
    )
def _runtime_artifact_policy_action(config: GuardConfig, artifact: GuardArtifact, harness: str) -> GuardAction:
    if _prompt_requires_hard_block(artifact):
        return "block"
    canonical_harness = _canonical_harness_name(harness)
    configured_override = config.resolve_action_override(
        canonical_harness,
        artifact.artifact_id,
        artifact.publisher,
    )

    def with_config_policy(action: GuardAction) -> GuardAction:
        # Artifact/publisher/harness settings are more-specific resolutions of
        # the global default, not additional inputs.  Scanner/risk results are
        # independent and therefore remain a floor even for an exact allow.
        current_config_action = configured_override if configured_override is not None else config.default_action
        return most_restrictive_guard_action(action, current_config_action)

    risk_classes = _runtime_artifact_risk_classes(artifact)
    has_configured_risk_action = any(
        _resolve_configured_risk_action(config, risk_class, harness=canonical_harness) for risk_class in risk_classes
    )
    if has_configured_risk_action:
        risk_actions = [
            _resolve_configured_risk_action(config, risk_class, harness=canonical_harness)
            or resolve_risk_action(config, risk_class, harness=canonical_harness)
            for risk_class in risk_classes
        ]
        resolved_actions = [action for action in risk_actions if coerce_guard_action(action) is not None]
        if resolved_actions:
            return with_config_policy(most_restrictive_guard_action(*resolved_actions))
    guard_default_action = _runtime_artifact_guard_default_action(artifact)
    risk_actions = [resolve_risk_action(config, risk_class, harness=canonical_harness) for risk_class in risk_classes]
    resolved_actions = [action for action in risk_actions if coerce_guard_action(action) is not None]
    if resolved_actions:
        resolved = most_restrictive_guard_action(*resolved_actions)
        resolved_with_default = (
            most_restrictive_guard_action(resolved, guard_default_action)
            if guard_default_action is not None
            else resolved
        )
        return with_config_policy(resolved_with_default)
    if guard_default_action is not None:
        return with_config_policy(guard_default_action)
    return with_config_policy(SAFE_CHANGED_HASH_ACTION)

def _resolve_configured_risk_action(config: GuardConfig, risk_class: str, *, harness: str) -> str | None:
    if config.harness_risk_actions is not None:
        harness_actions = config.harness_risk_actions.get(harness)
        if harness_actions is not None and risk_class in harness_actions:
            return harness_actions[risk_class]
    if config.risk_actions is not None and risk_class in config.risk_actions:
        return config.risk_actions[risk_class]
    return None

def _runtime_artifact_guard_default_action(artifact: GuardArtifact) -> GuardAction | None:
    value = artifact.metadata.get("guard_default_action")
    return normalize_guard_action(value, unknown_action="require-reapproval") if value is not None else None

def _runtime_action_data_flow_signals(
    action_envelope: GuardActionEnvelope | None,
    *,
    workspace: Path | None,
) -> tuple[RiskSignalV2, ...]:
    if action_envelope is None:
        return ()
    return detect_data_flow_exfiltration(action_envelope, workspace=workspace)

def _runtime_data_flow_summary(signals: tuple[RiskSignalV2, ...]) -> str:
    sink_type = _runtime_data_flow_sink_type(signals)
    if signals:
        return f"This command sends local secret to {sink_type}. Guard kept raw secret contents out of the evidence."
    return f"This command sends local secret to {sink_type}."

def _runtime_data_flow_sink_type(signals: tuple[RiskSignalV2, ...]) -> str:
    signal_ids = {signal.signal_id for signal in signals}
    if any(signal.category == "network" for signal in signals):
        return "network host"
    if "data-flow:clipboard-secret" in signal_ids:
        return "clipboard"
    if "data-flow:world-readable-temp-secret" in signal_ids:
        return "world-readable temp file"
    if "data-flow:git-remote-token" in signal_ids:
        return "git remote configuration"
    return "external sink"

def _runtime_artifact_risk_classes(artifact: GuardArtifact) -> list[str]:
    risk_classes: list[str] = []
    composite_risk_classes = artifact.metadata.get("risk_classes")
    if isinstance(composite_risk_classes, list):
        risk_classes.extend(
            value.strip() for value in composite_risk_classes if isinstance(value, str) and value.strip()
        )
    if artifact.artifact_type == "file_read_request":
        risk_classes.append("local_secret_read")
        return list(dict.fromkeys(risk_classes))
    if artifact.artifact_type == "package_request":
        risk_classes.append("package_script")
        return list(dict.fromkeys(risk_classes))
    if artifact.artifact_type == "prompt_request":
        prompt_classes = _prompt_request_classes(artifact)
        if "secret_read" in prompt_classes:
            risk_classes.append("local_secret_read")
        if "exfil_intent" in prompt_classes:
            risk_classes.append("credential_exfiltration")
        if "destructive_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        if "subprocess_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        if "prompt_injection_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        return list(dict.fromkeys(risk_classes))
    if artifact.artifact_type != "tool_action_request":
        return list(dict.fromkeys(risk_classes))
    action_class = artifact.metadata.get("action_class")
    if isinstance(action_class, str):
        risk_classes.extend(risk_classes_for_command_action(action_class))
    return list(dict.fromkeys(risk_classes))

def _guard_settings_payload(config: GuardConfig) -> dict[str, object]:
    return {
        "generated_at": _now(),
        "guard_home": str(config.guard_home),
        "config_path": str(config.guard_home / "config.toml"),
        "settings": editable_guard_settings(config),
    }

_PRESET_DESCRIPTIONS: dict[str, str] = {
    "gentle": (
        "Warn-only mode. All risky actions surface as warnings so you stay informed "
        "without blocking any agent workflows."
    ),
    "balanced": (
        "Default preset. High-severity actions (secret reads, exfiltration) require "
        "re-approval; network egress is warned."
    ),
    "strict": (
        "Elevated protection. Data-flow exfiltration is blocked; all other high-risk "
        "actions require explicit re-approval."
    ),
    "paranoid": (
        "Maximum protection. Every risk class is blocked outright. "
        "Recommended for high-security or air-gapped environments."
    ),
    "custom": "Fully custom action map. Each risk class uses the action you configured explicitly.",
}

def _guard_settings_explain_payload(config: GuardConfig) -> dict[str, object]:
    preset = config.security_level
    description = _PRESET_DESCRIPTIONS.get(preset, f"Unknown preset '{preset}'.")
    effective = editable_guard_settings(config).get("risk_actions") or {}
    return {
        "generated_at": _now(),
        "preset": preset,
        "description": description,
        "effective_risk_actions": effective,
    }

def _guard_settings_doctor_payload(config: GuardConfig) -> dict[str, object]:
    issues: list[dict[str, str]] = []
    if config.mode == "observe":
        issues.append(
            {
                "severity": "warning",
                "message": "Guard is in observe mode. No actions will be blocked or reviewed.",
            }
        )
    if config.security_level not in VALID_SECURITY_LEVELS:
        fallback = DEFAULT_SECURITY_LEVEL
        issues.append(
            {
                "severity": "error",
                "message": f"Unknown security level '{config.security_level}'. Falling back to '{fallback}'.",
            }
        )
    if config.approval_wait_timeout_seconds < 10:
        issues.append(
            {
                "severity": "warning",
                "message": (
                    f"approval_wait_timeout_seconds={config.approval_wait_timeout_seconds} is very low. "
                    "Approvals may time out before you can respond."
                ),
            }
        )
    return {
        "generated_at": _now(),
        "issues": issues,
        "healthy": len(issues) == 0,
    }

def _guard_cli_settings_payload(config: GuardConfig) -> dict[str, object]:
    payload = _guard_settings_payload(config)
    settings = payload.get("settings")
    if not isinstance(settings, dict):
        return payload
    cli_settings = dict(settings)
    cli_settings.pop("billing", None)
    return {
        **payload,
        "settings": cli_settings,
    }

def _runtime_detector_registry_payload(config: GuardConfig) -> dict[str, object]:
    return {
        "enabled": config.runtime_detector_registry,
        "debug_trace": config.runtime_detector_debug_trace,
        "timeout_ms": config.runtime_detector_timeout_ms,
        "disabled_detector_ids": list(config.runtime_detector_disabled_ids),
    }

def _runtime_detector_perf_payload(config: GuardConfig) -> list[dict[str, object]]:
    from ..runtime.actions import GuardActionEnvelope
    from ..runtime.detectors import (
        _SLOW_DETECTOR_THRESHOLD_MS,
        DetectorContext,
    )
    from ..runtime.runner import _get_default_detector_registry

    probe_action = GuardActionEnvelope(
        schema_version=1,
        action_id="perf-probe",
        harness="doctor",
        event_name="HarnessStart",
        action_type="harness_start",
        workspace=None,
        workspace_hash=None,
        tool_name=None,
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )
    probe_context = DetectorContext(
        config=config,
        workspace=None,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    result = _get_default_detector_registry().run(
        probe_action,
        probe_context,
        timeout_ms=config.runtime_detector_timeout_ms,
        disabled_detector_ids=config.runtime_detector_disabled_ids,
    )
    return [
        {
            **t.to_dict(),
            "slow": t.elapsed_ms >= _SLOW_DETECTOR_THRESHOLD_MS,
        }
        for t in result.telemetry
    ]

__all__ = [
    "_PRESET_DESCRIPTIONS", "_approval_center_routed_message", "_approval_delivery_payload",
    "_claude_notification_tool_display_name", "_claude_notification_tool_name", "_ensure_terminal_punctuation",
    "_guard_cli_settings_payload", "_guard_settings_doctor_payload", "_guard_settings_explain_payload",
    "_guard_settings_payload", "_is_cloud_inbox_url", "_localize_decision_v2_review_copy",
    "_localize_pending_approval_copy", "_native_approval_center_context", "_native_hook_reason",
    "_native_hook_reason_for_harness", "_resolve_configured_risk_action", "_runtime_action_data_flow_signals",
    "_runtime_artifact_guard_default_action", "_runtime_artifact_policy_action", "_runtime_artifact_risk_classes",
    "_runtime_data_flow_sink_type", "_runtime_data_flow_summary", "_runtime_detector_perf_payload",
    "_runtime_detector_registry_payload", "_runtime_stored_policy_action", "_strip_cloud_inbox_urls",
    "_strip_legacy_approval_center_sentence", "_strip_review_evidence_tail", "_terminal_action_message",
    "_terminalize_runtime_action_copy",
]
