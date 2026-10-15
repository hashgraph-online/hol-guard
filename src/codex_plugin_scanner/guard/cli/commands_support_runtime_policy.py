"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from ..runtime.data_flow_sink import data_flow_sink_type
from ..runtime.package_request_evaluation import strip_review_evidence_tail as _strip_review_evidence_tail

if TYPE_CHECKING:
    from ._commands_shared import _HOOK_DAEMON_UNREACHABLE_REASON_MARKER, _now
    from .commands_support_prompts import _prompt_request_classes


from ..models import GuardAction
from ..native_data_flow import detect_data_flow_exfiltration
from ..native_hook_approval_context import native_hook_approval_context_token, runtime_hook_approval_context_inputs
from ..runtime.approval_context import approval_context_tokens_validation_reason
from ..runtime.command_extensions import risk_classes_for_command_action
from ..runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord
from ..store import runtime_tool_action_exact_match_context
from ..text import ensure_terminal_punctuation as _ensure_terminal_punctuation
from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_runtime_artifact_policy import (
    _runtime_artifact_command_action_floor,
    _runtime_artifact_policy_action,
)

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
    from ..approval_hook_copy import join_native_hook_reason

    return join_native_hook_reason(*values)

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
    review_url = _preferred_approval_review_url(response_payload, harness=harness)
    if review_url is None:
        from ..approval_hook_copy import approval_review_url_from_payload

        review_url = approval_review_url_from_payload(response_payload)
    if review_url is None:
        return None
    canonical_harness = _canonical_harness_name(harness)
    harness_label = {
        "claude-code": "Claude Code",
        "codex": "Codex",
        "copilot": "Copilot",
        "cursor": "Cursor",
        "devin": "Devin",
        "guard-cli": "package install",
        "opencode": "OpenCode",
        "kimi": "Kimi",
        "grok": "Grok",
        "pi": "Pi",
        "omp": "Oh My Pi",
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
        retry_instruction = _optional_string(decision_v2.get("retry_instruction"))
        decision_v2["retry_instruction"] = (
            _approval_center_routed_message(retry_instruction, review_context)
            if retry_instruction is not None and "hol-guard connect" in retry_instruction
            else review_context
        )

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

def _runtime_saved_policy_probe(
    *,
    harness: str,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace: str | None,
    memory: bool,
) -> dict[str, object]:
    """Describe one saved-decision probe for the resident runtime lookup."""

    probe: dict[str, object] = {
        "harness": harness,
        "artifact_id": artifact.artifact_id,
        "artifact_hash": artifact_hash,
        "workspace": workspace,
        "publisher": artifact.publisher,
        "exact_match_context": _runtime_artifact_exact_match_context(artifact),
        "risk_scoped": bool(_runtime_artifact_risk_classes(artifact)),
    }
    if memory:
        probe["memory"] = {
            "command": artifact.command,
            "artifact_type": artifact.artifact_type,
            "artifact_name": artifact.name,
        }
    return probe


def _runtime_saved_policy_decision(
    *,
    store: GuardStore,
    harness: str,
    artifact: GuardArtifact,
    artifact_hash: str,
    workspace: str | None,
    legacy_artifact_hash: str,
    legacy_workspace: str | None,
    alias_harness: str,
    alias_artifact: GuardArtifact | None,
    alias_artifact_hash: str | None,
    alias_workspace: str | None,
) -> tuple[Mapping[str, object], Mapping[str, object] | None]:
    """Return the saved-decision lookup and the decision this artifact may use.

    The resident composes the current-hash and legacy-hash lookups (a legacy
    decision wins only when strictly more severe, so a new exact allow never
    hides a retained pre-v1 block) and falls back to the Claude alias. Nothing
    is consumed: the runtime claims an accepted approval only after recomputing
    all current policy and scanner inputs.
    """

    from ..native_context import bind_context_digest_home

    bind_context_digest_home(getattr(store, "guard_home", None))
    current = _runtime_saved_policy_probe(
        harness=harness,
        artifact=artifact,
        artifact_hash=artifact_hash,
        workspace=workspace,
        memory=True,
    )
    legacy = {**current, "artifact_hash": legacy_artifact_hash, "workspace": legacy_workspace}
    alias = None
    if alias_artifact is not None and alias_artifact_hash is not None:
        alias = _runtime_saved_policy_probe(
            harness=alias_harness,
            artifact=alias_artifact,
            artifact_hash=alias_artifact_hash,
            workspace=alias_workspace,
            memory=False,
        )
    return store.resolve_runtime_saved_decision(current, legacy, alias)


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
    workflow_approval_record: GitHubWorkflowApprovalRecord | None = None,
) -> str:
    """Bind a saved hook approval to the exact reviewed runtime context.

    The resident composes the context dimensions and returns the token.
    """

    inputs = runtime_hook_approval_context_inputs(
        artifact=artifact,
        content_hash=content_hash,
        runtime_workspace=runtime_workspace,
        action_envelope=action_envelope,
        config=config,
        policy_config=_runtime_hook_effective_policy_config(config),
        evaluator_policy_version=_RUNTIME_HOOK_EVALUATOR_POLICY_VERSION,
        composition={
            "current_action": current_action,
            "current_config_action": current_config_action,
            "data_flow_action": data_flow_action,
            "package_action": package_action,
            "scanner_action": scanner_action,
            "trusted_cli_action": trusted_cli_action,
            "untrusted_payload_action": untrusted_payload_action,
        },
        current_action=current_action,
        risk_classes=_runtime_artifact_risk_classes(artifact),
        data_flow_signals=data_flow_signals,
        scanner_evidence=scanner_evidence,
        workflow_approval_record=workflow_approval_record,
    )
    return native_hook_approval_context_token("runtime_hook_approval_context", inputs)


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
        **(
            {
                "protection_posture": config.protection_posture,
                "protection_posture_explicit": True,
            }
            if config.protection_posture_explicit
            else {}
        ),
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
    if not isinstance(raw_command_text, str) or not raw_command_text:
        raw_command_text = artifact.command
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


def _artifact_risk_confidence(artifact: GuardArtifact) -> object:
    confidence = artifact.metadata.get("risk_confidence")
    if confidence is None:
        confidence = artifact.metadata.get("confidence")
    if isinstance(confidence, str) and confidence.strip():
        return confidence
    signals = artifact.metadata.get("risk_signals")
    if not isinstance(signals, Sequence) or isinstance(signals, (str, bytes)):
        return confidence
    for signal in signals:
        if not isinstance(signal, Mapping):
            continue
        signal_confidence = signal.get("confidence")
        if isinstance(signal_confidence, str) and signal_confidence.strip():
            return signal_confidence
    return confidence


def _artifact_skill_is_known_bad(artifact: GuardArtifact) -> bool:
    if artifact.metadata.get("known_bad_skill") is True:
        return True
    if artifact.metadata.get("skill_is_known_bad") is True:
        return True
    intel = artifact.metadata.get("threat_intel")
    return isinstance(intel, Mapping) and intel.get("known_bad") is True


def _artifact_writes_launch_agent(artifact: GuardArtifact) -> bool:
    if artifact.metadata.get("persistence_writes_launch_agent") is True:
        return True
    action_class = artifact.metadata.get("action_class")
    if not isinstance(action_class, str):
        return False
    lowered = action_class.lower()
    return any(token in lowered for token in ("launch agent", "login item", "launchctl", "cron", "systemd", "launchd"))


def _runtime_action_data_flow_signals(
    action_envelope: GuardActionEnvelope | None,
    *,
    workspace: Path | None,
    guard_home: Path | None = None,
) -> tuple[RiskSignalV2, ...]:
    if action_envelope is None:
        return ()
    return detect_data_flow_exfiltration(action_envelope, workspace=workspace, guard_home=guard_home)

def _runtime_data_flow_summary(signals: tuple[RiskSignalV2, ...]) -> str:
    sink_type = _runtime_data_flow_sink_type(signals)
    if signals:
        return f"This command sends local secret to {sink_type}. Guard kept raw secret contents out of the evidence."
    return f"This command sends local secret to {sink_type}."

_runtime_data_flow_sink_type = data_flow_sink_type

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


def _guard_settings_explain_payload(config: GuardConfig) -> dict[str, object]:
    from ..harness_posture import harness_posture_summary
    from ..protection_posture import (
        posture_help,
        posture_label,
        protection_status_fields,
    )

    effective = editable_guard_settings(config).get("risk_actions") or {}
    status = protection_status_fields(posture=config.protection_posture, mode=config.mode)
    return {
        "generated_at": _now(),
        "protection_posture": config.protection_posture,
        "label": posture_label(config.protection_posture),
        "description": posture_help(config.protection_posture),
        "security_level": config.security_level,
        "protection_off": status["protection_off"],
        **harness_posture_summary(config),
        "effective_risk_actions": effective,
    }


def _guard_settings_doctor_payload(config: GuardConfig) -> dict[str, object]:
    from ..harness_posture import harness_posture_summary
    from ..protection_posture import protection_status_fields

    issues: list[dict[str, str]] = []
    if config.protection_posture == "watch" or config.mode == "observe":
        issues.append(
            {
                "severity": "warning",
                "message": "Protection is off. Guard is only recording.",
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
        **protection_status_fields(posture=config.protection_posture, mode=config.mode),
        **harness_posture_summary(config),
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
    "_approval_center_routed_message", "_approval_delivery_payload",
    "_claude_notification_tool_display_name", "_claude_notification_tool_name", "_ensure_terminal_punctuation",
    "_guard_cli_settings_payload", "_guard_settings_doctor_payload", "_guard_settings_explain_payload",
    "_guard_settings_payload", "_is_cloud_inbox_url", "_localize_decision_v2_review_copy",
    "_localize_pending_approval_copy", "_native_approval_center_context", "_native_hook_reason",
    "_native_hook_reason_for_harness", "_runtime_action_data_flow_signals",
    "_runtime_artifact_command_action_floor", "_runtime_artifact_policy_action", "_runtime_artifact_risk_classes",
    "_runtime_data_flow_sink_type", "_runtime_data_flow_summary", "_runtime_detector_perf_payload",
    "_runtime_detector_registry_payload", "_strip_cloud_inbox_urls",
    "_strip_legacy_approval_center_sentence", "_strip_review_evidence_tail", "_terminal_action_message",
    "_terminalize_runtime_action_copy",
]
