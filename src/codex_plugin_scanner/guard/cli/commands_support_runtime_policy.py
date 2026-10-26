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
    from ._commands_shared import _now


from ..runtime.approval_context import approval_context_tokens_validation_reason
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

def _approval_delivery_payload(
    harness: str,
    *,
    managed_install: dict[str, object] | None = None,
) -> dict[str, object]:
    return approval_delivery_payload(approval_prompt_flow(harness, managed_install=managed_install))

def _native_hook_reason(*values: object | None) -> str:
    from ..approval_hook_copy import join_native_hook_reason

    return join_native_hook_reason(*values)

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


_runtime_data_flow_sink_type = data_flow_sink_type

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
    "_claude_notification_tool_name", "_ensure_terminal_punctuation",
    "_guard_cli_settings_payload", "_guard_settings_doctor_payload", "_guard_settings_explain_payload",
    "_guard_settings_payload", "_is_cloud_inbox_url", "_localize_decision_v2_review_copy",
    "_localize_pending_approval_copy", "_native_approval_center_context", "_native_hook_reason",
    "_runtime_artifact_command_action_floor", "_runtime_artifact_policy_action",
    "_runtime_data_flow_sink_type", "_runtime_detector_perf_payload",
    "_runtime_detector_registry_payload", "_strip_cloud_inbox_urls",
    "_strip_legacy_approval_center_sentence", "_strip_review_evidence_tail",
]
