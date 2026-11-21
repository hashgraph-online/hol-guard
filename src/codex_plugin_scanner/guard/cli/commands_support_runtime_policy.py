"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now


from ._commands_shared import *
from .commands_parser_helpers import *

# Bump when runtime scanner or action-composition semantics change. Product and
# approval-surface versions deliberately do not participate in this identity.


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


def _approval_delivery_payload(
    harness: str,
    *,
    managed_install: dict[str, object] | None = None,
) -> dict[str, object]:
    return approval_delivery_payload(approval_prompt_flow(harness, managed_install=managed_install))

_COPY_FIELDS = ("harness_message", "action", "retry_instruction")


def _copy_fields(decision_v2: dict[str, object]) -> dict[str, str]:
    return {key: value for key in _COPY_FIELDS if isinstance(value := decision_v2.get(key), str)}


# Each native request stays well under the runner's request bound, so a long
# approval queue is routed in several calls instead of failing as one.
_APPROVAL_COPY_BATCH_BYTES = 1024 * 1024


def _copy_batches(fields: list[dict[str, str]]) -> list[list[dict[str, str]]]:
    batches: list[list[dict[str, str]]] = [[]]
    size = 0
    for item in fields:
        cost = sum(len(value.encode("utf-8")) for value in item.values()) + 64
        if batches[-1] and size + cost > _APPROVAL_COPY_BATCH_BYTES:
            batches.append([])
            size = 0
        batches[-1].append(item)
        size += cost
    return batches


def _approval_copy(
    review_url: str,
    *,
    harness: str,
    decisions: list[dict[str, object]] | None = None,
    user_copy_message: str | None = None,
) -> dict[str, object] | None:
    """Ask the native runtime to route review copy to the local approval center.

    The copy is display only, so an unavailable runtime leaves it unchanged.
    """
    from ..native_runner_authority import (
        NativeRunnerAuthorityError,
        NativeRunnerAuthorityRefusalError,
        native_runner_authority,
    )

    result: dict[str, object] | None = None
    patches: list[object] = []
    batches = _copy_batches([_copy_fields(decision_v2) for decision_v2 in decisions or []])
    for batch in batches:
        args = {
            "harness": _canonical_harness_name(harness),
            "review_url": review_url,
            "decisions": batch,
            # The message rides with every batch until one answers, so a
            # refused first batch does not leave it unrouted.
            "user_copy_message": user_copy_message if result is None else None,
        }
        try:
            answer = native_runner_authority("approval_copy", args)
        except NativeRunnerAuthorityRefusalError:
            answer = None
        except NativeRunnerAuthorityError:
            # An unavailable resident would cost every later batch its own
            # budget, so the remaining copy stays unchanged instead.
            break
        if result is None and answer is not None:
            result = answer
        routed = answer.get("decisions") if answer is not None else None
        if isinstance(routed, list) and len(routed) == len(batch):
            patches.extend(routed)
        else:
            # A refused batch keeps its original copy; the others still route.
            patches.extend([None] * len(batch))
    if result is not None:
        result["decisions"] = patches + [None] * (sum(len(batch) for batch in batches) - len(patches))
    return result

def _native_approval_center_context(response_payload: dict[str, object], *, harness: str) -> str | None:
    review_url = _preferred_approval_review_url(response_payload, harness=harness)
    if review_url is None:
        from ..approval_hook_copy import approval_review_url_from_payload

        review_url = approval_review_url_from_payload(response_payload)
    if review_url is None:
        return None
    result = _approval_copy(review_url, harness=harness)
    return None if result is None else _optional_string(result.get("review_context"))

def _localize_pending_approval_copy(response_payload: dict[str, object], *, harness: str) -> None:
    review_url = _preferred_approval_review_url(response_payload, harness=harness)
    if review_url is None:
        return
    decisions: list[dict[str, object]] = []
    decision_v2 = response_payload.get("decision_v2_json")
    if isinstance(decision_v2, dict):
        decisions.append(decision_v2)
    queued = response_payload.get("approval_requests")
    if isinstance(queued, list):
        for item in queued:
            if isinstance(item, dict) and isinstance(item_decision := item.get("decision_v2_json"), dict):
                decisions.append(item_decision)
    supply_chain_evaluation = response_payload.get("supply_chain_evaluation")
    user_copy = supply_chain_evaluation.get("user_copy") if isinstance(supply_chain_evaluation, dict) else None
    user_copy_message = None
    if isinstance(user_copy, dict):
        message = user_copy.get("harness_message")
        user_copy_message = message if isinstance(message, str) else None
        user_copy["dashboard_url"] = review_url
    result = _approval_copy(
        review_url,
        harness=harness,
        decisions=decisions,
        user_copy_message=user_copy_message,
    )
    if result is None:
        return
    patches = result.get("decisions")
    if isinstance(patches, list):
        for decision, patch in zip(decisions, patches, strict=False):
            if isinstance(patch, dict):
                decision.update({key: value for key, value in patch.items() if isinstance(value, str)})
    routed_user_copy = result.get("user_copy_message")
    if isinstance(user_copy, dict) and isinstance(routed_user_copy, str):
        user_copy["harness_message"] = routed_user_copy

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
    "_approval_delivery_payload",
    "_guard_cli_settings_payload", "_guard_settings_doctor_payload", "_guard_settings_explain_payload",
    "_guard_settings_payload",
    "_localize_pending_approval_copy", "_native_approval_center_context",
    "_runtime_detector_perf_payload",
    "_runtime_detector_registry_payload",
]
