"""Detection, detector and prompt-artifact evaluation inputs for Guard wrapper-mode runs."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..models import GuardArtifact, HarnessDetection
from ..native_prompt import NativePromptAnalysisError
from ..native_prompt import analyze as _prompt_analyze_native
from ..native_prompt import artifact_from_dict as _guard_artifact_from_dict
from ..native_prompt import extract_prompt_requests as extract_prompt_requests
from ..native_prompt import should_force_reapproval as should_force_reapproval
from ..store import GuardStore
from ..types import PromptRequest
from . import runner_native_authority as _authority
from .actions import GuardActionEnvelope, redacted_workspace_label
from .detectors import DetectorContext, DetectorRegistry, DetectorRunResult, register_default_detectors


def detect_harness(harness: str, context: HarnessContext) -> HarnessDetection:
    from ..consumer import detect_harness as _detect_harness

    return _detect_harness(harness, context)


def evaluate_detection(
    detection: HarnessDetection,
    store: GuardStore,
    config: GuardConfig,
    *,
    default_action: str | None = None,
    persist: bool = True,
    trusted_request_overrides: Mapping[str, str] | None = None,
    trusted_request_override_labels: Mapping[str, str] | None = None,
    pending_approval_claims: list[tuple[Mapping[str, object], str, str]] | None = None,
    claimed_saved_approval_overrides: Mapping[str, str] | None = None,
    retained_saved_approval_overrides: Mapping[str, str] | None = None,
    saved_approval_qualification_overrides: Mapping[str, Mapping[str, object]] | None = None,
    runtime_detector_context: Mapping[str, object] | None = None,
    runtime_detector_block_reason: str | None = None,
):
    from ..consumer.service import evaluate_detection as _evaluate_detection

    return _evaluate_detection(
        detection,
        store,
        config,
        default_action=default_action,
        persist=persist,
        trusted_request_overrides=trusted_request_overrides,
        trusted_request_override_labels=trusted_request_override_labels,
        pending_approval_claims=pending_approval_claims,
        claimed_saved_approval_overrides=claimed_saved_approval_overrides,
        retained_saved_approval_overrides=retained_saved_approval_overrides,
        saved_approval_qualification_overrides=saved_approval_qualification_overrides,
        runtime_detector_context=runtime_detector_context,
        runtime_detector_block_reason=runtime_detector_block_reason,
    )


_DEFAULT_DETECTOR_REGISTRY: tuple[Callable[[], tuple[Any, ...]], DetectorRegistry] | None = None
_DEFAULT_DETECTOR_REGISTRY_LOCK = threading.Lock()


def _get_default_detector_registry() -> DetectorRegistry:
    factory = register_default_detectors
    cached = _DEFAULT_DETECTOR_REGISTRY
    if cached is not None and cached[0] is factory:
        return cached[1]
    with _DEFAULT_DETECTOR_REGISTRY_LOCK:
        cached = _DEFAULT_DETECTOR_REGISTRY
        if cached is None or cached[0] is not factory:
            cached = (factory, DetectorRegistry(factory()))
            globals()["_DEFAULT_DETECTOR_REGISTRY"] = cached
    return cached[1]


def _guard_run_action_envelope(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
) -> GuardActionEnvelope:
    workspace = context.workspace_dir
    workspace_hash = None
    if workspace is not None:
        workspace_path = workspace.expanduser()
        with suppress(OSError):
            workspace_path = workspace_path.resolve()
        workspace_hash = hashlib.sha256(str(workspace_path).encode("utf-8")).hexdigest()
    return GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness=harness,
        event_name="HarnessStart",
        action_type="harness_start",
        workspace=redacted_workspace_label(workspace, home_dir=context.home_dir),
        workspace_hash=workspace_hash,
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
        raw_payload_redacted={"passthrough_arg_count": len(passthrough_args)},
    )


def _evaluation_with_action_envelope(
    evaluation: dict[str, Any],
    action_envelope: GuardActionEnvelope,
) -> dict[str, Any]:
    artifacts = evaluation.get("artifacts")
    if not isinstance(artifacts, list):
        return evaluation
    action_payload = action_envelope.to_dict()
    normalized_artifacts: list[object] = []
    changed = False
    for item in artifacts:
        if isinstance(item, dict) and "action_envelope_json" not in item:
            normalized_artifacts.append({**item, "action_envelope_json": action_payload})
            changed = True
        else:
            normalized_artifacts.append(item)
    if not changed:
        return evaluation
    return {**evaluation, "artifacts": normalized_artifacts}


def _evaluation_with_detector_registry(
    evaluation: dict[str, Any],
    action_envelope: GuardActionEnvelope,
    context: HarnessContext,
    config: GuardConfig,
) -> dict[str, Any]:
    if not config.runtime_detector_registry:
        return evaluation
    detector_context = DetectorContext(
        config=config,
        workspace=context.workspace_dir,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
        guard_home=context.guard_home,
    )
    result = _get_default_detector_registry().run(
        action_envelope,
        detector_context,
        timeout_ms=config.runtime_detector_timeout_ms,
        disabled_detector_ids=config.runtime_detector_disabled_ids,
    )
    trace_error = (
        _write_detector_debug_trace(config, action_envelope, result) if config.runtime_detector_debug_trace else None
    )
    if not result.signals and not result.telemetry:
        if trace_error is None:
            return evaluation
        return {**evaluation, "runtime_detector_trace_error": trace_error}
    next_evaluation = {
        **evaluation,
        "runtime_detector_signals_v2": [signal.to_dict() for signal in result.signals],
        "runtime_detector_telemetry": [item.to_dict() for item in result.telemetry],
    }
    # Compose detector authority independently from the base artifact result.
    # Otherwise an already-reviewable artifact makes every detector result
    # appear to be a block and prevents us from identifying a genuine terminal
    # detector block before entering the approval flow.
    composition, blocks = _authority.detector_composition(next_evaluation["runtime_detector_signals_v2"])
    next_evaluation["runtime_detector_composition"] = composition
    if blocks:
        next_evaluation["blocked"] = True
        next_evaluation["blocked_by_detector"] = composition["reason"]
    if trace_error is not None:
        next_evaluation["runtime_detector_trace_error"] = trace_error
    return next_evaluation


def _write_detector_debug_trace(
    config: GuardConfig,
    action_envelope: GuardActionEnvelope,
    result: DetectorRunResult,
) -> dict[str, object] | None:
    created_at = datetime.now(timezone.utc)
    action_payload = action_envelope.to_dict()
    trace_payload = {
        "schema_version": 1,
        "created_at": created_at.isoformat(),
        "action": _redact_detector_debug_payload(action_payload),
        "signals": [signal.to_dict() for signal in result.signals],
        "telemetry": [item.to_dict() for item in result.telemetry],
    }
    trace_dir = config.guard_home / "debug" / "detectors"
    action_digest = hashlib.sha256(
        json.dumps(action_payload, sort_keys=True, default=str).encode("utf-8"),
    ).hexdigest()[:12]
    trace_path = trace_dir / f"{created_at.strftime('%Y%m%dT%H%M%S%fZ')}-{action_digest}.json"
    try:
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_path.write_text(json.dumps(trace_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        return {"error_type": type(error).__name__, "message": str(error)}
    return None


def _redact_detector_debug_payload(value: object) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            key_text = str(key)
            if "prompt" in key_text.lower():
                redacted[key_text] = "[redacted]"
            else:
                redacted[key_text] = _redact_detector_debug_payload(item)
        return redacted
    if isinstance(value, (tuple, list)):
        return [_redact_detector_debug_payload(item) for item in value]
    return value


def _guard_run_config_paths(
    *,
    detection: HarnessDetection,
    context: HarnessContext,
    passthrough_args: list[str],
) -> list[str]:
    if detection.config_paths:
        return list(detection.config_paths)
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    if prompt_text:
        return [str(_prompt_policy_path(detection, context))]
    return []


def _detection_with_prompt_artifacts(
    detection: HarnessDetection,
    context: HarnessContext,
    passthrough_args: list[str],
) -> HarnessDetection:
    # Disabled Codex skills remain visible to inventory and AIBOM, but cannot
    # execute in this launch. They must not create launch approval requests.
    if detection.harness == "codex":
        detection = replace(
            detection,
            artifacts=tuple(
                replace(
                    artifact,
                    runtime_private_metadata={**artifact.runtime_private_metadata, "inventory_only": True},
                )
                if artifact.artifact_type == "skill" and artifact.metadata.get("enabled") is False
                else artifact
                for artifact in detection.artifacts
            ),
        )
    prompt_text = " ".join(value.strip() for value in passthrough_args if value.strip())
    if not passthrough_args:
        return detection
    prompt_requests = extract_prompt_requests(prompt_text, guard_home=context.guard_home)
    if not prompt_requests:
        return detection
    prompt_artifacts = prompt_requests_to_artifacts(
        detection=detection,
        context=context,
        requests=prompt_requests,
    )
    return HarnessDetection(
        harness=detection.harness,
        installed=detection.installed,
        command_available=detection.command_available,
        config_paths=detection.config_paths,
        artifacts=(*detection.artifacts, *prompt_artifacts),
        warnings=detection.warnings,
    )


def prompt_requests_to_artifacts(
    *,
    detection: HarnessDetection,
    context: HarnessContext,
    requests: list[PromptRequest],
) -> list[GuardArtifact]:
    """Convert typed prompt requests into pseudo-artifacts for policy evaluation.

    Rust constructs the artifacts; an unavailable or invalid result stops launch.
    """
    config_path = str(_prompt_policy_path(detection, context))
    native = _prompt_analyze_native(
        "to_artifacts",
        harness=str(detection.harness),
        config_path=config_path,
        requests=[r.to_dict() for r in requests],
        guard_home=context.guard_home,
    )
    if isinstance(native, list):
        rebuilt = [a for a in (_guard_artifact_from_dict(item) for item in native) if a is not None]
        if len(rebuilt) == len(native) == len(requests):
            return rebuilt
    raise NativePromptAnalysisError("native_prompt_analysis_invalid_result")


def _prompt_policy_path(detection: HarnessDetection, context: HarnessContext) -> Path:
    from ..adapters import get_adapter

    config_candidates = _prompt_config_candidates(detection, context)
    if context.workspace_dir is not None:
        for config_path in config_candidates:
            candidate = Path(config_path)
            if candidate.is_relative_to(context.workspace_dir):
                return candidate
    if config_candidates:
        return Path(config_candidates[0])
    return get_adapter(detection.harness).policy_path(context)


def _prompt_config_candidates(detection: HarnessDetection, context: HarnessContext) -> tuple[str, ...]:
    if detection.harness == "opencode":
        configured_path = os.getenv("OPENCODE_CONFIG")
        configured_candidate = None
        if configured_path:
            candidate = Path(configured_path).expanduser()
            if not candidate.is_absolute():
                if context.workspace_dir is not None:
                    candidate = context.workspace_dir / candidate
                else:
                    candidate = Path.cwd() / candidate
            configured_candidate = str(candidate)
        return tuple(
            config_path
            for config_path in detection.config_paths
            if Path(config_path).name in {"opencode.json", "opencode.jsonc"} or config_path == configured_candidate
        )
    return detection.config_paths
