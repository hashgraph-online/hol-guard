"""Typed client for the native prompt-analysis owner; no Python evaluator."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast, get_args

from . import native_execution
from .config import resolve_guard_home
from .models import GuardArtifact
from .types import PromptRequest, PromptRequestClass, RemediationAction, RemediationActionKind


class NativePromptAnalysisError(RuntimeError):
    """The native owner could not supply a complete, typed prompt result."""


def analyze(subop: str, *, guard_home: Path | None = None, **kwargs: Any) -> object:
    try:
        result = native_execution.prompt_analyze_native(
            subop, guard_home=guard_home if guard_home is not None else resolve_guard_home(), **kwargs
        )
    except (OSError, ValueError) as error:
        raise NativePromptAnalysisError("native_prompt_analysis_unavailable") from error
    if result is None:
        raise NativePromptAnalysisError("native_prompt_analysis_unavailable")
    return result


def _text(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError("invalid native prompt string")
    return value


def request_from_dict(value: object) -> PromptRequest | None:
    if not isinstance(value, dict):
        return None
    try:
        request_class = _text(value, "request_class")
        if request_class not in get_args(PromptRequestClass):
            return None
        severity = value.get("severity")
        confidence = value.get("confidence")
        if isinstance(severity, bool) or not isinstance(severity, int):
            return None
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            return None
        if not 0 <= severity <= 10 or not 0.0 <= confidence <= 1.0:
            return None
        items = value.get("remediation", [])
        if not isinstance(items, list):
            return None
        remediation: list[RemediationAction] = []
        for item in items:
            if not isinstance(item, dict):
                return None
            kind = _text(item, "kind")
            detail = item.get("detail")
            if kind not in get_args(RemediationActionKind) or (detail is not None and not isinstance(detail, str)):
                return None
            remediation.append(
                RemediationAction(kind=cast(RemediationActionKind, kind), label=_text(item, "label"), detail=detail)
            )
        return PromptRequest(
            request_id=_text(value, "request_id"),
            request_class=cast(PromptRequestClass, request_class),
            summary=_text(value, "summary"),
            matched_text=_text(value, "matched_text"),
            severity=severity,
            confidence=float(confidence),
            remediation=tuple(remediation),
        )
    except (TypeError, ValueError):
        return None


def requests_from_result(result: object) -> list[PromptRequest]:
    if not isinstance(result, list):
        raise NativePromptAnalysisError("native_prompt_analysis_invalid_result")
    requests = [request_from_dict(item) for item in result]
    if any(request is None for request in requests):
        raise NativePromptAnalysisError("native_prompt_analysis_invalid_result")
    return [request for request in requests if request is not None]


def extract_prompt_requests(prompt_text: str, *, guard_home: Path | None = None) -> list[PromptRequest]:
    return requests_from_result(analyze("extract", prompt_text=prompt_text, guard_home=guard_home))


def detect_prompt_injection_requests(prompt_text: str, *, guard_home: Path | None = None) -> list[PromptRequest]:
    return requests_from_result(analyze("detect_injection", prompt_text=prompt_text, guard_home=guard_home))


def artifact_from_dict(value: object) -> GuardArtifact | None:
    if not isinstance(value, dict) or not isinstance(value.get("metadata"), dict):
        return None
    try:
        return GuardArtifact(
            artifact_id=_text(value, "artifact_id"),
            name=_text(value, "name"),
            harness=_text(value, "harness"),
            artifact_type=_text(value, "artifact_type"),
            source_scope=_text(value, "source_scope"),
            config_path=_text(value, "config_path"),
            metadata=dict(value["metadata"]),
        )
    except (TypeError, ValueError):
        return None


def should_force_reapproval(
    prompt_reqs: list[PromptRequest], prior_policy: dict[str, object] | None, *, guard_home: Path | None = None
) -> bool:
    raw = prior_policy.get("approved_prompt_classes") if prior_policy is not None else None
    approved = [item for item in raw if isinstance(item, str)] if isinstance(raw, list) else []
    result = analyze(
        "should_force_reapproval",
        requests=[request.to_dict() for request in prompt_reqs],
        prior_policy_present=prior_policy is not None,
        approved_classes=approved,
        guard_home=guard_home,
    )
    if not isinstance(result, bool):
        raise NativePromptAnalysisError("native_prompt_analysis_invalid_result")
    return result


def prompt_request_id(request_class: str, matched_text: str, normalized_prompt: str) -> str:
    result = analyze(
        "request_id", request_class=request_class, matched_text=matched_text, prompt_text=normalized_prompt
    )
    if not isinstance(result, str) or len(result) != 64 or any(char not in "0123456789abcdef" for char in result):
        raise NativePromptAnalysisError("native_prompt_analysis_invalid_result")
    return result


def trailing_secret_read_state(content: str, *, guard_home: Path | None = None) -> tuple[int, bool] | None:
    result = analyze("trailing_secret_read_state", prompt_text=content, guard_home=guard_home)
    if not isinstance(result, dict) or "state" not in result:
        raise NativePromptAnalysisError("native_prompt_analysis_invalid_result")
    state = result["state"]
    if state is None:
        return None
    if not isinstance(state, list) or len(state) != 2:
        raise NativePromptAnalysisError("native_prompt_analysis_invalid_result")
    distance, positive = state
    if (
        isinstance(distance, bool)
        or not isinstance(distance, int)
        or distance not in (0, 1)
        or not isinstance(positive, bool)
    ):
        raise NativePromptAnalysisError("native_prompt_analysis_invalid_result")
    return distance, positive
