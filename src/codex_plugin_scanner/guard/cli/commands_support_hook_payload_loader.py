"""Raw hook payload loading and compatibility normalization."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..adapters.kimi_hooks import normalize_kimi_prompt


def _canonical_harness_name(value: str) -> str:
    from .commands_support_runtime_resolution import _canonical_harness_name as resolve

    return resolve(value)


def load_hook_payload(
    event_file: str | None,
    *,
    input_text: str | None = None,
    harness: str | None = None,
    normalize: bool = True,
) -> dict[str, object]:
    """Load one bounded hook payload and normalize only when requested."""

    if event_file:
        raw = Path(event_file).read_text(encoding="utf-8")
    else:
        raw = input_text.strip() if isinstance(input_text, str) else sys.stdin.read().strip()
    if not raw:
        return {}
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return {}
    if normalize:
        from ..runtime.hook_payload_reference import hydrate_hook_payload_reference

        payload = hydrate_hook_payload_reference(payload)
        return normalize_hook_payload(payload, harness=harness)
    return payload


def normalize_hook_payload(
    payload: dict[str, object],
    *,
    harness: str | None = None,
) -> dict[str, object]:
    normalized = dict(payload)
    for source_key, target_key in (
        ("artifactId", "artifact_id"),
        ("artifactHash", "artifact_hash"),
        ("artifactName", "artifact_name"),
        ("changedCapabilities", "changed_capabilities"),
        ("hookEventName", "hook_event_name"),
        ("hookName", "hook_name"),
        ("preExecutionResult", "pre_execution_result"),
        ("policyAction", "policy_action"),
        ("sourceScope", "source_scope"),
        ("toolName", "tool_name"),
        ("userOverride", "user_override"),
    ):
        if target_key not in normalized and source_key in payload:
            normalized[target_key] = payload[source_key]
    if "tool_name" not in normalized or "tool_input" not in normalized:
        tool_name, tool_input = first_hook_tool_call(
            payload.get("toolCalls"),
            expected_tool_name=normalized.get("tool_name"),
        )
        if "tool_name" not in normalized and tool_name is not None:
            normalized["tool_name"] = tool_name
        if "tool_input" not in normalized and tool_input is not None:
            normalized["tool_input"] = tool_input
    arguments = normalize_hook_arguments(
        normalized.get("tool_input"),
        normalized.get("arguments"),
        payload.get("toolArgs"),
        payload.get("toolInput"),
    )
    if arguments is not None:
        normalized["tool_input"] = arguments
        normalized["arguments"] = arguments
    if harness is not None and _canonical_harness_name(harness) == "kimi":
        normalized["prompt"] = normalize_kimi_prompt(normalized.get("prompt"))
    return normalized


def normalize_hook_arguments(*values: object | None) -> object | None:
    for value in values:
        normalized = normalize_hook_argument_value(value)
        if normalized is not None:
            return normalized
    return None


def normalize_hook_argument_value(value: object | None) -> object | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
        if isinstance(parsed, (dict, list, str)):
            return parsed
        return stripped
    return value


def first_hook_tool_call(
    value: object | None,
    *,
    expected_tool_name: object | None = None,
) -> tuple[str | None, object | None]:
    if not isinstance(value, list):
        return None, None
    normalized_expected_tool_name = expected_tool_name.strip() if isinstance(expected_tool_name, str) else None
    fallback_tool_call: tuple[str, object | None] | None = None
    for item in value:
        if not isinstance(item, dict):
            continue
        tool_name = item.get("name")
        tool_input = normalize_hook_argument_value(item.get("args"))
        if isinstance(tool_name, str) and tool_name.strip():
            stripped_tool_name = tool_name.strip()
            if fallback_tool_call is None:
                fallback_tool_call = (stripped_tool_name, tool_input)
            if normalized_expected_tool_name is None or stripped_tool_name == normalized_expected_tool_name:
                return stripped_tool_name, tool_input
    return fallback_tool_call or (None, None)


_load_hook_payload = load_hook_payload
_normalize_hook_payload = normalize_hook_payload
_normalize_hook_arguments = normalize_hook_arguments
_normalize_hook_argument_value = normalize_hook_argument_value
_first_hook_tool_call = first_hook_tool_call


__all__ = [
    "_first_hook_tool_call",
    "_load_hook_payload",
    "_normalize_hook_argument_value",
    "_normalize_hook_arguments",
    "_normalize_hook_payload",
    "first_hook_tool_call",
    "load_hook_payload",
    "normalize_hook_argument_value",
    "normalize_hook_arguments",
    "normalize_hook_payload",
]
