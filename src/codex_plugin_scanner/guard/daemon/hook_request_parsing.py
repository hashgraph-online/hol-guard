"""Normalize daemon hook payloads into the native review request model."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..runtime.hook_review_types import (
    HookOutputSummary,
    HookPayloadKind,
    HookReviewRequest,
    HookSourceFileRef,
)


def runtime_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            raw = value.strip()
            compact = raw.lower().replace("_", "").replace("-", "")
            if compact in {
                "pretool",
                "pretooluse",
                "beforeshellexecution",
                "beforereadfile",
                "beforewritefile",
                "beforemcpexecution",
            }:
                return "PreToolUse"
            if compact in {
                "posttool",
                "posttooluse",
                "aftershellexecution",
                "afterreadfile",
                "afterwritefile",
                "aftermcpexecution",
            }:
                return "PostToolUse"
            if compact in {"permissionrequest", "permissionrequestv2"}:
                return "PermissionRequest"
            return raw
    return "PreToolUse"


def payload_kind(payload: Mapping[str, object]) -> HookPayloadKind:
    if "guard_payload_ref" in payload:
        return "encrypted_payload_ref"
    if "guard_source_ref" in payload:
        return "source_file_ref"
    return "inline"


def parse_output_summary(payload: Mapping[str, object]) -> HookOutputSummary | None:
    summary = payload.get("tool_response_summary")
    if not isinstance(summary, Mapping):
        return None
    text_excerpt = summary.get("text_excerpt") or summary.get("excerpt") or ""
    if not isinstance(text_excerpt, str):
        text_excerpt = str(text_excerpt)
    output_sha256 = summary.get("output_sha256")
    if not isinstance(output_sha256, str):
        output_sha256 = None
    return HookOutputSummary(
        text_excerpt=text_excerpt,
        excerpt_truncated=bool(summary.get("excerpt_truncated", False)),
        output_sha256=output_sha256,
        output_chars=_summary_int(summary.get("output_chars")),
        content_items_seen=_summary_int(summary.get("content_items_seen")),
        object_keys_seen=_summary_int(summary.get("object_keys_seen")),
        max_depth_seen=_summary_int(summary.get("max_depth_seen")),
    )


def _summary_int(value: object) -> int | None:
    return int(value) if isinstance(value, (int, float)) else None


def parse_hook_source_file_ref(ref: Mapping[str, object]) -> HookSourceFileRef:
    """Parse one guard source ref mapping, fail-closed on invalid fields."""

    version = ref.get("version")
    path = ref.get("path")
    output_sha256 = ref.get("output_sha256")
    output_chars = ref.get("output_chars")
    tool_input_path = ref.get("tool_input_path")
    adapter_stat = ref.get("adapter_stat")
    if not isinstance(version, int) or not isinstance(path, str) or not isinstance(output_sha256, str):
        return HookSourceFileRef(version=-1, path="", output_sha256="", output_chars=0)
    return HookSourceFileRef(
        version=version,
        path=path,
        output_sha256=output_sha256,
        output_chars=output_chars if isinstance(output_chars, int) else 0,
        tool_input_path=tool_input_path if isinstance(tool_input_path, str) else None,
        adapter_stat=dict(adapter_stat) if isinstance(adapter_stat, Mapping) else {},
    )


def parse_source_ref(payload: Mapping[str, object]) -> HookSourceFileRef | None:
    ref = payload.get("guard_source_ref")
    if not isinstance(ref, Mapping):
        return None
    return parse_hook_source_file_ref(ref)


def build_hook_review_request(
    payload: dict[str, object],
    *,
    harness: str,
    source_ref_external_allowed: bool,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None = None,
) -> HookReviewRequest:
    config_path = payload.get("config_path")
    return HookReviewRequest(
        harness=harness,
        event_name=runtime_hook_event_name(payload),
        payload=payload,
        payload_kind=payload_kind(payload),
        config_path=config_path if isinstance(config_path, str) else None,
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        source_scope=str(payload.get("source_scope") or "project"),
        source_ref_external_allowed=source_ref_external_allowed,
        output_summary=parse_output_summary(payload),
        source_ref=parse_source_ref(payload),
        deadline_monotonic=deadline,
    )


def pre_tool_command(payload: Mapping[str, object]) -> str | None:
    for candidate in (payload.get("tool_input"), payload.get("arguments"), payload):
        if not isinstance(candidate, Mapping):
            continue
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


__all__ = [
    "build_hook_review_request",
    "parse_output_summary",
    "parse_source_ref",
    "payload_kind",
    "pre_tool_command",
    "runtime_hook_event_name",
]
