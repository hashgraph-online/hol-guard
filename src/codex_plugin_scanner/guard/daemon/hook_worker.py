"""Daemon-resident native hook worker.

The supported PostToolUse decision path is Rust-authoritative. Python builds the
bounded transport envelope and maps the already-completed native decision to a
harness response. It does not run a Python scanner, classifier, or evaluator,
and native failure produces a deterministic fail-safe result rather than a
Python decision fallback.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, final

from ..cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
)
from ..config import load_guard_config
from ..native_route_metrics import (
    attach_native_decision_receipt,
    native_decision_receipt,
    record_native_decision,
)
from ..native_runtime import review_post_tool_native
from ..runtime.hook_review_types import (
    HookOutputSummary,
    HookPayloadKind,
    HookReviewRequest,
    HookReviewResponse,
    HookSourceFileRef,
)

if TYPE_CHECKING:
    from ..store import GuardStore


class CommandActivityWriter(Protocol):
    def submit_command_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> bool: ...


def runtime_hook_event_name(payload: Mapping[str, object]) -> str:
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "PreToolUse"


class HookWorkerUnsupported(RuntimeError):  # noqa: N818
    """Raised when the native worker does not own an event surface."""


@final
class HookWorker:
    """Resident Rust-authoritative hook review worker."""

    def __init__(self, *, store: GuardStore, activity_writer: CommandActivityWriter | None = None):
        self.store = store
        self.guard_home = store.guard_home
        self.activity_writer = activity_writer
        # The daemon server owns aggregate failure accounting through this
        # recorder. It is observability only and never participates in a hook
        # decision or provides a Python evaluator fallback.
        from .hook_metrics import HookMetricsRecorder

        self.metrics = HookMetricsRecorder()

    def review_http_payload(
        self,
        *,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None = None,
    ) -> dict[str, object]:
        harness = self._runtime_harness(params) or default_harness
        event_name = self._hook_event_name(payload)
        if event_name != "PostToolUse":
            raise HookWorkerUnsupported(f"native worker does not own event={event_name}")

        request = self._request_from_payload(
            payload,
            harness=harness,
            source_ref_external_allowed=default_harness.strip().lower().replace("_", "-") in {"pi", "omp"},
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )
        observe_mode = self._observe_mode(guard_home=guard_home, workspace=workspace)
        try:
            response = review_post_tool_native(request, observe_mode=observe_mode)
        except Exception:
            response = None
        if response is None:
            response = HookReviewResponse(
                decision="deny",
                reason="HOL Guard could not complete local Rust review safely.",
                model_output_action="block",
                notice="warning",
                reason_code="native_post_tool_unavailable",
                policy_action="block",
            )
            receipt = native_decision_receipt(
                backend="native_fail_safe",
                transport="unavailable",
                decision_core="native_unavailable_fail_safe",
                reason_code=response.reason_code,
            )
        else:
            receipt = native_decision_receipt(
                backend="rust_native",
                transport="resident_or_oneshot",
                decision_core="rust_post_tool_v1",
                reason_code=response.reason_code,
            )
        response = attach_native_decision_receipt(response, receipt)
        record_native_decision(event_name, harness, receipt, guard_home=guard_home)

        succeeded = hook_post_succeeded(event_name, payload)
        if self.activity_writer is not None:
            _ = self.activity_writer.submit_command_activity(
                harness=harness,
                event=event_name,
                payload=payload,
                succeeded=succeeded,
            )
        else:
            _ = record_post_hook_command_activity_best_effort(
                store=self.store,
                guard_home=self.guard_home,
                harness=harness,
                event=event_name,
                payload=payload,
                succeeded=succeeded,
            )
        return _harness_json_from_review_response(harness, event_name, response)

    @staticmethod
    def _observe_mode(*, guard_home: Path, workspace: Path | None) -> bool:
        """Read product posture without introducing an alternate evaluator."""

        try:
            return load_guard_config(guard_home, workspace=workspace).mode == "observe"
        except (OSError, RuntimeError, TypeError, ValueError):
            # Configuration uncertainty may never weaken native enforcement.
            return False

    def _runtime_harness(self, params: Mapping[str, list[str]]) -> str | None:
        values = params.get("runtime-harness", [])
        if values and isinstance(values[-1], str) and values[-1].strip():
            return values[-1].strip()
        return None

    def _request_from_payload(
        self,
        payload: dict[str, object],
        *,
        harness: str,
        source_ref_external_allowed: bool,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None = None,
    ) -> HookReviewRequest:
        event_name = self._hook_event_name(payload)
        payload_kind = self._payload_kind(payload)
        output_summary = self._parse_output_summary(payload)
        source_ref = self._parse_source_ref(payload)
        source_scope = str(payload.get("source_scope") or "project")
        config_path = payload.get("config_path")
        if not isinstance(config_path, str):
            config_path = None
        request_id = payload.get("request_id")
        if not isinstance(request_id, str):
            request_id = None
        return HookReviewRequest(
            harness=harness,
            event_name=event_name,
            payload=payload,
            payload_kind=payload_kind,
            config_path=config_path,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            source_scope=source_scope,
            source_ref_external_allowed=source_ref_external_allowed,
            output_summary=output_summary,
            source_ref=source_ref,
            deadline_monotonic=deadline,
            request_id=request_id,
        )

    def _hook_event_name(self, payload: Mapping[str, object]) -> str:
        return runtime_hook_event_name(payload)

    def _payload_kind(self, payload: Mapping[str, object]) -> HookPayloadKind:
        if "guard_payload_ref" in payload:
            return "encrypted_payload_ref"
        if "guard_source_ref" in payload:
            return "source_file_ref"
        return "inline"

    def _parse_output_summary(self, payload: Mapping[str, object]) -> HookOutputSummary | None:
        summary = payload.get("tool_response_summary")
        if not isinstance(summary, Mapping):
            return None
        text_excerpt = summary.get("text_excerpt") or summary.get("excerpt") or ""
        if not isinstance(text_excerpt, str):
            text_excerpt = str(text_excerpt)
        excerpt_truncated = bool(summary.get("excerpt_truncated", False))
        output_sha256 = summary.get("output_sha256")
        if not isinstance(output_sha256, str):
            output_sha256 = None
        output_chars_raw = summary.get("output_chars")
        output_chars = int(output_chars_raw) if isinstance(output_chars_raw, (int, float)) else None
        content_items_seen_raw = summary.get("content_items_seen")
        content_items_seen = int(content_items_seen_raw) if isinstance(content_items_seen_raw, (int, float)) else None
        object_keys_seen_raw = summary.get("object_keys_seen")
        object_keys_seen = int(object_keys_seen_raw) if isinstance(object_keys_seen_raw, (int, float)) else None
        max_depth_seen_raw = summary.get("max_depth_seen")
        max_depth_seen = int(max_depth_seen_raw) if isinstance(max_depth_seen_raw, (int, float)) else None
        return HookOutputSummary(
            text_excerpt=text_excerpt,
            excerpt_truncated=excerpt_truncated,
            output_sha256=output_sha256,
            output_chars=output_chars,
            content_items_seen=content_items_seen,
            object_keys_seen=object_keys_seen,
            max_depth_seen=max_depth_seen,
        )

    def _parse_source_ref(self, payload: Mapping[str, object]) -> HookSourceFileRef | None:
        ref = payload.get("guard_source_ref")
        if not isinstance(ref, Mapping):
            return None
        version = ref.get("version")
        path = ref.get("path")
        output_sha256 = ref.get("output_sha256")
        output_chars = ref.get("output_chars")
        tool_input_path = ref.get("tool_input_path")
        adapter_stat = ref.get("adapter_stat")
        if not isinstance(version, int) or not isinstance(path, str) or not isinstance(output_sha256, str):
            return HookSourceFileRef(version=-1, path="", output_sha256="", output_chars=0)
        if not isinstance(output_chars, int):
            output_chars = 0
        if not isinstance(tool_input_path, str):
            tool_input_path = None
        stat_dict = dict(adapter_stat) if isinstance(adapter_stat, Mapping) else {}
        return HookSourceFileRef(
            version=version,
            path=path,
            output_sha256=output_sha256,
            output_chars=output_chars,
            tool_input_path=tool_input_path,
            adapter_stat=stat_dict,
        )


def _canonical_hook_harness(harness: str) -> str:
    return harness.strip().lower().replace("_", "-")


def post_tool_native_block_response(
    *,
    reason: str = "HOL Guard blocked this tool output because it could not be proven safe.",
    reason_code: str = "fast_path_block",
) -> dict[str, object]:
    return {
        "decision": "block",
        "reason": reason,
        "continue": False,
        "stopReason": reason,
        "policy_action": "block",
        "risk_summary": reason,
        "model_output_action": "block",
        "notice": "warning",
        "reason_code": reason_code,
    }


def post_tool_fail_safe_response(
    harness: str,
    *,
    reason: str = "HOL Guard could not complete local Rust hook review safely.",
    reason_code: str = "native_worker_failure",
) -> dict[str, object]:
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "reason_code": reason_code,
        }
    return post_tool_native_block_response(reason=reason, reason_code=reason_code)


def _harness_json_from_review_response(
    harness: str,
    event_name: str,
    response: HookReviewResponse,
) -> dict[str, object]:
    payload = response.to_harness_json()
    if event_name != "PostToolUse":
        return payload
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return payload
    if response.decision == "allow" and response.model_output_action == "allow_original":
        return {
            "policy_action": "allow",
            "hookSpecificOutput": {"hookEventName": event_name},
        }
    reason = response.reason or "HOL Guard blocked this tool output because it could not be proven safe."
    return post_tool_native_block_response(reason=reason, reason_code=response.reason_code)


__all__ = [
    "HookWorker",
    "HookWorkerUnsupported",
    "post_tool_fail_safe_response",
    "post_tool_native_block_response",
    "runtime_hook_event_name",
]
