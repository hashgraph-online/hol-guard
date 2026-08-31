"""Daemon-resident hook worker for fast hook review.

This worker avoids Python startup/import cost and avoids calling the
CLI path for normal daemon hooks. It builds a ``HookReviewRequest``
from the HTTP payload and calls the configured local decision backend.

Security:
- Never lets unreviewed tool output reach the model.
- Never falls back to legacy CLI after a worker exception for a
  request that supplied only ``guard_source_ref`` without full output.
- Never calls ``run_guard_command()``.
- Native PostToolUse is decided by Rust for ``auto``/``force``. Native failure
  fails closed instead of spilling into Python review. The Python engine is
  constructed only for ``off``/``shadow``.
- Supported command PreToolUse is decided by Rust. Native failure fails closed
  except when protection is off (watch/observe), which records via the CLI path.
  Non-command PreToolUse still raises ``HookWorkerUnsupported`` for the CLI path.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, final

from ..cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
)
from ..config import load_guard_config
from ..native_pretool import review_pre_tool_native
from ..native_route_receipt import record_python_semantic_hook_route
from ..native_runtime import native_mode, native_runtime_status, review_post_tool_native
from ..protection_posture import protection_is_off
from ..runtime.hook_content_scanner import ContentScanner
from ..runtime.hook_decision_cache import HookDecisionCache
from ..runtime.hook_review_engine import HookReviewEngine
from ..runtime.hook_review_types import (
    HookOutputSummary,
    HookPayloadKind,
    HookReviewRequest,
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
    """Raised when the worker cannot handle a request (caller falls back to CLI)."""


@final
class HookWorker:
    """Resident hook review worker for the daemon."""

    def __init__(self, *, store: GuardStore, activity_writer: CommandActivityWriter | None = None):
        self.store = store
        self.guard_home = store.guard_home
        self.activity_writer = activity_writer
        self._engine: HookReviewEngine | None = None
        from .hook_metrics import HookMetricsRecorder

        self.metrics = HookMetricsRecorder()

    @property
    def engine(self) -> HookReviewEngine:
        if self._engine is None:
            self._engine = HookReviewEngine(
                store=self.store,
                scanner=ContentScanner(),
                cache=HookDecisionCache(self.store),
                config_loader=self._load_config,
                metrics=self.metrics,
            )
        return self._engine

    def _load_config(self, guard_home: Path, workspace: Path | None):
        return load_guard_config(guard_home, workspace=workspace)

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
        """Review a hook HTTP payload and return harness JSON.

        ``off`` keeps the Python engine authoritative. ``shadow`` evaluates
        Python first and exercises native only as non-authoritative evidence.
        ``auto`` and ``force`` require the native runtime. When native is
        unavailable or returns no result, supported PreToolUse and PostToolUse
        fail closed.
        """
        harness = self._runtime_harness(params) or default_harness
        event_name = self._hook_event_name(payload)
        if event_name == "PreToolUse":
            command = _pre_tool_command(payload)
            if command is None:
                raise HookWorkerUnsupported("fast path PreToolUse requires a command")
            config = self._load_config(guard_home, workspace)
            recording_only = protection_is_off(
                posture=config.protection_posture,
                mode=config.mode,
            )
            native = review_pre_tool_native(
                command,
                guard_home=guard_home,
                cwd=workspace,
                home_dir=home_dir,
            )
            if native is not None:
                action = str(native.get("minimum_action") or "")
                if action == "review" or (recording_only and action != "allow"):
                    # Native established the minimum floor, but the CLI approval
                    # path still owns the terminal semantic decision. Watch/observe
                    # also records through that path instead of harness deny.
                    record_python_semantic_hook_route()
                    raise HookWorkerUnsupported("native PreToolUse review uses CLI approval coordination")
                return _harness_json_from_native_pre_tool(harness, native)
            if recording_only:
                raise HookWorkerUnsupported("observe PreToolUse uses CLI recording")
            status = native_runtime_status()
            if status.mode == "off":
                raise HookWorkerUnsupported("native PreToolUse runtime is off")
            if status.mode == "shadow":
                raise HookWorkerUnsupported("native PreToolUse runtime is unavailable")
            return post_tool_fail_safe_response(
                harness,
                reason="HOL Guard could not complete the native PreToolUse decision safely.",
                reason_code="native_pre_tool_unavailable",
            )
        if event_name != "PostToolUse":
            raise HookWorkerUnsupported(f"fast path supports PreToolUse and PostToolUse, got event={event_name}")
        return self._review_post_tool_http(
            payload,
            harness=harness,
            default_harness=default_harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )

    def _review_post_tool_http(
        self,
        payload: dict[str, object],
        *,
        harness: str,
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None,
    ) -> dict[str, object]:
        event_name = "PostToolUse"
        request = self._request_from_payload(
            payload,
            harness=harness,
            source_ref_external_allowed=default_harness.strip().lower().replace("_", "-") in {"pi", "omp"},
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )
        mode = native_mode()
        native_required = mode in {"auto", "force"}
        if native_required:
            config = self._load_config(guard_home, workspace)
            recording_only = protection_is_off(
                posture=config.protection_posture,
                mode=config.mode,
            )
            response = review_post_tool_native(
                request,
                observe_mode=recording_only,
            )
            if response is None:
                self._record_post_tool_activity(
                    harness=harness,
                    payload=payload,
                    succeeded=hook_post_succeeded(event_name, payload),
                )
                if recording_only:
                    return {
                        "policy_action": "allow",
                        "reason_code": "native_post_tool_unavailable",
                        "hookSpecificOutput": {"hookEventName": event_name},
                    }
                return post_tool_fail_safe_response(
                    harness,
                    reason="HOL Guard could not complete the native local hook review safely.",
                    reason_code="native_post_tool_unavailable",
                )
        else:
            response = self.engine.review(request)
            if mode == "shadow":
                with suppress(Exception):
                    _ = review_post_tool_native(request, observe_mode=response.observe_mode)

        self._record_post_tool_activity(
            harness=harness,
            payload=payload,
            succeeded=hook_post_succeeded(event_name, payload),
        )
        return _harness_json_from_review_response(harness, event_name, response)

    def _record_post_tool_activity(
        self,
        *,
        harness: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> None:
        if self.activity_writer is not None:
            _ = self.activity_writer.submit_command_activity(
                harness=harness,
                event="PostToolUse",
                payload=payload,
                succeeded=succeeded,
            )
            return
        _ = record_post_hook_command_activity_best_effort(
            store=self.store,
            guard_home=self.guard_home,
            harness=harness,
            event="PostToolUse",
            payload=payload,
            succeeded=succeeded,
        )

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


def _pre_tool_command(payload: Mapping[str, object]) -> str | None:
    for candidate in (payload.get("tool_input"), payload.get("arguments"), payload):
        if not isinstance(candidate, Mapping):
            continue
        for key in ("command", "cmd", "shell_command", "shellCommand"):
            value = candidate.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def _harness_json_from_native_pre_tool(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    action = response.get("minimum_action")
    reason = str(response.get("reason") or "HOL Guard requires native review before execution.")
    reason_code = str(response.get("reason_code") or "native_pre_tool_review")
    if action == "allow" and response.get("decision") == "allow":
        if _canonical_hook_harness(harness) in {"pi", "omp"}:
            return {
                "decision": "allow",
                "policy_action": "allow",
                "reason_code": reason_code,
            }
        return {
            "continue": True,
            "policy_action": "allow",
            "reason_code": reason_code,
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        }
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "reason_code": reason_code,
        }
    return {
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


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
    reason: str = "HOL Guard could not complete local hook review safely.",
    reason_code: str = "daemon_worker_exception",
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
    response: object,
) -> dict[str, object]:
    to_harness_json = getattr(response, "to_harness_json", None)
    payload = to_harness_json() if callable(to_harness_json) else {}
    if not isinstance(payload, dict):
        payload = {}
    if event_name != "PostToolUse":
        return payload
    if _canonical_hook_harness(harness) in {"pi", "omp"}:
        return payload
    decision = str(payload.get("decision") or "")
    model_output_action = str(payload.get("model_output_action") or "")
    if decision == "allow" and model_output_action == "allow_original":
        return {
            "policy_action": "allow",
            "hookSpecificOutput": {"hookEventName": event_name},
        }
    reason = str(payload.get("reason") or "HOL Guard blocked this tool output because it could not be proven safe.")
    reason_code = str(payload.get("reason_code") or "fast_path_block")
    return post_tool_native_block_response(reason=reason, reason_code=reason_code)


__all__ = [
    "HookWorker",
    "HookWorkerUnsupported",
    "post_tool_fail_safe_response",
    "post_tool_native_block_response",
]
