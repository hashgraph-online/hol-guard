"""Daemon-resident hook transport for the Rust Guard data plane.

The no-environment production path is Rust-authoritative from the raw hook
edge through the semantic decision and decision-critical PostToolUse I/O.
Python remains a bounded control plane for route handling, resident lifecycle,
harness rendering, and best-effort evidence.

Explicit ``off``/``shadow`` modes retain the Python reference evaluator for
rollback and differential compatibility. Native failure in ``auto``/``force``
never enters that compatibility evaluator.
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
from ..native_hook_edge import review_hook_edge_native
from ..native_runtime import native_mode
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
    """Best-effort display/fail-safe event label; Rust owns auto-mode extraction."""
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "PreToolUse"


class HookWorkerUnsupported(RuntimeError):  # noqa: N818
    """Raised only for explicit compatibility modes and unsupported control events."""


@final
class HookWorker:
    """Transport production hooks to Rust and isolate explicit compatibility."""

    def __init__(self, *, store: GuardStore, activity_writer: CommandActivityWriter | None = None):
        self.store = store
        self.guard_home = store.guard_home
        self.activity_writer = activity_writer
        self._engine: HookReviewEngine | None = None
        from .hook_metrics import HookMetricsRecorder

        self.metrics = HookMetricsRecorder()

    @property
    def engine(self) -> HookReviewEngine:
        """Lazy Python reference engine reachable only from explicit off/shadow."""
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
        """Return Rust authority by default; explicit off/shadow use compatibility."""

        harness = self._runtime_harness(params) or default_harness
        mode = native_mode()
        if mode in {"off", "shadow"}:
            return self._review_explicit_python_compatibility(
                payload,
                harness=harness,
                default_harness=default_harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                deadline=deadline,
                shadow=mode == "shadow",
            )

        try:
            config = self._load_config(guard_home, workspace)
            native = review_hook_edge_native(
                payload=payload,
                harness=harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                observe_mode=config.mode == "observe",
                deadline=deadline,
            )
        except Exception:
            native = None
        if native is None:
            event_name = runtime_hook_event_name(payload)
            if event_name == "PostToolUse":
                self._record_post_tool_activity(
                    harness=harness,
                    payload=payload,
                    succeeded=hook_post_succeeded(event_name, payload),
                )
            return post_tool_fail_safe_response(
                harness,
                reason="HOL Guard could not complete the native hook decision safely.",
                reason_code="native_hook_edge_unavailable",
                event_name=event_name,
            )

        event_name = str(native.get("event_name") or runtime_hook_event_name(payload))
        if event_name == "PostToolUse":
            self._record_post_tool_activity(
                harness=harness,
                payload=payload,
                succeeded=hook_post_succeeded(event_name, payload),
            )
        return _harness_json_from_native_edge(harness, native)

    def _review_explicit_python_compatibility(
        self,
        payload: dict[str, object],
        *,
        harness: str,
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None,
        shadow: bool,
    ) -> dict[str, object]:
        """Run the explicit rollback/reference evaluator, never automatic fallback."""

        event_name = runtime_hook_event_name(payload)
        if event_name != "PostToolUse":
            raise HookWorkerUnsupported(
                f"explicit Python compatibility handles PostToolUse only, got event={event_name}"
            )
        request = self._request_from_payload(
            payload,
            harness=harness,
            source_ref_external_allowed=default_harness.strip().lower().replace("_", "-") in {"pi", "omp"},
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )
        response = self.engine.review(request)
        if shadow:
            with suppress(Exception):
                config = self._load_config(guard_home, workspace)
                _ = review_hook_edge_native(
                    payload=payload,
                    harness=harness,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    workspace=workspace,
                    observe_mode=config.mode == "observe",
                    deadline=deadline,
                )
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
        """Build a Python reference request only in explicit compatibility mode."""

        event_name = runtime_hook_event_name(payload)
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


def _pre_tool_harness_response(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    action = str(response.get("minimum_action") or response.get("policy_action") or "block")
    reason = str(response.get("reason") or "HOL Guard requires native review before execution.")
    reason_code = str(response.get("reason_code") or "native_pre_tool_review")
    canonical = _canonical_hook_harness(harness)
    if action == "allow" and response.get("decision") == "allow":
        if canonical in {"pi", "omp"}:
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

    if canonical in {"pi", "omp"}:
        return {
            "decision": "deny",
            "reason": reason,
            "model_output_action": "block",
            "notice": "warning",
            "reason_code": reason_code,
            "policy_action": action,
        }

    permission_decision = "deny"
    if action == "review" and canonical not in {"codex", "kimi", "grok", "zcode"}:
        permission_decision = "ask"
    return {
        "policy_action": action,
        "reason_code": reason_code,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        },
    }


def _post_tool_harness_response(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    canonical = _canonical_hook_harness(harness)
    payload = {
        key: value
        for key, value in response.items()
        if key
        in {
            "decision",
            "reason",
            "model_output_action",
            "reviewed_output_sha256",
            "reviewed_excerpt",
            "notice",
            "reason_code",
            "policy_action",
            "observed_policy_action",
            "observe_mode",
        }
    }
    if canonical in {"pi", "omp"}:
        return payload
    decision = str(payload.get("decision") or "")
    model_output_action = str(payload.get("model_output_action") or "")
    if decision == "allow" and model_output_action == "allow_original":
        return {
            "policy_action": "allow",
            "reason_code": str(payload.get("reason_code") or "native_post_tool_allow"),
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        }
    reason = str(payload.get("reason") or "HOL Guard blocked this tool output because it could not be proven safe.")
    reason_code = str(payload.get("reason_code") or "native_post_tool_block")
    return post_tool_native_block_response(reason=reason, reason_code=reason_code)


def _harness_json_from_native_edge(harness: str, response: Mapping[str, object]) -> dict[str, object]:
    event_name = str(response.get("event_name") or "PreToolUse")
    if event_name == "PreToolUse":
        return _pre_tool_harness_response(harness, response)
    if event_name == "PostToolUse":
        return _post_tool_harness_response(harness, response)
    reason = str(response.get("reason") or "HOL Guard requires review for this native hook event.")
    return post_tool_fail_safe_response(
        harness,
        reason=reason,
        reason_code=str(response.get("reason_code") or "native_hook_event_review_required"),
        event_name=event_name,
    )


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
    event_name: str = "PostToolUse",
) -> dict[str, object]:
    canonical = _canonical_hook_harness(harness)
    if event_name == "PreToolUse" and canonical not in {"pi", "omp"}:
        return {
            "policy_action": "block",
            "reason_code": reason_code,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            },
        }
    if canonical in {"pi", "omp"}:
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
