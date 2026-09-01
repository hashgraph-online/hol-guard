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
- Supported generic PreToolUse is decided by Rust. Native failure fails closed
  in auto/force; explicit off/shadow keeps its compatibility path.
  Native review and block results are rendered mechanically and never escape to
  the Python semantic CLI path.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, final

from ..cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
)
from ..config import load_guard_config
from ..native_hook_edge import review_raw_hook_native
from ..native_policy_snapshot import get_native_policy_snapshot_publisher
from ..native_pretool import review_pre_tool_native
from ..native_route_receipt import record_python_semantic_hook_route
from ..native_runtime import native_mode, native_runtime_status, review_post_tool_native
from ..protection_posture import protection_is_off
from ..runtime.hook_content_scanner import ContentScanner
from ..runtime.hook_decision_cache import HookDecisionCache
from ..runtime.hook_review_engine import HookReviewEngine
from ..runtime.hook_review_types import HookOutputSummary, HookPayloadKind, HookReviewRequest, HookSourceFileRef
from .hook_request_parsing import (
    build_hook_review_request,
    parse_output_summary,
    parse_source_ref,
    payload_kind,
    pre_tool_command,
    runtime_hook_event_name,
)
from .hook_worker_responses import (
    harness_json_from_native_post_tool,
    harness_json_from_native_pre_tool,
    harness_json_from_review_response,
    post_tool_fail_safe_response,
    post_tool_native_block_response,
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


class HookWorkerUnsupported(RuntimeError):  # noqa: N818
    """Raised only for explicit off/shadow compatibility requests."""


class NativeApprovalCoordinationRequired(HookWorkerUnsupported):
    """Rust required review; route to the approval-center coordinator."""


_NATIVE_POLICY_READY_TIMEOUT_SECONDS = 0.25


@final
class HookWorker:
    """Resident hook review worker for the daemon."""

    def __init__(self, *, store: GuardStore, activity_writer: CommandActivityWriter | None = None):
        self.store = store
        self.guard_home = store.guard_home
        self.activity_writer = activity_writer
        self._engine: HookReviewEngine | None = None
        self.policy_snapshot_publisher = get_native_policy_snapshot_publisher(self.store)
        mode = native_mode()
        if mode in {"auto", "force", "shadow"}:
            self.policy_snapshot_publisher.start()
        if mode in {"auto", "force"}:
            wait_until_ready = getattr(self.policy_snapshot_publisher, "wait_until_ready", None)
            if callable(wait_until_ready):
                _ = wait_until_ready(time.monotonic() + 0.25)
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

    def close(self) -> None:
        """Stop the asynchronous native policy publisher with the worker."""

        self.policy_snapshot_publisher.close()

    def prepare_workspace_policy(
        self,
        workspace: Path | None = None,
        *,
        deadline: float | None = None,
    ) -> dict[str, object] | None:
        """Prepare an ACKed workspace policy before admitting a native hook.

        Workspace overlays are published asynchronously, so the first hook
        for a workspace must complete this same barrier used by normal hook
        evaluation. The barrier is always capped at the native readiness
        budget; a timeout returns ``None`` and callers fail closed.
        """

        if native_mode() not in {"auto", "force", "shadow"}:
            return None
        register_workspace = getattr(self.policy_snapshot_publisher, "register_workspace", None)
        if callable(register_workspace):
            _ = register_workspace(workspace)
        self.policy_snapshot_publisher.start()
        if native_mode() in {"auto", "force"}:
            wait_until_ready = getattr(self.policy_snapshot_publisher, "wait_until_ready", None)
            if callable(wait_until_ready):
                readiness_deadline = time.monotonic() + _NATIVE_POLICY_READY_TIMEOUT_SECONDS
                if deadline is not None:
                    readiness_deadline = min(readiness_deadline, deadline)
                if not wait_until_ready(readiness_deadline):
                    return None
        current_snapshot_binding = getattr(self.policy_snapshot_publisher, "current_snapshot_binding", None)
        if callable(current_snapshot_binding):
            snapshot = current_snapshot_binding()
            return snapshot if isinstance(snapshot, dict) else None
        snapshot = self.policy_snapshot_publisher.current_snapshot()
        return snapshot if isinstance(snapshot, dict) else None

    def _native_policy_snapshot(self, workspace: Path | None = None) -> dict[str, object] | None:
        """Return only the last resident-ACKed snapshot for native hooks."""

        return self.prepare_workspace_policy(workspace)

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
        mode = native_mode()
        if mode in {"auto", "force"}:
            # Send even unknown or malformed event labels to Rust. The edge
            # returns no semantic result for unsupported events, which this
            # method turns into a deterministic deny/fail-safe response.
            return self._review_native_edge(
                payload=payload,
                harness=harness,
                event_name=event_name,
                default_harness=default_harness,
                guard_home=guard_home,
                home_dir=home_dir,
                workspace=workspace,
                deadline=deadline,
            )
        if event_name not in {"PreToolUse", "PostToolUse"}:
            raise HookWorkerUnsupported(f"fast path supports PreToolUse and PostToolUse, got event={event_name}")
        if event_name == "PreToolUse":
            command = pre_tool_command(payload)
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
                return harness_json_from_native_pre_tool(harness, native)
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

    def _review_native_edge(
        self,
        *,
        payload: dict[str, object],
        harness: str,
        event_name: str,
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None,
    ) -> dict[str, object]:
        policy_snapshot = self._native_policy_snapshot(workspace)
        recording_only = policy_snapshot is not None and policy_snapshot.get("mode") == "observe"
        edge = review_raw_hook_native(
            payload=payload,
            harness=harness,
            event=event_name,
            guard_home=guard_home,
            home_dir=home_dir,
            cwd=workspace,
            source_ref_external_allowed=default_harness.strip().lower().replace("_", "-") in {"pi", "omp"},
            observe_mode=recording_only,
            deadline=deadline,
            policy_snapshot=policy_snapshot,
        )
        if edge is None:
            self.metrics.record_route("native_fail_safe")
            if event_name == "PostToolUse":
                self._record_post_tool_activity(
                    harness=harness,
                    payload=payload,
                    succeeded=hook_post_succeeded(event_name, payload),
                )
            reason_code = {
                "PostToolUse": "native_post_tool_unavailable",
                "PreToolUse": "native_pre_tool_unavailable",
            }.get(event_name, "native_hook_event_unavailable")
            return post_tool_fail_safe_response(
                harness,
                reason="HOL Guard could not complete the native hook decision safely.",
                reason_code=reason_code,
            )
        native_event = str(edge["event_name"])
        native_harness = str(edge["harness"])
        native_result = edge["result"]
        if not isinstance(native_result, Mapping):
            self.metrics.record_route("native_fail_safe")
            return post_tool_fail_safe_response(harness, reason_code="native_hook_edge_invalid_response")
        self.metrics.record_route("native_resident")
        if native_event == "PreToolUse":
            if str(native_result.get("minimum_action") or "") == "review":
                raise NativeApprovalCoordinationRequired(
                    "native PreToolUse review requires approval coordination"
                )
            return harness_json_from_native_pre_tool(native_harness, native_result)
        self._record_post_tool_activity(
            harness=native_harness,
            payload=payload,
            succeeded=hook_post_succeeded(native_event, payload),
        )
        return harness_json_from_native_post_tool(native_harness, native_result)

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
            policy_snapshot = self._native_policy_snapshot(workspace)
            recording_only = policy_snapshot is not None and policy_snapshot.get("mode") == "observe"
            response = review_post_tool_native(
                request,
                observe_mode=recording_only,
                policy_snapshot=policy_snapshot,
            )
            if response is None:
                self._record_post_tool_activity(
                    harness=harness,
                    payload=payload,
                    succeeded=hook_post_succeeded(event_name, payload),
                )
                return post_tool_fail_safe_response(
                    harness,
                    reason="HOL Guard could not complete the native local hook review safely.",
                    reason_code="native_post_tool_unavailable",
                )
        else:
            response = self.engine.review(request)
            if mode == "shadow":
                with suppress(Exception):
                    _ = review_post_tool_native(
                        request,
                        observe_mode=response.observe_mode,
                        policy_snapshot=self._native_policy_snapshot(workspace),
                    )

        self._record_post_tool_activity(
            harness=harness,
            payload=payload,
            succeeded=hook_post_succeeded(event_name, payload),
        )
        return harness_json_from_review_response(harness, event_name, response)

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
        return build_hook_review_request(
            payload,
            harness=harness,
            source_ref_external_allowed=source_ref_external_allowed,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )

    def _hook_event_name(self, payload: Mapping[str, object]) -> str:
        return runtime_hook_event_name(payload)

    def _payload_kind(self, payload: Mapping[str, object]) -> HookPayloadKind:
        return payload_kind(payload)

    def _parse_output_summary(self, payload: Mapping[str, object]) -> HookOutputSummary | None:
        return parse_output_summary(payload)

    def _parse_source_ref(self, payload: Mapping[str, object]) -> HookSourceFileRef | None:
        return parse_source_ref(payload)


__all__ = [
    "HookWorker",
    "HookWorkerUnsupported",
    "post_tool_fail_safe_response",
    "post_tool_native_block_response",
]
