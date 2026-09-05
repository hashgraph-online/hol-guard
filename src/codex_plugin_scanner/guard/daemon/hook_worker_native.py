"""Native hook review helpers shared by the daemon hook worker."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Protocol

from ..cli.commands_support_command_activity import hook_post_succeeded
from ..native_mode import python_oracle_surface_enabled
from ..native_route_receipt import record_python_semantic_hook_route
from ..native_runtime import NativeRuntimeStatus
from ..runtime.hook_review_types import HookReviewRequest, HookReviewResponse
from .hook_availability_policy import (
    availability_harness_response,
    hook_review_is_recording_only,
    recording_only_pre_tool_response,
)
from .hook_native_review_approval import pause_native_pre_tool_for_approval
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import (
    harness_json_from_native_post_tool,
    harness_json_from_native_pre_tool,
)


def _watch_native_pre_tool_result(native: Mapping[str, object]) -> dict[str, object]:
    rewritten = dict(native)
    if str(rewritten.get("minimum_action") or "") == "allow" and rewritten.get("decision") == "allow":
        return rewritten
    rewritten["decision"] = "allow"
    rewritten["minimum_action"] = "warn"
    rewritten["policy_action"] = "warn"
    return rewritten


def _watch_native_post_tool_result(native: Mapping[str, object]) -> dict[str, object]:
    rewritten = dict(native)
    if rewritten.get("decision") == "allow" and rewritten.get("model_output_action") == "allow_original":
        return rewritten
    rewritten["decision"] = "allow"
    rewritten["model_output_action"] = "allow_original"
    rewritten["policy_action"] = "warn"
    return rewritten


class PythonOracle(Protocol):
    """Minimal response surface accepted from an explicit test oracle."""

    def review(self, request: HookReviewRequest) -> HookReviewResponse: ...


class HookWorkerUnsupported(RuntimeError):  # noqa: N818
    """Raised only for explicit off/shadow compatibility requests."""


class _HookWorkerMetrics(Protocol):
    def record_route(self, route: str) -> None: ...


class _HookWorkerNativeHost(Protocol):
    store: object

    @property
    def metrics(self) -> _HookWorkerMetrics: ...

    @property
    def activity_writer(self) -> object | None: ...

    _last_native_decision_receipt: dict[str, object] | None
    _native_policy_snapshot: Callable[..., dict[str, object] | None]
    _review_pre_tool_native: Callable[..., dict[str, object] | None]
    _native_runtime_status: Callable[[], NativeRuntimeStatus]
    _review_raw_hook_native: Callable[..., dict[str, object] | None]
    _record_post_tool_activity: Callable[..., None]
    _record_native_decision_receipt: Callable[[object], None]


def _record_unavailable_native(
    host: _HookWorkerNativeHost,
    payload: dict[str, object],
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    workspace: Path | None,
    home_dir: Path,
    guard_home: Path,
    recording_only: bool,
) -> dict[str, object]:
    response = availability_harness_response(
        payload,
        harness=harness,
        event_name=event_name,
        reason_code=reason_code,
        reason="HOL Guard could not complete the native hook decision safely.",
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        recording_only=recording_only,
    )
    route = "native_degraded" if response.get("reason_code") == "native_degraded_emergency_safe" else "native_fail_safe"
    host.metrics.record_route(route)
    if event_name == "PreToolUse":
        writer = host.activity_writer
        submit = getattr(writer, "submit_command_activity", None)
        if callable(submit):
            with suppress(Exception):
                _ = submit(
                    harness=harness,
                    event=event_name,
                    payload=payload,
                    succeeded=str(response.get("policy_action") or "") != "block",
                )
    return response


class HookWorkerNativeMixin:
    """Native edge and explicit-oracle paths kept out of the worker facade."""

    _last_native_decision_receipt: dict[str, object] | None = None

    def _mode_surface_response(
        self: _HookWorkerNativeHost,
        harness: str,
        event_name: str,
        mode: str,
        *,
        payload: dict[str, object],
        workspace: Path | None,
        home_dir: Path,
        guard_home: Path,
    ) -> dict[str, object] | None:
        oracle_surface = python_oracle_surface_enabled(mode)
        if event_name not in {"PreToolUse", "PostToolUse"}:
            if oracle_surface:
                raise HookWorkerUnsupported(f"fast path supports PreToolUse and PostToolUse, got event={event_name}")
            return availability_harness_response(
                payload,
                harness=harness,
                event_name=event_name,
                reason_code="native_hook_event_unavailable",
                reason="HOL Guard could not classify this hook event safely.",
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
            )
        reason_code = {"off": "native_hook_disabled", "shadow": "native_shadow_diagnostic_disabled"}.get(mode)
        if reason_code is None or oracle_surface:
            return None
        reason = {
            "off": "HOL Guard native hook review is explicitly disabled; the action continues without native review.",
            "shadow": "HOL Guard shadow comparison is unavailable outside its diagnostic surface.",
        }[mode]
        return availability_harness_response(
            payload,
            harness=harness,
            event_name=event_name,
            reason_code=reason_code,
            reason=reason,
            workspace=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )

    def _review_pre_tool_http(
        self: _HookWorkerNativeHost,
        payload: dict[str, object],
        *,
        harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
    ) -> dict[str, object]:
        command = pre_tool_command(payload)
        if command is None:
            raise HookWorkerUnsupported("fast path PreToolUse requires a command")
        recording_only = hook_review_is_recording_only(guard_home=guard_home, workspace=workspace)
        native = self._review_pre_tool_native(command, guard_home=guard_home, cwd=workspace, home_dir=home_dir)
        if native is not None:
            if recording_only:
                action = str(native.get("minimum_action") or "")
                if action != "allow" or native.get("decision") != "allow":
                    native = _watch_native_pre_tool_result(native)
                    return recording_only_pre_tool_response(
                        harness,
                        reason_code=str(native.get("reason_code") or "watch_recording_only"),
                        reason=str(native.get("reason") or "Watch recorded this action without stopping it."),
                    )
            else:
                action = str(native.get("minimum_action") or "")
                if action == "review":
                    record_python_semantic_hook_route()
                    raise HookWorkerUnsupported("native PreToolUse review uses CLI approval coordination")
            return harness_json_from_native_pre_tool(harness, native)
        if recording_only:
            return _record_unavailable_native(
                self,
                payload,
                harness=harness,
                event_name="PreToolUse",
                reason_code="watch_recording_only",
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
                recording_only=True,
            )
        status = self._native_runtime_status()
        if status.mode == "off":
            raise HookWorkerUnsupported("native PreToolUse runtime is off")
        if status.mode == "shadow":
            raise HookWorkerUnsupported("native PreToolUse runtime is unavailable")
        return availability_harness_response(
            payload,
            harness=harness,
            event_name="PreToolUse",
            reason_code="native_pre_tool_unavailable",
            reason="HOL Guard could not complete the native PreToolUse decision safely.",
            workspace=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )

    def _review_native_edge(
        self: _HookWorkerNativeHost,
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
        policy_snapshot = self._native_policy_snapshot(workspace, deadline=deadline)
        recording_only = hook_review_is_recording_only(guard_home=guard_home, workspace=workspace) or (
            policy_snapshot is not None and policy_snapshot.get("mode") == "observe"
        )
        edge = self._review_raw_hook_native(
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
            return _record_unavailable_native(
                self,
                payload,
                harness=harness,
                event_name=event_name,
                reason_code=reason_code,
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
                recording_only=recording_only,
            )
        native_event = str(edge["event_name"])
        native_harness = str(edge["harness"])
        native_result = edge["result"]
        if not isinstance(native_result, Mapping):
            return _record_unavailable_native(
                self,
                payload,
                harness=harness,
                event_name=event_name,
                reason_code="native_hook_edge_invalid_response",
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
                recording_only=recording_only,
            )
        self._record_native_decision_receipt(edge.get("receipt"))
        self.metrics.record_route("native_resident")
        if native_event == "PreToolUse":
            if recording_only:
                action = str(native_result.get("minimum_action") or "")
                if action != "allow" or native_result.get("decision") != "allow":
                    native_result = _watch_native_pre_tool_result(native_result)
                    return recording_only_pre_tool_response(
                        native_harness,
                        reason_code=str(native_result.get("reason_code") or "watch_recording_only"),
                        reason=str(native_result.get("reason") or "Watch recorded this action without stopping it."),
                    )
            action = str(native_result.get("minimum_action") or "")
            if action == "review":
                return pause_native_pre_tool_for_approval(
                    self.store,
                    harness=native_harness,
                    payload=payload,
                    native_result=native_result,
                    workspace=workspace,
                    guard_home=guard_home,
                )
            return harness_json_from_native_pre_tool(native_harness, native_result)
        if recording_only:
            native_result = _watch_native_post_tool_result(native_result)
        self._record_post_tool_activity(
            harness=native_harness,
            payload=payload,
            succeeded=hook_post_succeeded(native_event, payload),
        )
        return harness_json_from_native_post_tool(native_harness, native_result)

    def _record_native_decision_receipt(self: _HookWorkerNativeHost, receipt: object) -> None:
        """Hand Rust evidence to the non-authoritative writer without waiting."""

        if isinstance(receipt, Mapping):
            self._last_native_decision_receipt = dict(receipt)
        writer = self.activity_writer
        submit = getattr(writer, "submit_native_decision_receipt", None)
        if not callable(submit) or not isinstance(receipt, Mapping):
            return
        with suppress(Exception):
            _ = submit(receipt=receipt)
