"""Native hook review helpers shared by the daemon hook worker."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Protocol

from ..cli.commands_support_command_activity import hook_post_succeeded
from ..config import load_guard_config
from ..native_mode import python_oracle_surface_enabled
from ..native_route_receipt import record_python_semantic_hook_route
from ..native_runtime import NativeRuntimeStatus
from ..protection_posture import protection_is_off
from ..runtime.hook_review_types import HookReviewRequest, HookReviewResponse
from .hook_availability_policy import availability_harness_response
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import (
    harness_json_from_native_post_tool,
    harness_json_from_native_pre_tool,
    post_tool_fail_safe_response,
)


class PythonOracle(Protocol):
    """Minimal response surface accepted from an explicit test oracle."""

    def review(self, request: HookReviewRequest) -> HookReviewResponse: ...


class HookWorkerUnsupported(RuntimeError):  # noqa: N818
    """Raised only for explicit off/shadow compatibility requests."""


class _HookWorkerMetrics(Protocol):
    def record_route(self, route: str) -> None: ...


class _HookWorkerNativeHost(Protocol):
    @property
    def metrics(self) -> _HookWorkerMetrics: ...

    @property
    def activity_writer(self) -> object | None: ...

    _last_native_decision_receipt: dict[str, object] | None
    _native_policy_snapshot: Callable[[Path | None], dict[str, object] | None]
    _review_pre_tool_native: Callable[..., dict[str, object] | None]
    _native_runtime_status: Callable[[], NativeRuntimeStatus]
    _review_raw_hook_native: Callable[..., dict[str, object] | None]
    _record_post_tool_activity: Callable[..., None]
    _record_native_decision_receipt: Callable[[object], None]


class HookWorkerNativeMixin:
    """Native edge and explicit-oracle paths kept out of the worker facade."""

    _last_native_decision_receipt: dict[str, object] | None = None

    def _mode_surface_response(
        self: _HookWorkerNativeHost,
        harness: str,
        event_name: str,
        mode: str,
    ) -> dict[str, object] | None:
        oracle_surface = python_oracle_surface_enabled(mode)
        if event_name not in {"PreToolUse", "PostToolUse"}:
            if oracle_surface:
                raise HookWorkerUnsupported(f"fast path supports PreToolUse and PostToolUse, got event={event_name}")
            return post_tool_fail_safe_response(
                harness,
                reason="HOL Guard could not classify this hook event safely.",
                reason_code="native_hook_event_unavailable",
            )
        reason_code = {"off": "native_hook_disabled", "shadow": "native_shadow_diagnostic_disabled"}.get(mode)
        if reason_code is None or oracle_surface:
            return None
        reason = {
            "off": "HOL Guard native hook review is explicitly disabled; the action is blocked safely.",
            "shadow": "HOL Guard shadow comparison is unavailable outside its diagnostic surface.",
        }[mode]
        return post_tool_fail_safe_response(harness, reason=reason, reason_code=reason_code)

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
        config = load_guard_config(guard_home, workspace=workspace)
        recording_only = protection_is_off(posture=config.protection_posture, mode=config.mode)
        native = self._review_pre_tool_native(command, guard_home=guard_home, cwd=workspace, home_dir=home_dir)
        if native is not None:
            action = str(native.get("minimum_action") or "")
            if action == "review" or (recording_only and action != "allow"):
                record_python_semantic_hook_route()
                raise HookWorkerUnsupported("native PreToolUse review uses CLI approval coordination")
            return harness_json_from_native_pre_tool(harness, native)
        if recording_only:
            raise HookWorkerUnsupported("observe PreToolUse uses CLI recording")
        status = self._native_runtime_status()
        if status.mode == "off":
            raise HookWorkerUnsupported("native PreToolUse runtime is off")
        if status.mode == "shadow":
            raise HookWorkerUnsupported("native PreToolUse runtime is unavailable")
        return post_tool_fail_safe_response(
            harness,
            reason="HOL Guard could not complete the native PreToolUse decision safely.",
            reason_code="native_pre_tool_unavailable",
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
        policy_snapshot = self._native_policy_snapshot(workspace)
        recording_only = policy_snapshot is not None and policy_snapshot.get("mode") == "observe"
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
            response = availability_harness_response(
                payload,
                harness=harness,
                event_name=event_name,
                reason_code=reason_code,
                reason="HOL Guard could not complete the native hook decision safely.",
                workspace=workspace,
                home_dir=home_dir,
            )
            route = (
                "native_degraded"
                if response.get("reason_code") == "native_degraded_emergency_safe"
                else "native_fail_safe"
            )
            self.metrics.record_route(route)
            return response
        native_event = str(edge["event_name"])
        native_harness = str(edge["harness"])
        native_result = edge["result"]
        if not isinstance(native_result, Mapping):
            response = availability_harness_response(
                payload,
                harness=harness,
                event_name=event_name,
                reason_code="native_hook_edge_invalid_response",
                reason="HOL Guard could not complete the native hook decision safely.",
                workspace=workspace,
                home_dir=home_dir,
            )
            route = (
                "native_degraded"
                if response.get("reason_code") == "native_degraded_emergency_safe"
                else "native_fail_safe"
            )
            self.metrics.record_route(route)
            return response
        self._record_native_decision_receipt(edge.get("receipt"))
        self.metrics.record_route("native_resident")
        if native_event == "PreToolUse":
            return harness_json_from_native_pre_tool(native_harness, native_result)
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
