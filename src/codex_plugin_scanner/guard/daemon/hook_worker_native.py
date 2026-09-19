"""Native hook review helpers shared by the daemon hook worker."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ..cli.commands_support_command_activity import hook_post_succeeded
from ..native_mode import python_oracle_surface_enabled
from ..native_policy_decision_context import NativePolicyDecisionContext
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..native_route_receipt import record_python_semantic_hook_route
from ..native_runtime import NativeRuntimeStatus, native_output_sha256
from ..native_scoped_result import scoped_result_is_current
from ..runtime.hook_output_text import extract_payload_output
from ..runtime.hook_review_types import HookReviewRequest, HookReviewResponse
from .hook_availability_policy import (
    availability_harness_response,
    hook_review_is_recording_only,
    recording_only_pre_tool_response,
)
from .hook_native_activity import _record_native_pre_activity, _record_unavailable_native
from .hook_native_policy_context import capture_result_context
from .hook_native_review_approval import pause_native_pre_tool_for_approval
from .hook_native_review_fence import native_review_fence
from .hook_policy_authority import legacy_source_binding_is_current, policy_authority_required
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import (
    harness_json_from_native_post_tool,
    harness_json_from_native_pre_tool,
    integrity_fail_closed_hook_response,
)

_NATIVE_PRE_TOOL_APPROVAL_ACTIONS = frozenset({"review", "require-reapproval"})


def _watch_native_pre_tool_result(native: Mapping[str, object]) -> dict[str, object]:
    rewritten = dict(native)
    if str(rewritten.get("minimum_action") or "") == "allow" and rewritten.get("decision") == "allow":
        return rewritten
    rewritten["decision"] = "allow"
    rewritten["minimum_action"] = "warn"
    rewritten["policy_action"] = "warn"
    return rewritten


def _canonical_output_sha256(value: object) -> str | None:
    if not isinstance(value, str) or len(value) != 64:
        return None
    if any(character not in "0123456789abcdef" for character in value):
        return None
    return value


def _recording_only_output_sha256(payload: Mapping[str, object]) -> str | None:
    source_ref = payload.get("guard_source_ref")
    if isinstance(source_ref, Mapping):
        digest = _canonical_output_sha256(source_ref.get("output_sha256"))
        if digest is not None:
            return digest

    summary = payload.get("tool_response_summary")
    if isinstance(summary, Mapping):
        digest = _canonical_output_sha256(summary.get("output_sha256"))
        if digest is not None:
            return digest
        # A summary can contain only a bounded excerpt. Never treat it as the
        # complete output when its canonical full-output proof is absent. If a
        # complete inline payload is also present, fall through and prove it.

    # Pi's legacy inline payload carries the complete output under
    # ``tool_response``. Keep the extraction isolated from other fields such
    # as stdout, which may be a bounded rendering of the same output.
    if "tool_response" not in payload:
        return None
    extracted = extract_payload_output({"tool_response": payload["tool_response"]})
    if extracted.truncated:
        return None
    return native_output_sha256(extracted.text)


def _watch_native_post_tool_result(
    native: Mapping[str, object],
    payload: Mapping[str, object],
) -> dict[str, object]:
    digest = _recording_only_output_sha256(payload)
    rewritten = dict(native)
    if rewritten.get("decision") == "allow" and rewritten.get("model_output_action") == "allow_original":
        if digest is not None:
            rewritten["reviewed_output_sha256"] = digest
        else:
            rewritten.pop("reviewed_output_sha256", None)
        return rewritten
    rewritten["decision"] = "allow"
    rewritten["model_output_action"] = "allow_original"
    rewritten["policy_action"] = "warn"
    if digest is not None:
        rewritten["reviewed_output_sha256"] = digest
    else:
        rewritten.pop("reviewed_output_sha256", None)
    return rewritten


class PythonOracle(Protocol):
    """Minimal response surface accepted from an explicit test oracle."""

    def review(self, request: HookReviewRequest) -> HookReviewResponse: ...


class HookWorkerUnsupported(RuntimeError):  # noqa: N818
    """Raised only for explicit off/shadow compatibility requests."""


class _HookWorkerMetrics(Protocol):
    def record_route(self, route: str) -> None: ...


if TYPE_CHECKING:
    from ..store import GuardStore


class _HookWorkerNativeHost(Protocol):
    store: GuardStore

    @property
    def metrics(self) -> _HookWorkerMetrics: ...

    @property
    def activity_writer(self) -> object | None: ...

    _last_native_decision_receipt: dict[str, object] | None
    _last_native_policy_context: NativePolicyDecisionContext | None
    _native_policy_snapshot: Callable[..., dict[str, object] | None]
    _review_pre_tool_native: Callable[..., dict[str, object] | None]
    _native_runtime_status: Callable[[], NativeRuntimeStatus]
    _review_raw_hook_native: Callable[..., dict[str, object] | None]
    _review_native_edge_with_snapshot: Callable[..., tuple[dict[str, object], bool]]
    _record_post_tool_activity: Callable[..., None]
    _record_native_decision_receipt: Callable[[object], Mapping[str, object] | None]


def _scoped_authority_unavailable(
    host: _HookWorkerNativeHost, harness: str, event_name: str = "PreToolUse"
) -> dict[str, object]:
    host.metrics.record_route("native_fail_safe")
    return integrity_fail_closed_hook_response(
        harness,
        event_name=event_name,
        reason="HOL Guard could not verify the current scoped policy authority.",
        reason_code="native_scoped_authority_unavailable",
    )


class HookWorkerNativeMixin:
    """Native edge and explicit-oracle paths kept out of the worker facade."""

    _last_native_decision_receipt: dict[str, object] | None = None
    _last_native_policy_context: NativePolicyDecisionContext | None = None

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
                    response = recording_only_pre_tool_response(
                        harness,
                        reason_code=str(native.get("reason_code") or "watch_recording_only"),
                        reason=str(native.get("reason") or "Watch recorded this action without stopping it."),
                    )
                    return _record_native_pre_activity(self, harness, payload, response)
            else:
                action = str(native.get("minimum_action") or "")
                if action in _NATIVE_PRE_TOOL_APPROVAL_ACTIONS:
                    record_python_semantic_hook_route()
                    raise HookWorkerUnsupported("native PreToolUse review uses CLI approval coordination")
            return _record_native_pre_activity(
                self, harness, payload, harness_json_from_native_pre_tool(harness, native)
            )
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
        publisher = getattr(self, "policy_snapshot_publisher", None)
        required = policy_authority_required(publisher)
        try:
            policy_snapshot = self._native_policy_snapshot(workspace, deadline=deadline)
        except Exception:
            if required or policy_authority_required(publisher):
                return _scoped_authority_unavailable(self, harness, event_name)
            raise
        required = policy_authority_required(publisher)
        if required and policy_snapshot is None:
            return _scoped_authority_unavailable(self, harness, event_name)
        scoped = getattr(publisher, "requires_scoped_authority", False) is True or (
            policy_snapshot is not None and "source_input_digest" in policy_snapshot
        )
        if scoped and (policy_snapshot is None or "source_input_digest" not in policy_snapshot):
            return _scoped_authority_unavailable(self, harness, event_name)
        # Delivery uses the exact acknowledged posture. Pending local edits
        # cannot weaken the accepted decision while its replacement is unready.
        recording_only = not scoped and policy_snapshot is not None and policy_snapshot.get("mode") == "observe"
        fenced: bool | None = None
        try:
            with native_review_fence(
                policy_snapshot=policy_snapshot,
                event_name=event_name,
                recording_only=recording_only,
                guard_home=guard_home,
                deadline=deadline,
            ) as fenced:
                response, native_used = self._review_native_edge_with_snapshot(
                    payload=payload,
                    harness=harness,
                    event_name=event_name,
                    default_harness=default_harness,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    workspace=workspace,
                    deadline=deadline,
                    policy_snapshot=policy_snapshot,
                    recording_only=recording_only,
                )
                if (
                    fenced
                    and native_used
                    and response.get("policy_action") == "allow"
                    and deadline is not None
                    and time.monotonic() >= deadline
                ):
                    raise TimeoutError("native_review_fence_deadline")
            if native_used:
                self.metrics.record_route("native_resident")
            return response
        except TimeoutError:
            if required or scoped or policy_authority_required(publisher):
                return _scoped_authority_unavailable(self, harness, event_name)
            return _record_unavailable_native(
                self,
                payload,
                harness=harness,
                event_name=event_name,
                reason_code="native_review_deadline_exceeded",
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
                recording_only=recording_only,
            )
        except (OSError, NativePolicySnapshotError):
            if required or scoped or policy_authority_required(publisher):
                return _scoped_authority_unavailable(self, harness, event_name)
            if fenced is False:
                raise
            return _record_unavailable_native(
                self,
                payload,
                harness=harness,
                event_name=event_name,
                reason_code="native_command_control_fence_unavailable",
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
                recording_only=recording_only,
            )

    def _review_native_edge_with_snapshot(
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
        policy_snapshot: Mapping[str, object] | None,
        recording_only: bool,
    ) -> tuple[dict[str, object], bool]:
        publisher = getattr(self, "policy_snapshot_publisher", None)
        required = policy_authority_required(publisher)
        scoped = getattr(publisher, "requires_scoped_authority", False) is True or (
            policy_snapshot is not None and "source_input_digest" in policy_snapshot
        )
        try:
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
        except Exception:
            if required or scoped or policy_authority_required(publisher):
                return _scoped_authority_unavailable(self, harness, event_name), False
            raise
        required |= policy_authority_required(publisher)
        if (
            required
            and not scoped
            and (edge is None or not legacy_source_binding_is_current(publisher, policy_snapshot))
        ):
            return _scoped_authority_unavailable(self, harness, event_name), False
        if scoped and (edge is None or not scoped_result_is_current(publisher, edge)):
            return _scoped_authority_unavailable(self, harness, event_name), False
        self._last_native_policy_context = None
        if scoped and edge is not None:
            accepted, self._last_native_policy_context = capture_result_context(publisher, edge)
            if not accepted:
                return _scoped_authority_unavailable(self, harness, event_name), False
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
            return (
                _record_unavailable_native(
                    self,
                    payload,
                    harness=harness,
                    event_name=event_name,
                    reason_code=reason_code,
                    workspace=workspace,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    recording_only=recording_only,
                ),
                False,
            )
        native_event = str(edge["event_name"])
        native_harness = str(edge["harness"])
        native_result = edge["result"]
        if not isinstance(native_result, Mapping):
            return (
                _record_unavailable_native(
                    self,
                    payload,
                    harness=harness,
                    event_name=event_name,
                    reason_code="native_hook_edge_invalid_response",
                    workspace=workspace,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    recording_only=recording_only,
                ),
                False,
            )
        raw_receipt = edge.get("receipt")
        accepted_receipt = self._record_native_decision_receipt(raw_receipt)
        if native_event == "PreToolUse":
            if recording_only:
                action = str(native_result.get("minimum_action") or "")
                if action != "allow" or native_result.get("decision") != "allow":
                    native_result = _watch_native_pre_tool_result(native_result)
                    response = recording_only_pre_tool_response(
                        native_harness,
                        reason_code=str(native_result.get("reason_code") or "watch_recording_only"),
                        reason=str(native_result.get("reason") or "Watch recorded this action without stopping it."),
                    )
                    return (
                        _record_native_pre_activity(self, native_harness, payload, response, accepted_receipt),
                        True,
                    )
            action = str(native_result.get("minimum_action") or "")
            if action in _NATIVE_PRE_TOOL_APPROVAL_ACTIONS:
                response = pause_native_pre_tool_for_approval(
                    self.store,
                    harness=native_harness,
                    payload=payload,
                    native_result=native_result,
                    native_receipt=accepted_receipt,
                    workspace=workspace,
                    guard_home=guard_home,
                )
                return (_record_native_pre_activity(self, native_harness, payload, response, accepted_receipt), True)
            return (
                _record_native_pre_activity(
                    self,
                    native_harness,
                    payload,
                    harness_json_from_native_pre_tool(native_harness, native_result),
                    accepted_receipt,
                ),
                True,
            )
        if recording_only:
            native_result = _watch_native_post_tool_result(native_result, payload)
        self._record_post_tool_activity(
            harness=native_harness,
            payload=payload,
            succeeded=hook_post_succeeded(native_event, payload),
        )
        return (harness_json_from_native_post_tool(native_harness, native_result), True)

    def _record_native_decision_receipt(self: _HookWorkerNativeHost, receipt: object) -> Mapping[str, object] | None:
        """Accept only a validated Rust receipt; persistence remains best-effort."""

        from ..native_decision_receipt import validate_native_decision_receipt

        self._last_native_decision_receipt = None
        accepted = validate_native_decision_receipt(receipt)
        if accepted is None:
            self._last_native_policy_context = None
            return None
        writer = self.activity_writer
        submit = getattr(writer, "submit_native_decision_receipt", None)
        if callable(submit):
            with suppress(Exception):
                context = getattr(self, "_last_native_policy_context", None)
                if context is None:
                    submit(receipt=accepted)
                else:
                    submit(receipt=accepted, policy_context=context)
        self._last_native_decision_receipt = accepted
        return accepted
