"""Native hook review helpers shared by the daemon hook worker."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ..cli.commands_support_command_activity import hook_post_succeeded
from ..codex_binding_capture_writer import CodexBindingCaptureWriter
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..native_runtime import NativeRuntimeStatus, native_mode
from ..runtime.structured_output_mediation import (
    StructuredContentMediation,
    StructuredOutputBinding,
    StructuredOutputResolution,
    canonical_harness_name,
    mediate_native_post_tool_content,
    resolve_managed_structured_output_resolution,
)
from .hook_availability_policy import (
    availability_harness_response,
    recording_only_pre_tool_response,
)
from .hook_native_review_approval import (
    pause_native_pre_tool_for_approval,
    record_claude_permission_notice_for_native_review,
)
from .hook_native_review_fence import native_review_fence
from .hook_policy_repair import apply_command_policy_repair
from .hook_worker_responses import (
    harness_json_from_native_post_tool,
    harness_json_from_native_pre_tool,
    harness_json_from_native_prompt,
    observe_lifecycle_fail_safe_response,
)

_NATIVE_PRE_TOOL_APPROVAL_ACTIONS = frozenset({"review", "require-reapproval"})


_CLAUDE_SECRET_READ_NATIVE_CLASSES = frozenset({"local_env_read", "sensitive_material"})


def _claude_native_prompt_brand(
    response: dict[str, object],
    native_result: Mapping[str, object],
) -> dict[str, object]:
    """Overlay the Python-owned Claude approval presentation on a native prompt result.

    Rust decides the action; this only re-derives the branded system message and
    approval briefing copy that the hook surfaces to Claude Code users.
    """
    from ..cli.commands_support_prompts import (
        _claude_prompt_additional_context,
        _claude_prompt_system_message,
    )
    from ..models import GuardArtifact

    raw_classes = native_result.get("prompt_risk_classes")
    request_classes = (
        [
            "secret_read" if item in _CLAUDE_SECRET_READ_NATIVE_CLASSES else item
            for item in raw_classes
            if isinstance(item, str) and item
        ]
        if isinstance(raw_classes, list)
        else []
    )
    artifact = GuardArtifact(
        artifact_id="claude-code:native-prompt:session",
        name="user prompt",
        harness="claude-code",
        artifact_type="prompt_request",
        source_scope="harness",
        config_path="",
        metadata={"prompt_request_classes": request_classes},
    )
    policy_action = str(native_result.get("minimum_action") or "")
    native_reason = str(native_result.get("reason") or "")
    system_message = _claude_prompt_system_message(
        event_name="UserPromptSubmit",
        policy_action=policy_action,
        artifact=artifact,
        native_reason=native_reason,
    )
    if system_message:
        response["systemMessage"] = system_message
    additional_context = _claude_prompt_additional_context(
        harness="claude-code",
        event_name="UserPromptSubmit",
        policy_action=policy_action,
        artifact=artifact,
        native_reason=native_reason,
    )
    if additional_context:
        hook_output = response.get("hookSpecificOutput")
        if isinstance(hook_output, dict):
            hook_output["additionalContext"] = additional_context
    return response


def _watch_native_pre_tool_result(native: Mapping[str, object]) -> dict[str, object]:
    rewritten = dict(native)
    if str(rewritten.get("minimum_action") or "") == "allow" and rewritten.get("decision") == "allow":
        return rewritten
    rewritten["decision"] = "allow"
    rewritten["minimum_action"] = "warn"
    rewritten["policy_action"] = "warn"
    return rewritten


class _HookWorkerMetrics(Protocol):
    def record_route(self, route: str) -> None: ...


if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore


class _HookWorkerNativeHost(Protocol):
    store: GuardStore
    capture_writer: CodexBindingCaptureWriter | None

    @property
    def metrics(self) -> _HookWorkerMetrics: ...

    @property
    def activity_writer(self) -> object | None: ...

    _last_native_decision_receipt: dict[str, object] | None
    _native_policy_snapshot: Callable[..., dict[str, object] | None]
    _native_runtime_status: Callable[[], NativeRuntimeStatus]
    _hook_event_name: Callable[[Mapping[str, object]], str]
    _review_raw_hook_native: Callable[..., dict[str, object] | None]
    _review_native_edge_with_snapshot: Callable[..., tuple[dict[str, object], bool]]
    _record_post_tool_activity: Callable[..., None]
    _record_native_decision_receipt: Callable[[object], Mapping[str, object] | None]
    _apply_structured_unavailable_overlay: Callable[..., dict[str, object]]

    def _load_config(self, guard_home: Path, workspace: Path | None) -> GuardConfig: ...

    def _apply_structured_mediation(
        self,
        native_result: Mapping[str, object],
        *,
        payload: Mapping[str, object],
        native_harness: str,
        native_event: str,
        accepted_receipt: Mapping[str, object] | None,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None,
        recording_only: bool,
    ) -> dict[str, object]: ...

    def _structured_output_resolution(
        self,
        *,
        guard_home: Path,
        workspace: Path | None,
        harness: str,
    ) -> StructuredOutputResolution: ...


def _record_native_pre_activity(
    host: _HookWorkerNativeHost,
    harness: str,
    payload: Mapping[str, object],
    response: dict[str, object],
    receipt: Mapping[str, object] | None = None,
) -> dict[str, object]:
    submit = getattr(host.activity_writer, "submit_command_activity", None)
    if callable(submit):
        with suppress(Exception):
            submit(
                harness=harness,
                event="PreToolUse",
                payload=payload,
                succeeded=True,
                policy_action=response.get("policy_action"),
                receipt_id=receipt.get("decision_id") if receipt is not None else None,
                prompted=response.get("prompted") is True,
                approval_reuse_status=response.get("approval_reuse_status", "not-applicable"),
            )
    return response


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
                    policy_action=response.get("policy_action"),
                )
    return response


class HookWorkerNativeMixin:
    """Native edge paths kept out of the worker facade."""

    _last_native_decision_receipt: dict[str, object] | None = None

    def _structured_output_binding(
        self: _HookWorkerNativeHost,
        *,
        guard_home: Path,
        workspace: Path | None,
        harness: str,
    ) -> StructuredOutputBinding | None:
        """Read the active machine binding without creating a local authority.

        This compatibility wrapper intentionally drops the required-state
        detail; the native PostToolUse path uses ``_structured_output_resolution``
        when it must distinguish optional-off from fail-closed authority.
        """

        return self._structured_output_resolution(
            guard_home=guard_home,
            workspace=workspace,
            harness=harness,
        ).binding

    def _structured_output_resolution(
        self: _HookWorkerNativeHost,
        *,
        guard_home: Path,
        workspace: Path | None,
        harness: str,
    ) -> StructuredOutputResolution:
        """Resolve managed output only for post-native presentation.

        This helper must run after the Rust edge has returned. Structured output
        is an adapter projection and cannot participate in the native decision
        or its availability floor.
        """

        loader = getattr(self, "_load_config", None)
        if not callable(loader):
            return StructuredOutputResolution(None, True, "structured_managed_authority_unavailable")
        try:
            config = loader(guard_home, workspace)
            if config is None:
                return StructuredOutputResolution(None, True, "structured_managed_authority_unavailable")
            return resolve_managed_structured_output_resolution(config, harness=harness)
        except Exception:
            # A config read failure cannot establish whether the managed route
            # is enrolled.  Keep the model-visible destination fail-closed.
            return StructuredOutputResolution(None, True, "structured_managed_authority_unavailable")

    def _apply_structured_mediation(
        self: _HookWorkerNativeHost,
        native_result: Mapping[str, object],
        *,
        payload: Mapping[str, object],
        native_harness: str,
        native_event: str,
        accepted_receipt: Mapping[str, object] | None,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None,
        recording_only: bool,
    ) -> dict[str, object]:
        """Project managed structured mediation after Rust has decided."""

        if native_event != "PostToolUse" or canonical_harness_name(native_harness) not in {"pi", "omp"}:
            return dict(native_result)
        resolution = self._structured_output_resolution(
            guard_home=guard_home,
            workspace=workspace,
            harness=native_harness,
        )
        if not resolution.required:
            return dict(native_result)
        mediation = mediate_native_post_tool_content(
            harness=native_harness,
            event_name=native_event,
            native_result=native_result,
            validated_receipt=accepted_receipt,
            structured_output_json=payload.get("structured_output_json"),
            binding=resolution.binding,
            required_reason_code=resolution.reason_code,
            # This second read is a revocation/binding check after scanning;
            # reusing the initial resolution would permit a stale forward.
            recheck_binding=lambda: (
                self._structured_output_resolution(
                    guard_home=guard_home,
                    workspace=workspace,
                    harness=native_harness,
                ).binding
            ),
            deadline_monotonic=deadline,
            allow_observe_mode=recording_only,
        )
        if mediation is None:
            return dict(native_result)
        return {
            **native_result,
            "structured_content_mediation": mediation.to_harness_json(),
        }

    def _apply_structured_unavailable_overlay(
        self: _HookWorkerNativeHost,
        response: dict[str, object],
        *,
        harness: str,
        event_name: str,
        guard_home: Path,
        workspace: Path | None,
        resolution: StructuredOutputResolution | None = None,
    ) -> dict[str, object]:
        """Withhold a managed structured destination when native proof is absent.

        This is an adapter-only overlay. It does not change the native result,
        receipt, or native availability floor. An intentionally unconfigured
        structured destination keeps the existing availability response.
        """

        if event_name != "PostToolUse" or canonical_harness_name(harness) not in {"pi", "omp"}:
            return response
        # Unavailable-edge callers supply their one resolution. The successful
        # edge uses a separate initial read and a post-scan revocation check.
        resolved = resolution or self._structured_output_resolution(
            guard_home=guard_home,
            workspace=workspace,
            harness=harness,
        )
        if not resolved.required:
            return response
        return {
            **response,
            "structured_content_mediation": StructuredContentMediation(
                action="withhold",
                reason_code="structured_native_edge_unavailable",
                native_decision_id=None,
            ).to_harness_json(),
        }

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
        if event_name not in {"PreToolUse", "PostToolUse"}:
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
        if reason_code is None:
            return None
        reason = {
            "off": "HOL Guard native hook review is explicitly disabled; no trusted native decision is available.",
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
        reason_code = "native_hook_disabled" if native_mode() == "off" else "native_shadow_diagnostic_disabled"
        return availability_harness_response(
            payload,
            harness=harness,
            event_name="PreToolUse",
            reason_code=reason_code,
            reason="HOL Guard could not complete the native hook decision safely.",
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
        claim_saved_approval: bool = True,
        claimed_saved_allow_hash: str | None = None,
        claimed_approval_request_id: str | None = None,
    ) -> dict[str, object]:
        policy_snapshot = self._native_policy_snapshot(workspace, deadline=deadline)
        # Native evaluation and Python delivery use the same acknowledged
        # posture. A local Watch edit cannot weaken an enforcing snapshot
        # before its replacement is accepted. A missing binding takes the
        # unavailable route and cannot establish recording-only authority.
        recording_only = policy_snapshot is not None and policy_snapshot.get("mode") == "observe"
        fenced: bool | None = None
        capture_receipts: list[Mapping[str, object]] = []
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
                    claim_saved_approval=claim_saved_approval,
                    claimed_saved_allow_hash=claimed_saved_allow_hash,
                    claimed_approval_request_id=claimed_approval_request_id,
                    capture_receipts=capture_receipts,
                )
                if (
                    fenced
                    and native_used
                    and response.get("policy_action") == "allow"
                    and deadline is not None
                    and time.monotonic() >= deadline
                ):
                    raise TimeoutError("native_review_fence_deadline")
            if capture_receipts and self.capture_writer is not None:
                with suppress(Exception):
                    _ = self.capture_writer.submit_native_capture(
                        guard_home=guard_home, payload=payload, receipt=capture_receipts[0]
                    )
            if native_used:
                self.metrics.record_route("native_resident")
            return response
        except TimeoutError:
            return self._apply_structured_unavailable_overlay(
                _record_unavailable_native(
                    self,
                    payload,
                    harness=harness,
                    event_name=event_name,
                    reason_code="native_review_deadline_exceeded",
                    workspace=workspace,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    recording_only=recording_only,
                ),
                harness=harness,
                event_name=event_name,
                guard_home=guard_home,
                workspace=workspace,
            )
        except (OSError, NativePolicySnapshotError):
            if fenced is False:
                raise
            return self._apply_structured_unavailable_overlay(
                _record_unavailable_native(
                    self,
                    payload,
                    harness=harness,
                    event_name=event_name,
                    reason_code="native_command_control_fence_unavailable",
                    workspace=workspace,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    recording_only=recording_only,
                ),
                harness=harness,
                event_name=event_name,
                guard_home=guard_home,
                workspace=workspace,
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
        claim_saved_approval: bool = True,
        claimed_saved_allow_hash: str | None = None,
        claimed_approval_request_id: str | None = None,
        capture_receipts: list[Mapping[str, object]] | None = None,
    ) -> tuple[dict[str, object], bool]:
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
            structured_resolution = (
                self._structured_output_resolution(
                    guard_home=guard_home,
                    workspace=workspace,
                    harness=harness,
                )
                if event_name == "PostToolUse" and canonical_harness_name(harness) in {"pi", "omp"}
                else StructuredOutputResolution(None, False)
            )
            return (
                self._apply_structured_unavailable_overlay(
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
                    harness=harness,
                    event_name=event_name,
                    guard_home=guard_home,
                    workspace=workspace,
                    resolution=structured_resolution,
                ),
                False,
            )
        native_event = str(edge["event_name"])
        native_harness = str(edge["harness"])
        native_result = edge["result"]
        if not isinstance(native_result, Mapping):
            structured_resolution = (
                self._structured_output_resolution(
                    guard_home=guard_home,
                    workspace=workspace,
                    harness=harness,
                )
                if event_name == "PostToolUse" and canonical_harness_name(harness) in {"pi", "omp"}
                else StructuredOutputResolution(None, False)
            )
            return (
                self._apply_structured_unavailable_overlay(
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
                    harness=harness,
                    event_name=event_name,
                    guard_home=guard_home,
                    workspace=workspace,
                    resolution=structured_resolution,
                ),
                False,
            )
        raw_receipt = edge.get("receipt")
        accepted_receipt = self._record_native_decision_receipt(raw_receipt)
        if accepted_receipt is not None and capture_receipts is not None and native_harness == "codex":
            capture_receipts.append(accepted_receipt)
        if native_event == "UserPromptSubmit":
            if accepted_receipt is None:
                return (
                    _record_unavailable_native(
                        self,
                        payload,
                        harness=native_harness,
                        event_name=native_event,
                        reason_code="native_hook_edge_invalid_response",
                        workspace=workspace,
                        home_dir=home_dir,
                        guard_home=guard_home,
                        recording_only=recording_only,
                    ),
                    False,
                )
            if recording_only:
                return (
                    observe_lifecycle_fail_safe_response(
                        native_harness,
                        event_name=native_event,
                        reason_code="watch_recording_only",
                    ),
                    True,
                )
            response = harness_json_from_native_prompt(native_harness, native_result)
            if native_harness.strip().lower().replace("_", "-") == "claude-code":
                with suppress(Exception):
                    response = _claude_native_prompt_brand(response, native_result)
            return (response, True)
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
                    home_dir=home_dir,
                    claim_saved_approval=claim_saved_approval,
                    claimed_saved_allow_hash=claimed_saved_allow_hash,
                    claimed_approval_request_id=claimed_approval_request_id,
                )
                if native_harness.strip().lower().replace("_", "-") == "claude-code" and response.get("prompted"):
                    with suppress(Exception):
                        record_claude_permission_notice_for_native_review(
                            self.store,
                            harness=native_harness,
                            payload=payload,
                            native_result=native_result,
                            native_receipt=accepted_receipt,
                            workspace=workspace,
                            guard_home=guard_home,
                        )
                return (_record_native_pre_activity(self, native_harness, payload, response, accepted_receipt), True)
            repaired_result = apply_command_policy_repair(
                self.store,
                native_result,
                guard_home=guard_home,
            )
            if repaired_result:
                native_result = repaired_result
            from ..adapters.zcode_contained_tests import route_zcode_containment

            rendered = route_zcode_containment(
                harness_json_from_native_pre_tool(native_harness, native_result),
                harness=native_harness,
                payload=payload,
                guard_home=guard_home,
                home_dir=home_dir,
                workspace=workspace,
            )
            return (
                _record_native_pre_activity(
                    self,
                    native_harness,
                    payload,
                    rendered,
                    accepted_receipt,
                ),
                True,
            )
        native_result = self._apply_structured_mediation(
            native_result,
            payload=payload,
            native_harness=native_harness,
            native_event=native_event,
            accepted_receipt=accepted_receipt,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
            recording_only=recording_only,
        )
        self._record_post_tool_activity(
            harness=native_harness,
            payload=payload,
            succeeded=hook_post_succeeded(native_event, payload),
        )
        return (harness_json_from_native_post_tool(native_harness, native_result), True)

    def review_native_edge_decision(
        self: _HookWorkerNativeHost,
        *,
        payload: dict[str, object],
        harness: str,
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None = None,
    ) -> dict[str, object]:
        """Return the raw native edge decision for the CLI presentation path.

        Unlike ``review_http_payload``, this performs no harness rendering and
        no approval queueing; the CLI pipeline owns presentation and approval
        persistence. The returned mapping carries ``result`` (the typed edge
        decision), the validated ``receipt``, and ``recording_only`` posture.
        ``failure_reason_code`` is set when the runtime cannot answer or the
        event is outside native scope.
        """
        event_name = self._hook_event_name(payload)
        if native_mode() not in {"auto", "force"}:
            return {
                "event_name": event_name,
                "harness": harness,
                "result": None,
                "receipt": None,
                "recording_only": False,
                "failure_reason_code": "native_runtime_unavailable",
            }
        policy_snapshot = self._native_policy_snapshot(workspace, deadline=deadline)
        recording_only = policy_snapshot is not None and policy_snapshot.get("mode") == "observe"
        fenced: bool | None = None

        def unavailable(reason_code: str) -> dict[str, object]:
            # The CLI path owns presentation, but evidence persistence stays
            # worker-owned so the daemon and CLI deliveries of the same
            # fail-safe record identical activity.
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
            )
            return {
                "event_name": event_name,
                "harness": harness,
                "result": None,
                "receipt": None,
                "recording_only": recording_only,
                "failure_reason_code": reason_code,
            }

        try:
            with native_review_fence(
                policy_snapshot=policy_snapshot,
                event_name=event_name,
                recording_only=recording_only,
                guard_home=guard_home,
                deadline=deadline,
            ) as fenced:
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
                if edge is not None and deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("native_review_fence_deadline")
        except TimeoutError:
            return unavailable("native_review_deadline_exceeded")
        except (OSError, NativePolicySnapshotError):
            if fenced is False:
                raise
            return unavailable("native_command_control_fence_unavailable")
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
            return unavailable(reason_code)
        native_result = edge["result"]
        if not isinstance(native_result, Mapping):
            return unavailable("native_hook_edge_invalid_response")
        receipt = self._record_native_decision_receipt(edge.get("receipt"))
        native_event = str(edge["event_name"])
        native_harness = str(edge["harness"])
        native_result = self._apply_structured_mediation(
            native_result,
            payload=payload,
            native_harness=native_harness,
            native_event=native_event,
            accepted_receipt=receipt,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
            recording_only=recording_only,
        )
        self.metrics.record_route("native_resident")
        return {
            "event_name": native_event,
            "harness": native_harness,
            "result": native_result,
            "receipt": dict(receipt) if isinstance(receipt, Mapping) else None,
            "recording_only": recording_only,
            "failure_reason_code": None,
        }

    def _record_native_decision_receipt(self: _HookWorkerNativeHost, receipt: object) -> Mapping[str, object] | None:
        """Accept only a validated Rust receipt; persistence remains best-effort."""

        from ..native_decision_receipt import validate_native_decision_receipt

        self._last_native_decision_receipt = None
        accepted = validate_native_decision_receipt(receipt)
        if accepted is None:
            return None
        writer = self.activity_writer
        submit = getattr(writer, "submit_native_decision_receipt", None)
        if callable(submit):
            with suppress(Exception):
                submit(receipt=accepted)
        self._last_native_decision_receipt = accepted
        return accepted
