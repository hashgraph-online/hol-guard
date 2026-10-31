"""Native hook review helpers shared by the daemon hook worker."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from ..cli.commands_support_command_activity import hook_post_succeeded
from ..native_codex_binding_capture import CodexBindingCaptureWriter
from ..native_hook_containment_route import edge_routed_shape
from ..native_hook_decision import NativeHookDecisionError
from ..native_policy_snapshot_harness_postures import recording_only_for_binding
from ..native_resident_client import (
    native_resident_client_failure_code,
    record_native_resident_client_failure_code,
)
from ..native_resident_revival import native_unavailable_reason
from ..native_runtime import NativeRuntimeStatus
from .hook_availability_policy import availability_harness_response
from .hook_evidence_dispatch import run_hook_evidence
from .hook_fail_closed import render_recording_only_pre_tool
from .hook_native_review_approval import (
    pause_native_pre_tool_for_approval,
)
from .hook_native_saved_approval import native_exact_command_block_response
from .hook_policy_fence_window import POLICY_SOURCE_FENCE_ERRORS, PolicySourceFenceBusyError
from .hook_request_parsing import pre_tool_command
from .hook_worker_native_review import (
    CONTROL_BINDING_REFRESH_ERRORS,
    SNAPSHOT_NOT_CURRENT_ERROR,
    NativePolicyBindingRefreshError,
    review_native_edge,
    superseded_post_tool_snapshot,
)
from .hook_worker_structured import (
    read_structured_view,
    structured_destination_required,
    withhold_stale_forward,
    withhold_structured_destination,
    withholds_structured_destination,
)


def _edge_harness_response(edge: Mapping[str, object]) -> dict[str, object]:
    """The harness response Rust rendered for the edge decision."""

    rendered = edge["harness_response"]
    if not isinstance(rendered, dict):
        raise ValueError("native_hook_edge_invalid_response")
    return {str(key): value for key, value in rendered.items()}


_NATIVE_PRE_TOOL_APPROVAL_ACTIONS = frozenset({"review", "require-reapproval"})
# `containment_rewrite` answers the edge gives once it rewrote a sink route.
_EDGE_CONTAINMENT_REWRITES = frozenset({"routed", "kept"})
_EDGE_REWRITE_INVALID = "native_containment_rewrite_invalid"
_EDGE_REWRITE_UNAVAILABLE = "native_containment_rewrite_unavailable"


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

    @property
    def evidence_dispatch(self) -> object | None: ...

    @property
    def policy_snapshot_publisher(self) -> object: ...

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


def _record_native_pre_activity(
    host: _HookWorkerNativeHost,
    harness: str,
    payload: Mapping[str, object],
    response: dict[str, object],
    receipt: Mapping[str, object] | None = None,
) -> dict[str, object]:
    from ..runtime_transition_hook_probe import OBSERVATION_FIELD, transition_hook_observation

    # Bind diagnostics to this call's accepted receipt, never the worker's
    # shared last-receipt slot (other HTTP requests may run concurrently).
    observation = transition_hook_observation(payload, receipt)
    if observation is not None:
        response = {**response, OBSERVATION_FIELD: observation}
    submit = getattr(host.activity_writer, "submit_command_activity", None)
    if callable(submit):
        receipt_id = receipt.get("decision_id") if receipt is not None else None
        # The hook has its verdict; the activity row records it. The writer
        # lives in the resident, so submitting here would spend a round trip
        # in front of the response rather than behind it.
        run_hook_evidence(
            host,
            lambda: submit(
                harness=harness,
                event="PreToolUse",
                payload=payload,
                succeeded=True,
                policy_action=response.get("policy_action"),
                receipt_id=receipt_id,
                prompted=response.get("prompted") is True,
                approval_reuse_status=response.get("approval_reuse_status", "not-applicable"),
            ),
        )
    return response


def _containment_outage(
    host: _HookWorkerNativeHost,
    payload: dict[str, object],
    harness: str,
    error: NativeHookDecisionError,
    guard_home: Path,
    deadline: float | None,
) -> tuple[dict[str, object], bool]:
    """The host outage answer when the resident does not route a PreToolUse call."""
    response = _record_unavailable_native(
        host,
        payload,
        harness=harness,
        event_name="PreToolUse",
        reason_code=error.code,
        guard_home=guard_home,
        deadline=deadline,
    )
    return (response, False)


def _record_unavailable_native(
    host: _HookWorkerNativeHost,
    payload: dict[str, object],
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    guard_home: Path,
    watch_continue: bool = False,
    deadline: float | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    failure_code = native_resident_client_failure_code()
    response = availability_harness_response(
        harness=harness,
        event_name=event_name,
        reason_code=reason_code,
        reason=reason
        or native_unavailable_reason(
            failure_code,
            "HOL Guard could not complete the native hook decision safely.",
        ),
        prompt_reason=reason or native_unavailable_reason(failure_code, "") or None,
    )
    if watch_continue and event_name == "PreToolUse":
        # Only a superseded Watch snapshot (resident reachable) keeps recording,
        # through the resident-rendered continue; any render failure keeps the
        # fixed deny above. Real outages never take this path.
        response = render_recording_only_pre_tool(
            harness,
            reason_code=reason_code,
            reason="Watch recorded this action without stopping it.",
            guard_home=guard_home,
            deadline=deadline,
            fallback=response,
        )
    host.metrics.record_route("native_fail_safe")
    if event_name == "PreToolUse":
        writer = host.activity_writer
        submit = getattr(writer, "submit_command_activity", None)
        if callable(submit):
            run_hook_evidence(
                host,
                lambda: submit(
                    harness=harness,
                    event=event_name,
                    payload=payload,
                    succeeded=str(response.get("policy_action") or "") != "block",
                    policy_action=response.get("policy_action"),
                ),
            )
    return response


class HookWorkerNativeMixin:
    """Native edge paths kept out of the worker facade."""

    _last_native_decision_receipt: dict[str, object] | None = None

    def _apply_structured_unavailable_overlay(
        self: _HookWorkerNativeHost,
        response: dict[str, object],
        *,
        harness: str,
        event_name: str,
        guard_home: Path,
        workspace: Path | None,
    ) -> dict[str, object]:
        """Withhold a managed structured destination when native proof is absent.

        This is an adapter-only overlay. It does not change the native result,
        receipt, or native availability floor. An intentionally unconfigured
        structured destination keeps the existing availability response.
        """

        if not withholds_structured_destination(harness=harness, event_name=event_name):
            return response
        # The edge never answered, so nothing resolved the policy. Read it
        # again: one activated while the edge was tried must still apply.
        resolved = read_structured_view(lambda: self._load_config(guard_home, workspace))
        if not structured_destination_required(resolved, harness=harness):
            return response
        return withhold_structured_destination(response)

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
        policy_snapshot: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        return review_native_edge(
            self,
            payload=payload,
            harness=harness,
            event_name=event_name,
            default_harness=default_harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
            claim_saved_approval=claim_saved_approval,
            claimed_saved_allow_hash=claimed_saved_allow_hash,
            claimed_approval_request_id=claimed_approval_request_id,
            policy_snapshot=policy_snapshot,
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
        from ..runtime_transition_hook_probe import transition_hook_probe

        probe = transition_hook_probe(payload)
        # Worker threads are reused, so clear any failure code left by an
        # earlier request before this review can report its own.
        record_native_resident_client_failure_code(None)
        # The edge mediates a managed structured destination itself, from the
        # managed policy only this daemon reads. It is read once, ahead of the
        # call, and does not depend on the native decision.
        structured_view = (
            read_structured_view(lambda: self._load_config(guard_home, workspace))
            if withholds_structured_destination(harness=harness, event_name=event_name)
            else None
        )
        for retried in (False, True):
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
                **({"request_id": probe[1]} if probe is not None else {}),
                local_cli_rules=True,
                observe_local_cli=True,
                record_receipt=callable(getattr(self.activity_writer, "submit_native_decision_receipt", None)),
                # The edge rewrites a call it routes to the contained sink in
                # the same answer.
                containment_sink=True,
                **({"structured_output_config": structured_view} if structured_view is not None else {}),
            )
            refreshed = (
                None
                if edge is not None or retried
                else superseded_post_tool_snapshot(
                    self, policy_snapshot, event_name, workspace=workspace, deadline=deadline
                )
            )
            if refreshed is None:
                break
            # The tool already ran; review its result once under the binding
            # that replaced ours instead of answering PostToolUse fail-safe.
            policy_snapshot = refreshed
            recording_only = recording_only_for_binding(refreshed, harness)
            record_native_resident_client_failure_code(None)
        if edge is None:
            failure = native_resident_client_failure_code()
            if failure in POLICY_SOURCE_FENCE_ERRORS and event_name in {"PreToolUse", "UserPromptSubmit"}:
                raise PolicySourceFenceBusyError(failure, recording_only=recording_only)
            if (
                isinstance(failure, str)
                and event_name in {"PreToolUse", "UserPromptSubmit"}
                and policy_snapshot is not None
                and (
                    failure == SNAPSHOT_NOT_CURRENT_ERROR
                    or (failure in CONTROL_BINDING_REFRESH_ERRORS and policy_snapshot.get("mode") == "enforce")
                )
            ):
                raise NativePolicyBindingRefreshError(
                    failure, policy_snapshot.get("generation"), recording_only=recording_only
                )
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
                self._apply_structured_unavailable_overlay(
                    _record_unavailable_native(
                        self,
                        payload,
                        harness=harness,
                        event_name=event_name,
                        reason_code=reason_code,
                        guard_home=guard_home,
                    ),
                    harness=harness,
                    event_name=event_name,
                    guard_home=guard_home,
                    workspace=workspace,
                ),
                False,
            )
        native_event = str(edge["event_name"])
        native_harness = str(edge["harness"])
        # The edge's decoder admits only a mapping result.
        native_result = cast("Mapping[str, object]", edge["result"])
        raw_receipt = edge.get("receipt")
        accepted_receipt = self._record_native_decision_receipt(raw_receipt)
        submit = getattr(self.activity_writer, "submit_native_decision_receipt", None)
        if accepted_receipt is not None and callable(submit) and edge.get("receipt_recorded") is not True:
            # Ordered in front of this hook's activity row, which links to the
            # receipt by its decision id. An edge that queued it says so.
            run_hook_evidence(self, lambda receipt=accepted_receipt: submit(receipt=receipt))
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
                        guard_home=guard_home,
                    ),
                    False,
                )
            # The edge already carries Guard's Claude Code notice outside Watch.
            return (_edge_harness_response(edge), True)
        if native_event == "PreToolUse":
            if recording_only:
                action = str(native_result.get("minimum_action") or "")
                if action != "allow" or native_result.get("decision") != "allow":
                    return (
                        _record_native_pre_activity(
                            self, native_harness, payload, _edge_harness_response(edge), accepted_receipt
                        ),
                        True,
                    )
            # The resident stamped its route on the edge answer, and the decoder
            # refuses an unstamped one; Python never picks a route.
            containment = edge.get("containment_route", "none")
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
                    deadline=deadline,
                    claim_saved_approval=claim_saved_approval,
                    claimed_saved_allow_hash=claimed_saved_allow_hash,
                    claimed_approval_request_id=claimed_approval_request_id,
                    local_cli_rule=cast("Mapping[str, object] | None", edge.get("local_cli_rule")),
                    exact_command_block=edge.get("exact_command_block"),
                    review_evidence=cast("Mapping[str, object] | None", edge.get("review_evidence")),
                )
                return (_record_native_pre_activity(self, native_harness, payload, response, accepted_receipt), True)
            # The edge settled the custom extension rules; a block it found
            # answers an allowed call (in Watch, as a recorded continue).
            custom_block = edge.get("local_cli_rule")
            if isinstance(custom_block, dict) and custom_block["blocked"] is True:
                return (
                    _record_native_pre_activity(
                        self,
                        native_harness,
                        payload,
                        dict(cast("Mapping[str, object]", custom_block["harness_response"])),
                        accepted_receipt,
                    ),
                    True,
                )
            # A saved or Guard Cloud block on this exact command outranks the
            # edge's allow; Watch records the call and lets it run.
            if not recording_only:
                command_block = native_exact_command_block_response(
                    self.store,
                    harness=native_harness,
                    command=pre_tool_command(payload),
                    native_result=native_result,
                    workspace=workspace,
                    edge_hint=edge.get("exact_command_block"),
                )
                if command_block is not None:
                    return (
                        _record_native_pre_activity(self, native_harness, payload, command_block, accepted_receipt),
                        True,
                    )
            rendered = _edge_harness_response(edge)
            # The edge rewrites a sink route in a workspace itself and says so;
            # an edge that could not is the outage response. Its routed allow
            # is held to the shape the sink's rewrite gives. Without a
            # workspace there is no snapshot to write, so the receipt stands.
            rewrite = edge.get("containment_rewrite") if containment == "sink" else None
            if rewrite == "routed" and not edge_routed_shape(rendered, payload):
                error = NativeHookDecisionError(_EDGE_REWRITE_INVALID)
                return _containment_outage(self, payload, native_harness, error, guard_home, deadline)
            if containment == "sink" and workspace is not None and rewrite not in _EDGE_CONTAINMENT_REWRITES:
                error = NativeHookDecisionError(_EDGE_REWRITE_UNAVAILABLE)
                return _containment_outage(self, payload, native_harness, error, guard_home, deadline)
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
        self._record_post_tool_activity(
            harness=native_harness,
            payload=payload,
            succeeded=hook_post_succeeded(native_event, payload),
        )
        response = _edge_harness_response(edge)
        if structured_view is not None:
            edge_result = edge.get("result")
            response = withhold_stale_forward(
                response,
                view=structured_view,
                load_config=lambda: self._load_config(guard_home, workspace),
                deadline=deadline,
                allowed=isinstance(edge_result, dict) and edge_result.get("decision") == "allow",
            )
        return (response, True)

    def _record_native_decision_receipt(self: _HookWorkerNativeHost, receipt: object) -> Mapping[str, object] | None:
        """Hold the edge's receipt for this hook; the edge checked it before answering."""

        self._last_native_decision_receipt = None
        if not isinstance(receipt, dict):
            return None
        accepted: dict[str, object] = receipt
        self._last_native_decision_receipt = accepted
        return accepted
