"""Native hook review helpers shared by the daemon hook worker."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from ..native_codex_binding_capture import CodexBindingCaptureWriter
from ..native_hook_decision import NativeHookDecisionError
from ..native_hook_direct_route import native_or_daemon_edge
from ..native_hook_render import native_exact_command_block_response, native_recording_only_for_binding
from ..native_payload_facts import native_hook_facts
from ..native_policy_fence_window import POLICY_SOURCE_FENCE_ERROR, PolicySourceFenceBusyError
from ..native_resident_client import (
    native_resident_client_failure_code,
    record_native_resident_client_failure_code,
)
from ..native_runtime import NativeRuntimeStatus
from ..resident_evidence_dispatch import run_resident_evidence
from .hook_native_review_approval import (
    pause_native_pre_tool_for_approval,
)
from .hook_worker_native_evidence import _record_native_pre_activity, _record_unavailable_native
from .hook_worker_native_review import (
    CONTROL_BINDING_REFRESH_ERRORS,
    SNAPSHOT_NOT_CURRENT_ERROR,
    NativePolicyBindingRefreshError,
    review_native_edge,
    superseded_post_tool_snapshot,
)
from .hook_worker_unavailable import structured_outage_overlay


def _edge_harness_response(edge: Mapping[str, object]) -> dict[str, object]:
    """The harness response Rust rendered for the edge decision."""

    rendered = edge["harness_response"]
    if not isinstance(rendered, dict):
        raise ValueError("native_hook_edge_invalid_response")
    response = {str(key): value for key, value in rendered.items()}
    transition = edge.get("transition_hook_observation")
    if isinstance(transition, Mapping):
        observation = transition.get("observation")
        if isinstance(observation, Mapping):
            response["guard_transition_observation"] = dict(observation)
    return response


# `containment_rewrite` answers the edge gives once it rewrote a sink route.
_EDGE_CONTAINMENT_REWRITES = frozenset({"routed", "kept"})
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
    _hook_event_name: Callable[..., str | None]
    _review_raw_hook_native: Callable[..., dict[str, object] | None]
    _review_native_edge_with_snapshot: Callable[..., tuple[dict[str, object], bool]]
    _record_post_tool_activity: Callable[..., None]
    _record_native_decision_receipt: Callable[[object], Mapping[str, object] | None]
    _apply_structured_unavailable_overlay: Callable[..., dict[str, object]]

    def _load_config(self, guard_home: Path, workspace: Path | None) -> GuardConfig: ...


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
        deadline: float | None = None,
    ) -> dict[str, object]:
        """Withhold a managed structured destination when native proof is absent.

        This is an adapter-only overlay. It does not change the native result,
        receipt, or native availability floor. An intentionally unconfigured
        structured destination keeps the existing availability response.
        """

        overlay = structured_outage_overlay(
            harness=harness,
            event_name=event_name,
            guard_home=guard_home,
            deadline=deadline,
        )
        return {**response, **overlay} if overlay else response

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
        defer_accepted_recording: bool = False,
        deferred_receipts: list[Mapping[str, object]] | None = None,
    ) -> tuple[dict[str, object], bool]:
        # Worker threads are reused, so clear any failure code left by an
        # earlier request before this review can report its own.
        record_native_resident_client_failure_code(None)
        for retried in (False, True):
            edge, direct_answer = native_or_daemon_edge(
                self,
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
                defer_accepted_recording=defer_accepted_recording,
                claim_saved_approval=claim_saved_approval,
            )
            if direct_answer:
                if edge is None:
                    break
                receipt = self._record_native_decision_receipt(edge.get("receipt"))
                if receipt is not None and defer_accepted_recording and deferred_receipts is not None:
                    deferred_receipts.append(receipt)
                if receipt is not None and capture_receipts is not None and edge.get("harness") == "codex":
                    capture_receipts.append(receipt)
                return _edge_harness_response(edge), True
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
            recording_only = native_recording_only_for_binding(
                refreshed, harness, guard_home=guard_home, deadline=deadline
            )
            record_native_resident_client_failure_code(None)
        if edge is None:
            failure = native_resident_client_failure_code()
            if failure == POLICY_SOURCE_FENCE_ERROR and event_name in {"PreToolUse", "UserPromptSubmit"}:
                raise PolicySourceFenceBusyError(failure)
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
                    event=event_name,
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
                    deadline=deadline,
                ),
                False,
            )
        native_event = str(edge["event_name"])
        native_harness = str(edge["harness"])
        # The edge's decoder admits only a mapping result.
        native_result = cast("Mapping[str, object]", edge["result"])
        raw_receipt = edge.get("receipt")
        accepted_receipt = self._record_native_decision_receipt(raw_receipt)
        if accepted_receipt is not None and defer_accepted_recording and deferred_receipts is not None:
            deferred_receipts.append(accepted_receipt)
        submit = getattr(self.activity_writer, "submit_native_decision_receipt", None)
        if (
            accepted_receipt is not None
            and not defer_accepted_recording
            and callable(submit)
            and edge.get("receipt_recorded") is not True
        ):
            # Ordered in front of this hook's activity row, which links to the
            # receipt by its decision id. An edge that queued it says so.
            run_resident_evidence(self, lambda receipt=accepted_receipt: submit(receipt=receipt))
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
            # The edge queues the activity only for an answer returned as it
            # rendered it: recorded only, a custom block, or the final one.
            recorded = edge.get("activity_recorded") is True
            if edge.get("recording_only_response") is True:
                return (
                    _edge_harness_response(edge)
                    if defer_accepted_recording
                    else _record_native_pre_activity(
                        self,
                        native_harness,
                        payload,
                        _edge_harness_response(edge),
                        accepted_receipt,
                        recorded=recorded,
                    ),
                    True,
                )
            # The resident stamped its route on the edge answer, and the decoder
            # refuses an unstamped one; Python never picks a route.
            containment = edge.get("containment_route", "none")
            if edge.get("requires_approval") is True:
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
                if defer_accepted_recording:
                    return response, True
                return (_record_native_pre_activity(self, native_harness, payload, response, accepted_receipt), True)
            # The edge settled the custom extension rules; a block it found
            # answers an allowed call (in Watch, as a recorded continue).
            custom_block = edge.get("local_cli_rule")
            if edge.get("local_cli_rule_blocked") is True:
                if not isinstance(custom_block, dict):
                    return _containment_outage(
                        self,
                        payload,
                        native_harness,
                        NativeHookDecisionError("native_hook_edge_invalid_response"),
                        guard_home,
                        deadline,
                    )
                return (
                    (
                        dict(cast("Mapping[str, object]", custom_block["harness_response"]))
                        if defer_accepted_recording
                        else _record_native_pre_activity(
                            self,
                            native_harness,
                            payload,
                            dict(cast("Mapping[str, object]", custom_block["harness_response"])),
                            accepted_receipt,
                            recorded=recorded,
                        )
                    ),
                    True,
                )
            # A saved or Guard Cloud block on this exact command outranks the
            # edge's allow; Watch records the call and lets it run.
            if not recording_only:
                edge_hint = edge.get("exact_command_block")
                facts = native_hook_facts(payload, guard_home, deadline=deadline) if edge_hint is not False else None
                if facts is None and edge_hint is not False:
                    return (
                        _record_unavailable_native(
                            self,
                            payload,
                            harness=native_harness,
                            event_name="PreToolUse",
                            reason_code="native_payload_facts_unavailable",
                            reason="HOL Guard could not identify this command safely.",
                            guard_home=guard_home,
                            deadline=deadline,
                        ),
                        False,
                    )
                if edge_hint is True and (facts is None or facts.command is None):
                    return (
                        _record_unavailable_native(
                            self,
                            payload,
                            harness=native_harness,
                            event_name="PreToolUse",
                            reason_code="native_command_facts_unavailable",
                            reason="HOL Guard could not identify this command safely.",
                            guard_home=guard_home,
                            deadline=deadline,
                        ),
                        False,
                    )
                command_block = native_exact_command_block_response(
                    self.store,
                    harness=native_harness,
                    command=facts.command if facts is not None else None,
                    native_result=native_result,
                    workspace=workspace,
                    edge_hint=edge_hint,
                    deadline=deadline,
                )
                if command_block is not None:
                    return (
                        command_block
                        if defer_accepted_recording
                        else _record_native_pre_activity(
                            self, native_harness, payload, command_block, accepted_receipt
                        ),
                        True,
                    )
            rendered = _edge_harness_response(edge)
            # The edge rewrites a sink route in a workspace itself and says so;
            # the Rust edge proves the routed allow's shape, while Python only
            # transports it. Without a workspace there is no snapshot to write,
            # so the receipt stands.
            rewrite = edge.get("containment_rewrite") if containment == "sink" else None
            if containment == "sink" and workspace is not None and rewrite not in _EDGE_CONTAINMENT_REWRITES:
                error = NativeHookDecisionError(_EDGE_REWRITE_UNAVAILABLE)
                return _containment_outage(self, payload, native_harness, error, guard_home, deadline)
            return (
                rendered
                if defer_accepted_recording
                else _record_native_pre_activity(
                    self, native_harness, payload, rendered, accepted_receipt, recorded=recorded
                ),
                True,
            )
        if edge.get("activity_recorded") is not True:
            self._record_post_tool_activity(
                harness=native_harness,
                payload=payload,
                event=native_event,
            )
        return (_edge_harness_response(edge), True)

    def _record_native_decision_receipt(self: _HookWorkerNativeHost, receipt: object) -> Mapping[str, object] | None:
        """Hold the edge's receipt for this hook; the edge checked it before answering."""

        self._last_native_decision_receipt = None
        if not isinstance(receipt, dict):
            return None
        accepted: dict[str, object] = receipt
        self._last_native_decision_receipt = accepted
        return accepted
