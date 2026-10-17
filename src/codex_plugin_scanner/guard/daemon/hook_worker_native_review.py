"""Bounded native review across acknowledged control-authority transitions."""

from __future__ import annotations

import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..native_policy_snapshot_harness_postures import recording_only_for_binding
from ..native_resident_client import native_resident_client_failure_code
from .hook_native_review_fence import native_review_fence
from .hook_policy_fence_window import (
    POLICY_UPDATE_PENDING_REASON_CODE,
    PolicySourceFenceBusyError,
    PolicySourceFenceWait,
    policy_update_pending_reason,
)

if TYPE_CHECKING:
    from .hook_worker_native import _HookWorkerNativeHost

CONTROL_BINDING_REFRESH_ERRORS = frozenset(
    {"native_command_control_mutation_in_progress", "native_command_control_authority_not_current"}
)
# The resident holds one current snapshot per Guard home. A short-lived CLI
# hook or another publisher can supersede the generation this worker last
# saw ACKed, so the worker refreshes its own binding and retries once.
SNAPSHOT_NOT_CURRENT_ERROR = "native_policy_snapshot_not_current"
NATIVE_REVIEW_REFRESH_ERRORS = CONTROL_BINDING_REFRESH_ERRORS | {SNAPSHOT_NOT_CURRENT_ERROR}


class NativePolicyBindingRefreshError(RuntimeError):
    def __init__(self, code: str, generation: object = None, *, recording_only: bool = False) -> None:
        if code not in NATIVE_REVIEW_REFRESH_ERRORS:
            raise ValueError("unsupported native binding refresh")
        super().__init__(code)
        self.code = code
        self.generation = generation if isinstance(generation, int) and not isinstance(generation, bool) else None
        # Posture of the rejected ACKed binding, so a refresh that cannot
        # complete keeps a Watch binding recording instead of stopping.
        self.recording_only = recording_only is True


def superseded_post_tool_snapshot(
    worker: _HookWorkerNativeHost,
    policy_snapshot: Mapping[str, object] | None,
    event_name: str,
    *,
    workspace: Path | None,
    deadline: float | None,
) -> Mapping[str, object] | None:
    """Return a fresh ACKed binding after another publisher superseded this one.

    A contained test run or other short-lived CLI hook publishes its own
    snapshot while the tool runs, so the PostToolUse that follows can find the
    worker's binding no longer current. Refresh once within the original
    deadline; any other failure, including a refresh that cannot complete,
    keeps the existing unavailable answer.
    """
    if (
        event_name != "PostToolUse"
        or policy_snapshot is None
        or deadline is None
        or time.monotonic() >= deadline
        or native_resident_client_failure_code() != SNAPSHOT_NOT_CURRENT_ERROR
        or getattr(worker, "_publish_native_policy", False) is not True
    ):
        return None
    publisher = getattr(worker, "policy_snapshot_publisher", None)
    request_refresh = getattr(publisher, "request_control_binding_refresh", None)
    if not callable(request_refresh):
        return None
    generation = policy_snapshot.get("generation")
    try:
        request_refresh(generation if isinstance(generation, int) and not isinstance(generation, bool) else None)
        refreshed = worker._native_policy_snapshot(workspace, deadline=deadline)
    except (OSError, TimeoutError, NativePolicySnapshotError):
        return None
    return refreshed if refreshed is not None and time.monotonic() < deadline else None


def review_native_edge(
    worker: _HookWorkerNativeHost,
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
    """Retry one rejected admission after fresh ACK, within the original deadline."""
    from .hook_worker_native import _record_unavailable_native

    snapshot = policy_snapshot
    refreshed_once = False
    fence_wait = PolicySourceFenceWait(deadline, store=getattr(worker, "store", None))
    try:
        while True:
            try:
                return _review_native_edge_once(
                    worker,
                    payload=payload,
                    harness=harness,
                    event_name=event_name,
                    default_harness=default_harness,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    workspace=workspace,
                    # A poll after a fence wait stops short of the hook deadline.
                    deadline=fence_wait.attempt_deadline,
                    claim_saved_approval=claim_saved_approval,
                    claimed_saved_allow_hash=claimed_saved_allow_hash,
                    claimed_approval_request_id=claimed_approval_request_id,
                    policy_snapshot=snapshot,
                )
            except PolicySourceFenceBusyError as busy:
                # The fence refused admission before any evaluation, so the same
                # request is retried as-is once it clears, within the deadline.
                if fence_wait.pause():
                    continue
                response = _record_unavailable_native(
                    worker,
                    payload,
                    harness=harness,
                    event_name=event_name,
                    reason_code=POLICY_UPDATE_PENDING_REASON_CODE,
                    workspace=workspace,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    recording_only=busy.recording_only,
                    reason=policy_update_pending_reason(),
                )
                response["native_failure_code"] = busy.code
                return response
            except NativePolicyBindingRefreshError as error:
                # The native engine rejected admission; no tool or approval result
                # was accepted. Release the mutation lease before waiting for the
                # publisher. Never reset the caller deadline or retry a deny verdict.
                can_refresh = (
                    not refreshed_once
                    and deadline is not None
                    and time.monotonic() < deadline
                    and event_name in {"UserPromptSubmit", "PreToolUse"}
                    and getattr(worker, "_publish_native_policy", False) is True
                )
                if can_refresh and deadline is not None:
                    publisher = getattr(worker, "policy_snapshot_publisher", None)
                    request_refresh = getattr(publisher, "request_control_binding_refresh", None)
                    if callable(request_refresh):
                        request_refresh(error.generation)
                        snapshot = worker._native_policy_snapshot(workspace, deadline=deadline)
                        refreshed = snapshot is not None and (
                            error.code == SNAPSHOT_NOT_CURRENT_ERROR or snapshot.get("mode") == "enforce"
                        )
                        if refreshed and time.monotonic() < deadline:
                            refreshed_once = True
                            continue
                response = _record_unavailable_native(
                    worker,
                    payload,
                    harness=harness,
                    event_name=event_name,
                    reason_code="native_control_binding_unavailable",
                    workspace=workspace,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    # Control-binding failures only refresh enforce bindings and
                    # stay blocking; a superseded Watch snapshot keeps recording.
                    recording_only=False,
                    watch_continue=error.code == SNAPSHOT_NOT_CURRENT_ERROR and error.recording_only,
                    deadline=deadline,
                )
                response["native_failure_code"] = error.code
                return response

    finally:
        # Close this hook's share of a fence window it waited through.
        fence_wait.finish()


def _review_native_edge_once(
    worker: _HookWorkerNativeHost,
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
    from .hook_worker_native import _record_unavailable_native

    # Only the publisher's acknowledged binding is used here. HTTP payload
    # fields never establish snapshot authority. Rust still checks the
    # resident generation, digest and all installed floors.
    if policy_snapshot is None:
        policy_snapshot = worker._native_policy_snapshot(workspace, deadline=deadline)
    # Native evaluation and Python delivery use the same acknowledged
    # posture. A local Watch edit cannot weaken an enforcing snapshot
    # before its replacement is accepted. A missing binding takes the
    # unavailable route and cannot establish recording-only authority.
    recording_only = recording_only_for_binding(policy_snapshot, harness)
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
            response, native_used = worker._review_native_edge_with_snapshot(
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
        if capture_receipts and worker.capture_writer is not None:
            with suppress(Exception):
                _ = worker.capture_writer.submit_native_capture(
                    guard_home=guard_home, payload=payload, receipt=capture_receipts[0]
                )
        if native_used:
            worker.metrics.record_route("native_resident")
        return response
    except TimeoutError:
        return worker._apply_structured_unavailable_overlay(
            _record_unavailable_native(
                worker,
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
        return worker._apply_structured_unavailable_overlay(
            _record_unavailable_native(
                worker,
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
