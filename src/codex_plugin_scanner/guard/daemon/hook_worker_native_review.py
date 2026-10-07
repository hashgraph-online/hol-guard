"""Bounded native review across acknowledged control-authority transitions."""

from __future__ import annotations

import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_policy_snapshot_constants import NativePolicySnapshotError
from .hook_native_review_fence import native_review_fence

if TYPE_CHECKING:
    from .hook_worker_native import _HookWorkerNativeHost

CONTROL_BINDING_REFRESH_ERRORS = frozenset(
    {"native_command_control_mutation_in_progress", "native_command_control_authority_not_current"}
)


class NativePolicyBindingRefreshError(RuntimeError):
    def __init__(self, code: str, generation: object = None) -> None:
        if code not in CONTROL_BINDING_REFRESH_ERRORS:
            raise ValueError("unsupported native binding refresh")
        super().__init__(code)
        self.code = code
        self.generation = generation if isinstance(generation, int) and not isinstance(generation, bool) else None


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
    for attempt in range(2):
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
                deadline=deadline,
                claim_saved_approval=claim_saved_approval,
                claimed_saved_allow_hash=claimed_saved_allow_hash,
                claimed_approval_request_id=claimed_approval_request_id,
                policy_snapshot=snapshot,
            )
        except NativePolicyBindingRefreshError as error:
            # The native engine rejected admission; no tool or approval result
            # was accepted. Release the mutation lease before waiting for the
            # publisher. Never reset the caller deadline or retry a deny verdict.
            can_refresh = (
                attempt == 0
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
                    if snapshot is not None and snapshot.get("mode") == "enforce" and time.monotonic() < deadline:
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
                recording_only=False,
            )
            response["native_failure_code"] = error.code
            return response
    raise AssertionError("bounded native review exhausted without a result")


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
