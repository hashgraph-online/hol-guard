"""Failure-only code-identity observations for an installed hook request.

This module never reads frame locals, source paths, thread names or requests.
The sample is not proof that any observed phase caused the transport failure.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from types import CodeType, FrameType, FunctionType

from codex_plugin_scanner.guard.daemon.hook_native_review_approval import (
    pause_native_pre_tool_for_approval,
    queue_native_pre_tool_review,
)
from codex_plugin_scanner.guard.daemon.hook_native_review_fence import native_review_fence
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.daemon.hook_worker_responses import prepare_native_hook_policy
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_resident_client import (
    _PersistentNativeClientPool,
    native_resident_client_request,
)
from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient
from codex_plugin_scanner.guard.store_connection_schema import StoreConnectionSchemaMixin

_MAX_THREADS = 64
_MAX_FRAMES = 48
_CASES = frozenset(
    {
        "recovered-lockdown-enforce",
        "recovered-lockdown-observe",
        "recovered-managed-permission-enforce",
        "recovered-managed-permission-observe",
        "managed-permission-enforce",
        "managed-permission-observe",
        "intrinsic-enforce",
        "intrinsic-observe",
        "later-local-enable",
        "signed-enable-rejected",
        "managed-read-approval",
        "immutable-baseline-enforce",
        "immutable-baseline-observe",
        "immutable-enable-rejected-enforce",
        "immutable-enable-rejected-observe",
        "managed-after-immutable-rejection-enforce",
        "managed-after-immutable-rejection-observe",
        "managed-lockdown-enforce",
        "managed-lockdown-observe",
        "approved-read-lockdown-enforce",
        "approved-read-lockdown-observe",
        "external-off",
        "external-enabled",
        "owned-help",
        "safe-does-not-weaken-floor",
        "permission-disabled",
        "external-disabled",
        "external-reenabled",
        "restart-retains-controls",
        "command.package.go",
        "command.package.jvm",
        "command.package.node",
        "command.package.php",
        "command.package.python",
        "command.package.ruby",
        "command.package.rust",
        "command.package.system",
        "mcp-write-blocked",
        "mcp-read-inherits",
        "mcp-instapods-delete-review",
        "mcp-instapods-alias-exec-review",
        "mcp-instapods-inherit",
        "mcp-off",
    }
)


def _function_code(function: object) -> CodeType | None:
    return function.__code__ if type(function) is FunctionType else None


def _body_code(function: object) -> CodeType | None:
    if type(function) is not FunctionType:
        return None
    wrapped = vars(function).get("__wrapped__")
    return wrapped.__code__ if type(wrapped) is FunctionType else None


_PHASE_CODES: tuple[tuple[CodeType | None, str], ...] = (
    (_GuardDaemonHandler.do_POST.__code__, "request_input"),
    (_GuardDaemonHandler._handle_runtime_hook.__code__, "hook_admission"),
    (prepare_native_hook_policy.__code__, "policy_barrier"),
    (HookWorker.prepare_workspace_policy.__code__, "workspace_readiness"),
    (HookWorker.review_http_payload.__code__, "worker_dispatch"),
    (_function_code(vars(HookWorkerNativeMixin).get("_review_native_edge")), "native_review"),
    (_function_code(vars(HookWorkerNativeMixin).get("_review_native_edge_with_snapshot")), "native_evaluation"),
    (review_raw_hook_native.__code__, "raw_native_review"),
    (_body_code(native_review_fence), "command_lease"),
    (native_resident_client_request.__code__, "resident_transport"),
    (_PersistentNativeClient.request.__code__, "resident_transport"),
    (_PersistentNativeClientPool._lease.__code__, "transport_capacity"),
    (_body_code(StoreConnectionSchemaMixin._connect_once), "store_connection"),
    (pause_native_pre_tool_for_approval.__code__, "approval_reuse"),
    (queue_native_pre_tool_review.__code__, "approval_queue"),
    (NativePolicySnapshotPublisher._run.__code__, "publisher_loop"),
    (NativePolicySnapshotPublisher._publish_once.__code__, "publication"),
    (NativePolicySnapshotPublisher._publication_context.__code__, "publication_context"),
    (NativePolicySnapshotPublisher.current_snapshot_binding.__code__, "snapshot_binding"),
    (NativePolicySnapshotPublisher.result_binding_is_current.__code__, "result_currentness"),
)


def _stack_phase(frame: object) -> tuple[str, str]:
    """Return only a fixed phase for the innermost known code object."""
    try:
        for _ in range(_MAX_FRAMES):
            if frame is None:
                return "unknown", "complete"
            if type(frame) is not FrameType:
                return "unknown", "unavailable"
            for code, phase in _PHASE_CODES:
                if frame.f_code is code:
                    return phase, "matched"
            frame = frame.f_back
        return "unknown", "truncated" if frame is not None else "complete"
    finally:
        frame = None


def describe_active_phases() -> dict[str, object]:
    """Sample existing threads once without acquiring production locks."""
    frames: dict[int, FrameType] | None = None
    frame: FrameType | None = None
    try:
        frames = sys._current_frames()
        phases: Counter[str] = Counter()
        scans: Counter[str] = Counter()
        inspected = 0
        for frame in frames.values():
            if inspected >= _MAX_THREADS:
                break
            phase, scan = _stack_phase(frame)
            phases[phase] += 1
            scans[scan] += 1
            inspected += 1
        return {
            "available": True,
            "threads_sampled": inspected,
            "threads_truncated": len(frames) > inspected,
            "phases": dict(sorted(phases.items())),
            "scans": dict(sorted(scans.items())),
        }
    except BaseException:
        return {"available": False}
    finally:
        frame = None
        if frames is not None:
            frames.clear()


def _count(value: object) -> int | None:
    return min(999, max(0, value)) if type(value) is int else None


@contextmanager
def report_hook_transport_timeout(*, case: str, completed_cases: int, control_revision: int) -> Iterator[None]:
    """Re-raise the original timeout after a best-effort bounded observation."""
    try:
        yield
    except TimeoutError:
        with suppress(BaseException):
            print(
                json.dumps(
                    {
                        "schema": "guard.installed-hook-transport-failure.v1",
                        "failure": "timeout",
                        "case": case if type(case) is str and case in _CASES else "other",
                        "completed_cases": _count(completed_cases),
                        "control_revision": _count(control_revision),
                        "active_phases": describe_active_phases(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
        raise
