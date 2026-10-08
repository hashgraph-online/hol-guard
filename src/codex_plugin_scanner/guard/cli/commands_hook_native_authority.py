"""Route auto/force PreToolUse and PostToolUse through the native worker."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, TextIO

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon.hook_availability_policy import availability_harness_response
from ..daemon.hook_request_parsing import runtime_hook_event_name
from ..daemon.hook_worker import HookWorker
from ..daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from ..native_mode import native_mode_is_fail_safe_disabled
from ..native_mode import (
    native_mode_requires_rust as _native_mode_requires_rust,
)
from ..native_policy_snapshot_acked import recording_only_from_acked_snapshot
from ..store import GuardStore
from .commands_hook_native_availability import _native_unavailable_exit_code
from .commands_support_interaction import _emit

_NATIVE_RECEIPT_DRAIN_TIMEOUT_SECONDS = 0.25


def try_native_hook_authority(
    *,
    payload: dict[str, object],
    harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    store: GuardStore,
    pipeline: Callable[[HookWorker], int] | None = None,
) -> dict[str, Any] | int | None:
    """Run native authority, optionally composing it into the CLI pipeline.

    ``auto`` and ``force`` send supported generic PreToolUse and PostToolUse
    through the same fail-closed Rust worker as the daemon. Out-of-scope
    events still return ``None`` for their compatibility handlers.
    """
    if not _native_mode_requires_rust():
        return None
    worker: HookWorker | None = None
    evidence_writer: RuntimeHookEvidenceWriter | None = None
    try:
        # Short-lived CLI hooks publish and await the resident-ACKed policy
        # snapshot themselves; with no Python fallback, a missing snapshot must
        # not silently downgrade a hook to a fail-safe allow. Teardown drains
        # the writer independently of the native decision result.
        evidence_writer = RuntimeHookEvidenceWriter(store=store)
        worker = HookWorker(
            store=store,
            activity_writer=evidence_writer,
        )
        if pipeline is not None:
            return pipeline(worker)
        return worker.review_http_payload(
            payload=payload,
            params={},
            default_harness=harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )
    except Exception:
        return availability_harness_response(
            payload,
            harness=harness,
            event_name=runtime_hook_event_name(payload),
            reason_code="native_hook_worker_exception",
            reason="HOL Guard could not complete the native hook decision safely.",
            workspace=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            recording_only=recording_only_from_acked_snapshot(store),
        )
    finally:
        if worker is not None:
            close = getattr(worker, "close", None)
            if callable(close):
                close()
        if evidence_writer is not None:
            # A one-shot hook must not hold the harness response open for
            # control-plane persistence. Persistence is best effort; the
            # security result is already returned and never depends on it.
            _ = evidence_writer.stop(timeout_seconds=_NATIVE_RECEIPT_DRAIN_TIMEOUT_SECONDS)


def route_native_hook(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    output_stream: TextIO | None = None,
    _claim_saved_approval: bool = True,
    _claimed_saved_allow_hash: str | None = None,
    _claimed_trusted_request_override: bool = False,
    _claimed_approval_request_id: str | None = None,
) -> int:
    """Route a hook through native authority and emit its result.

    ``auto`` and ``force`` keep every hook result native or fail-safe. An
    explicit ``off`` is also fail-safe; there is no Python semantic fallback.
    The Rust edge owns the decision floor; the pipeline composes mechanical
    presentation, approval queueing, and receipt persistence on top of it.
    """
    if not _native_mode_requires_rust():
        # ``off`` is an explicit disablement, not permission to restore a
        # second semantic evaluator. Shadow never escapes to Python semantics.
        reason_code = (
            "native_hook_disabled" if native_mode_is_fail_safe_disabled() else "native_shadow_diagnostic_disabled"
        )
        if runtime_hook_event_name(payload) == "PreToolUse":
            writer: RuntimeHookEvidenceWriter | None = None
            # Evidence is bounded and best effort; denial never depends on it.
            with suppress(Exception):
                writer = RuntimeHookEvidenceWriter(store=store)
                writer.submit_command_activity(
                    harness=args.harness,
                    event="PreToolUse",
                    payload=payload,
                    succeeded=True,
                    policy_action="block",
                    receipt_id=None,
                    prompted=False,
                )
            if writer is not None:
                with suppress(Exception):
                    writer.stop(timeout_seconds=_NATIVE_RECEIPT_DRAIN_TIMEOUT_SECONDS)
        response = availability_harness_response(
            payload,
            harness=args.harness,
            event_name=runtime_hook_event_name(payload),
            reason="HOL Guard could not complete the native hook decision safely.",
            reason_code=reason_code,
            workspace=runtime_workspace,
            home_dir=context.home_dir,
            guard_home=context.guard_home,
        )
        _emit("hook", response, True)
        return _native_unavailable_exit_code(args, response, runtime_hook_event_name(payload))
    from .commands_hook_native_pipeline import run_native_hook_pipeline

    def run_pipeline(worker: HookWorker) -> int:
        return run_native_hook_pipeline(
            args,
            config=config,
            context=context,
            payload=payload,
            runtime_workspace=runtime_workspace,
            store=store,
            worker=worker,
            output_stream=output_stream,
            _claim_saved_approval=_claim_saved_approval,
            _claimed_saved_allow_hash=_claimed_saved_allow_hash,
            _claimed_trusted_request_override=_claimed_trusted_request_override,
            _claimed_approval_request_id=_claimed_approval_request_id,
        )

    try:
        native_result = try_native_hook_authority(
            payload=payload,
            harness=args.harness,
            home_dir=context.home_dir,
            guard_home=context.guard_home,
            workspace=runtime_workspace,
            store=store,
            pipeline=run_pipeline,
        )
        if isinstance(native_result, int):
            return native_result
        if native_result is None:
            native_result = availability_harness_response(
                payload,
                harness=args.harness,
                event_name=runtime_hook_event_name(payload),
                reason_code="native_hook_worker_unavailable",
                reason="HOL Guard could not complete the native hook decision safely.",
                workspace=runtime_workspace,
                home_dir=context.home_dir,
                guard_home=context.guard_home,
                recording_only=recording_only_from_acked_snapshot(store),
            )
        # Availability responses are already harness wire documents. A hook
        # caller need not pass --json to receive a parseable deny response.
        _emit("hook", native_result, True)
        # rc mirrors the emitted verdict through the harness's adapter contract
        # (per-harness deny code, recording-only allows keep 0).
        return _native_unavailable_exit_code(args, native_result, runtime_hook_event_name(payload))
    except Exception:
        response = availability_harness_response(
            payload,
            harness=args.harness,
            event_name=runtime_hook_event_name(payload),
            reason_code="native_hook_worker_exception",
            reason="HOL Guard could not complete the native hook decision safely.",
            workspace=runtime_workspace,
            home_dir=context.home_dir,
            guard_home=context.guard_home,
            recording_only=recording_only_from_acked_snapshot(store),
        )
        _emit("hook", response, True)
        return _native_unavailable_exit_code(args, response, runtime_hook_event_name(payload))
