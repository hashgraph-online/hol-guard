"""Route auto/force PreToolUse and PostToolUse through the native worker."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Callable
from contextlib import suppress
from functools import wraps
from pathlib import Path
from typing import Any, TextIO

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon.diagnostics import DaemonDiagnostics
from ..daemon.hook_availability_policy import availability_harness_response
from ..daemon.hook_request_parsing import runtime_hook_event_name
from ..daemon.hook_worker import HookWorker
from ..native_hook_adapter import hook_adapter_memo
from ..native_hook_evidence_writer import NativeHookEvidenceWriter
from ..store import GuardStore
from .commands_hook_native_availability import _native_unavailable_exit_code
from .commands_support_interaction import _emit

_DIAGNOSTIC_DRAIN_TIMEOUT_SECONDS = 0.25


def _record_native_hook_exception(guard_home: Path, *, harness: str, event_name: str) -> None:
    """Write the swallowed hook exception to Guard's own log.

    The fail-closed response deliberately carries no detail: it travels the
    harness wire and would leak local paths. Without this the operator sees a
    deny with no stderr, no reason beyond the generic message, and nothing in
    any log to explain it. Diagnostics never change the returned verdict, so
    every failure here is suppressed. Call this from inside the ``except``
    block, where ``sys.exc_info()`` still holds the exception.
    """

    with suppress(Exception):
        diagnostics = DaemonDiagnostics(guard_home, start_worker=False, rotate=False)
        try:
            diagnostics.record_exception(
                "native_hook_worker_exception",
                detail=f"harness={harness} event={event_name}",
            )
        finally:
            diagnostics.close(timeout_seconds=_DIAGNOSTIC_DRAIN_TIMEOUT_SECONDS)


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
    worker: HookWorker | None = None
    try:
        # Short-lived CLI hooks publish and await the resident-ACKed policy
        # snapshot themselves; with no Python fallback, a missing snapshot must
        # not silently downgrade a hook to a fail-safe allow.
        worker = HookWorker(
            store=store,
            activity_writer=NativeHookEvidenceWriter(store=store),
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
    except Exception as error:
        _record_native_hook_exception(
            guard_home,
            harness=harness,
            event_name=runtime_hook_event_name(payload),
        )
        _log_worker_exception(error, harness=harness)
        return availability_harness_response(
            harness=harness,
            event_name=runtime_hook_event_name(payload),
            reason_code="native_hook_worker_exception",
            reason="HOL Guard could not complete the native hook decision safely.",
        )
    finally:
        if worker is not None:
            close = getattr(worker, "close", None)
            if callable(close):
                close()
        # The writer belongs to the resident, not to this process, so a
        # one-shot hook never stops it: the records it handed over are
        # persisted after this process exits, and stopping the writer here
        # would drain and drop one the next hook would have to rebuild.


def _log_worker_exception(error: BaseException, *, harness: str) -> None:
    """Point the operator at the Guard log before denying.

    The harness wire document is a fixed deny that deliberately carries no
    detail. The full exception and traceback go to Guard's own log through
    ``_record_native_hook_exception``; this line only names the failure class
    so the operator knows where to look. Hook stderr can reach the harness, so
    no exception message, traceback, path or payload-derived value is logged
    here, and a failing log handler never changes the returned verdict.
    """

    with suppress(Exception):
        logging.getLogger(__name__).warning(
            "HOL Guard native hook authority failed for %s (%s); details are in the Guard daemon log",
            harness,
            type(error).__name__,
        )


def _one_adapter_scope(route: Callable[..., int]) -> Callable[..., int]:
    """Answer each repeated adapter query once per hook invocation (one resident round trip)."""

    @wraps(route)
    def scoped(*args: object, **kwargs: Any) -> int:
        store = kwargs.get("store")
        context = kwargs.get("context")
        home = getattr(store, "guard_home", None) or getattr(context, "guard_home", None)
        with hook_adapter_memo(home):
            return route(*args, **kwargs)

    return scoped


@_one_adapter_scope
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

    Every hook result is native or fail-safe; there is no Python semantic
    fallback.
    The Rust edge owns the decision floor; the pipeline composes mechanical
    presentation, approval queueing, and receipt persistence on top of it.
    """
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
                harness=args.harness,
                event_name=runtime_hook_event_name(payload),
                reason_code="native_hook_worker_unavailable",
                reason="HOL Guard could not complete the native hook decision safely.",
            )
        # Availability responses are already harness wire documents. A hook
        # caller need not pass --json to receive a parseable deny response.
        _emit("hook", native_result, True)
        # rc mirrors the emitted verdict through the harness's adapter contract
        # (per-harness deny code, recording-only allows keep 0).
        return _native_unavailable_exit_code(args, native_result, runtime_hook_event_name(payload))
    except Exception as error:
        _record_native_hook_exception(
            context.guard_home,
            harness=args.harness,
            event_name=runtime_hook_event_name(payload),
        )
        _log_worker_exception(error, harness=args.harness)
        response = availability_harness_response(
            harness=args.harness,
            event_name=runtime_hook_event_name(payload),
            reason_code="native_hook_worker_exception",
            reason="HOL Guard could not complete the native hook decision safely.",
        )
        _emit("hook", response, True)
        return _native_unavailable_exit_code(args, response, runtime_hook_event_name(payload))
