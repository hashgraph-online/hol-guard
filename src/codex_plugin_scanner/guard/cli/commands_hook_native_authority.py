"""Route auto/force PreToolUse and PostToolUse through the native worker."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon.hook_availability_policy import availability_harness_response
from ..daemon.hook_request_parsing import runtime_hook_event_name
from ..daemon.hook_worker import HookWorker, HookWorkerUnsupported
from ..daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from ..native_mode import (
    native_mode_is_fail_safe_disabled,
    python_oracle_surface_enabled,
)
from ..native_mode import (
    native_mode_requires_rust as _native_mode_requires_rust,
)
from ..native_route_receipt import record_python_semantic_hook_route
from ..store import GuardStore
from .commands_hook_source_ref import _try_source_ref_fast_path
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
) -> dict[str, Any] | None:
    """Return native harness JSON, or None when Python CLI must continue.

    ``auto`` and ``force`` send supported generic PreToolUse and PostToolUse
    through the same fail-closed Rust worker as the daemon. Out-of-scope
    events still return ``None`` for their compatibility handlers.
    """
    if not _native_mode_requires_rust():
        return None
    worker: HookWorker | None = None
    evidence_writer: RuntimeHookEvidenceWriter | None = None
    try:
        # Short-lived CLI hooks use the same bounded, non-authoritative
        # handoff as the resident daemon. Teardown drains it independently of
        # the native decision result.
        evidence_writer = RuntimeHookEvidenceWriter(store=store)
        worker = HookWorker(store=store, activity_writer=evidence_writer)
        return worker.review_http_payload(
            payload=payload,
            params={},
            default_harness=harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )
    except HookWorkerUnsupported:
        return None
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


def try_native_or_source_ref_hook(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    allow_compatibility: bool = True,
) -> int | None:
    """Prefer native authority, then an explicitly injected test oracle.

    ``auto`` and ``force`` keep every hook result native or fail-safe. An
    explicit ``off`` is also fail-safe in production; only the differential
    test oracle can continue to the compatibility source-ref seam. Callers
    that have not yet performed compatibility normalization set
    ``allow_compatibility`` to false so no native request can escape into a
    Python source-ref path.
    """
    native_result = try_native_hook_authority(
        payload=payload,
        harness=args.harness,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        workspace=runtime_workspace,
        store=store,
    )
    if native_result is not None:
        _emit("hook", native_result, getattr(args, "json", False))
        return 0
    if _native_mode_requires_rust():
        # Native mode never escapes to Python semantics, including unknown or
        # malformed event labels. The worker normally returns this floor;
        # retain a deterministic terminal result for transport failure.
        _emit(
            "hook",
            availability_harness_response(
                payload,
                harness=args.harness,
                event_name=runtime_hook_event_name(payload),
                reason_code=(
                    "native_hook_worker_unavailable"
                    if allow_compatibility
                    else "native_hook_worker_unavailable_before_compatibility"
                ),
                reason="HOL Guard could not complete the native hook decision safely.",
                workspace=runtime_workspace,
                home_dir=context.home_dir,
                guard_home=context.guard_home,
            ),
            getattr(args, "json", False),
        )
        return 0
    if not python_oracle_surface_enabled():
        # ``off`` is an explicit disablement, not permission to restore a
        # second semantic evaluator. Shadow requires the same explicit test or
        # non-production diagnostic boundary before comparison is permitted.
        reason_code = (
            "native_hook_disabled" if native_mode_is_fail_safe_disabled() else "native_shadow_diagnostic_disabled"
        )
        _emit(
            "hook",
            availability_harness_response(
                payload,
                harness=args.harness,
                event_name=runtime_hook_event_name(payload),
                reason="HOL Guard could not complete the native hook decision safely.",
                reason_code=reason_code,
                workspace=runtime_workspace,
                home_dir=context.home_dir,
                guard_home=context.guard_home,
            ),
            getattr(args, "json", False),
        )
        return 0
    if not allow_compatibility:
        return None
    # Any path beyond native authority is a Python terminal semantic path.
    # Preserve that final provenance even when Python asks Rust for a floor.
    record_python_semantic_hook_route()
    return _try_source_ref_fast_path(
        args,
        config=config,
        context=context,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
    )
