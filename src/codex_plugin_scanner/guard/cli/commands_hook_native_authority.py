"""Route auto/force PreToolUse and PostToolUse through the native worker."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon.hook_worker import HookWorker, HookWorkerUnsupported
from ..daemon.hook_worker_responses import post_tool_fail_safe_response
from ..native_route_receipt import record_python_semantic_hook_route
from ..native_runtime import native_mode
from ..store import GuardStore
from .commands_hook_source_ref import _try_source_ref_fast_path
from .commands_support_interaction import _emit


def _native_mode_requires_rust() -> bool:
    return native_mode() in {"auto", "force"}


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
    try:
        worker = HookWorker(store=store)
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
        return post_tool_fail_safe_response(
            harness,
            reason="HOL Guard could not complete the native hook decision safely.",
            reason_code="native_hook_worker_exception",
        )
    finally:
        if worker is not None:
            close = getattr(worker, "close", None)
            if callable(close):
                close()


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
    """Prefer native authority, then Python source-ref when native does not apply.

    ``off`` and ``shadow`` stay on the Python source-ref path. ``auto`` and
    ``force`` keep every hook result native or fail-safe. Callers that have
    not yet performed compatibility normalization set ``allow_compatibility``
    to false so no native request can escape into a Python source-ref path.
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
        reason_code = (
            "native_hook_worker_unavailable"
            if allow_compatibility
            else "native_hook_worker_unavailable_before_compatibility"
        )
        _emit(
            "hook",
            post_tool_fail_safe_response(
                args.harness,
                reason="HOL Guard could not complete the native hook decision safely.",
                reason_code=reason_code,
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
