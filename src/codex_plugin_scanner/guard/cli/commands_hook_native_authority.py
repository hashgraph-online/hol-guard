"""Route auto/force PreToolUse and PostToolUse through the native worker."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon.hook_worker import HookWorker, HookWorkerUnsupported
from ..native_route_receipt import record_python_semantic_hook_route
from ..native_runtime import native_mode
from ..store import GuardStore
from .commands_hook_source_ref import _try_source_ref_fast_path
from .commands_support_interaction import _emit


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

    ``auto`` and ``force`` send supported command PreToolUse and PostToolUse
    through the same fail-closed Rust worker as the daemon. File PreToolUse
    and other events still raise ``HookWorkerUnsupported`` so the existing
    CLI path can handle them.
    """
    if native_mode() not in {"auto", "force"}:
        return None
    try:
        return HookWorker(store=store).review_http_payload(
            payload=payload,
            params={},
            default_harness=harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )
    except HookWorkerUnsupported:
        return None


def try_native_or_source_ref_hook(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int | None:
    """Prefer native authority, then Python source-ref when native does not apply.

    ``off`` and ``shadow`` stay on the Python source-ref path. ``auto`` and
    ``force`` use that path only after the native worker reports the event as
    unsupported, such as file PreToolUse with a source reference.
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
