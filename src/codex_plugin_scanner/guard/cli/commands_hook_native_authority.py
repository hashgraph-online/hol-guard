"""Route default production hooks through the native Rust authority."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..daemon.hook_worker import HookWorker
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
    """Return Rust authority for auto/force, or None for explicit compatibility."""

    if native_mode() not in {"auto", "force"}:
        return None
    return HookWorker(store=store).review_http_payload(
        payload=payload,
        params={},
        default_harness=harness,
        home_dir=home_dir,
        guard_home=guard_home,
        workspace=workspace,
    )


def try_native_or_source_ref_hook(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int | None:
    """Use Rust in auto/force; retain Python reference only for off/shadow.

    A native failure in auto/force is returned as a deterministic fail-closed
    response by ``HookWorker`` and cannot reach the Python source-ref evaluator.
    The source-ref helper remains reachable only when the operator explicitly
    selected ``off`` or ``shadow`` compatibility.
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
    return _try_source_ref_fast_path(
        args,
        config=config,
        context=context,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
    )
