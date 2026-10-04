"""Present native availability failures to the managed harness."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..adapters.base import HarnessContext
from ..daemon.hook_availability_policy import availability_harness_response
from .commands_support_interaction import _emit

if TYPE_CHECKING:
    from ..daemon.hook_worker import HookWorker


def _emit_native_unavailable(
    args: argparse.Namespace,
    *,
    payload: Mapping[str, object],
    workspace: Path | None,
    context: HarnessContext,
    event_name: str,
    reason_code: str,
    worker: HookWorker,
    recording_only: bool = False,
) -> int:
    response = availability_harness_response(
        dict(payload),
        harness=args.harness,
        event_name=event_name,
        reason_code=reason_code,
        reason="HOL Guard could not complete the native hook decision safely.",
        workspace=workspace,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        recording_only=recording_only,
    )
    # The native edge has already returned before this projection.  Keep the
    # native availability response and overlay only the managed model-visible
    # structured destination; this must not invent a native result, receipt,
    # or decision identifier.
    response = worker._apply_structured_unavailable_overlay(
        response,
        harness=args.harness,
        event_name=event_name,
        guard_home=context.guard_home,
        workspace=workspace,
    )
    _emit("hook", response, True)
    return 0
