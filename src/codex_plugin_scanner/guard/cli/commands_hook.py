"""Guard CLI hook command entrypoint."""

# ruff: noqa: F403

from __future__ import annotations

from typing import TYPE_CHECKING

from ._commands_shared import *
from .commands_hook_native_authority import route_native_hook
from .commands_support_hook_payload import _load_hook_payload

if TYPE_CHECKING:
    import argparse
    from pathlib import Path
    from typing import TextIO

    from ..adapters.base import HarnessContext
    from ..config import GuardConfig
    from ..runtime.harness_attribution import resolve_runtime_hook_harness
    from ..store import GuardStore
    from ._commands_shared import _require_guard_context, _require_guard_store


def _run_guard_hook_command(
    args: argparse.Namespace,
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    context: HarnessContext | None = None,
    store: GuardStore | None = None,
    config: GuardConfig | None = None,
    input_text: str | None = None,
    output_stream: TextIO | None = None,
    _claim_saved_approval: bool = True,
    _claimed_saved_allow_hash: str | None = None,
    _claimed_trusted_request_override: bool = False,
    _claimed_approval_request_id: str | None = None,
) -> int:
    if guard_home is None:
        raise RuntimeError("Guard home is required")
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    runtime_harness = getattr(args, "runtime_harness", None)
    if isinstance(runtime_harness, str) and runtime_harness.strip():
        args.harness = runtime_harness.strip()
    else:
        args.harness = resolve_runtime_hook_harness(args.harness)
    payload = _load_hook_payload(
        getattr(args, "event_file", None),
        input_text=input_text,
        harness=args.harness,
        normalize=False,
    )
    return route_native_hook(
        args,
        config=config,
        context=context,
        payload=payload,
        runtime_workspace=workspace,
        store=store,
        output_stream=output_stream,
        _claim_saved_approval=_claim_saved_approval,
        _claimed_saved_allow_hash=_claimed_saved_allow_hash,
        _claimed_trusted_request_override=_claimed_trusted_request_override,
        _claimed_approval_request_id=_claimed_approval_request_id,
    )


__all__ = [
    "_run_guard_hook_command",
]
