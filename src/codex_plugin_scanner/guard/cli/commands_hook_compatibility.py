"""Compatibility-only payload preparation for explicitly non-native hooks."""

from __future__ import annotations

import os
from argparse import Namespace
from pathlib import Path

from ..adapters.base import HarnessContext
from ..cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_command_activity_failure_best_effort,
    record_post_hook_command_activity_best_effort,
)
from ..runtime.command_activity_cursor import cursor_command_activity_observer_trusted
from ..store import GuardStore
from .commands_support_hook_payload import _normalize_hook_payload
from .commands_support_hook_state import _cursor_conversation_id, _cursor_shell_command_from_payload
from .commands_support_interaction import _emit
from .commands_support_permission_store import _persist_cursor_native_permission_after_shell
from .commands_support_runtime_artifacts import _hook_event_name
from .commands_support_workspace import _workspace_from_cursor_project_dir


def prepare_compatibility_hook_payload(payload: dict[str, object], *, harness: str) -> dict[str, object]:
    """Apply harness-specific normalization after native authority declines."""

    from ..adapters.cline_hook_payload import prepare_cline_hook_payload
    from ..adapters.cursor_hooks import prepare_cursor_hook_payload
    from ..adapters.grok_hooks import prepare_grok_hook_payload
    from ..adapters.zcode_hooks import prepare_zcode_hook_payload
    from .commands_support_runtime_resolution import _canonical_harness_name

    canonical_harness = _canonical_harness_name(harness)
    preparers = {
        "cline": prepare_cline_hook_payload,
        "cursor": prepare_cursor_hook_payload,
        "grok": prepare_grok_hook_payload,
        "zcode": prepare_zcode_hook_payload,
    }
    prepare = preparers.get(canonical_harness)
    if prepare is not None:
        payload = prepare(payload)
        payload = _normalize_hook_payload(payload, harness=harness)
    return payload


def maybe_handle_cursor_post_tool(
    *,
    args: Namespace,
    payload: dict[str, object],
    context: HarnessContext,
    store: GuardStore,
    runtime_workspace: Path | None,
) -> tuple[Path | None, int | None]:
    """Record Cursor observer activity and signal whether the hook is complete."""

    from .commands_support_runtime_resolution import _canonical_harness_name

    if _canonical_harness_name(args.harness) != "cursor" or _hook_event_name(payload) not in {
        "afterShellExecution",
        "afterMCPExecution",
    }:
        return runtime_workspace, None
    if runtime_workspace is None:
        runtime_workspace = _workspace_from_cursor_project_dir()
    conversation_id = _cursor_conversation_id(payload)
    cursor_command = _cursor_shell_command_from_payload(payload)
    try:
        observer_trusted = bool(
            conversation_id is not None
            and cursor_command is not None
            and cursor_command_activity_observer_trusted(
                guard_home=context.guard_home,
                payload=payload,
                conversation_id=conversation_id,
                command=cursor_command,
                env=os.environ,
            )
        )
    except Exception:
        observer_trusted = False
        record_command_activity_failure_best_effort(store, "cursor_observer_verify_failed")
    saved = _persist_cursor_native_permission_after_shell(
        store=store,
        payload=payload,
        harness=args.harness,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        workspace=runtime_workspace,
        hook_env=os.environ,
    )
    if observer_trusted:
        event_name = _hook_event_name(payload) or "afterShellExecution"
        _ = record_post_hook_command_activity_best_effort(
            store=store,
            guard_home=context.guard_home,
            harness="cursor",
            event=event_name,
            payload=payload,
            succeeded=hook_post_succeeded(event_name, payload),
        )
    _emit(
        "hook",
        {"recorded": saved, "harness": "cursor", "session_approved": saved},
        getattr(args, "json", False),
    )
    return runtime_workspace, 0


__all__ = ["maybe_handle_cursor_post_tool", "prepare_compatibility_hook_payload"]
