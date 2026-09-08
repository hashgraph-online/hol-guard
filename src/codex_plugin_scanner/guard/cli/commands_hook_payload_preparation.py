"""Prepare compatibility hook state before legacy hook routing."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

from ..adapters.base import HarnessContext
from ..models import GuardArtifact
from ..runtime.actions import GuardActionEnvelope
from ..store import GuardStore

if TYPE_CHECKING:
    from ..config import GuardConfig


def prepare_compatibility_hook_state(
    args: argparse.Namespace,
    *,
    payload: dict[str, object],
    context: HarnessContext,
    store: GuardStore,
    workspace: Path | None,
    prepare_compatibility_hook_payload: Callable[..., dict[str, object]],
    managed_install_for: Callable[..., dict[str, object] | None],
    workspace_from_hook_payload: Callable[..., Path | None],
    maybe_handle_cursor_post_tool: Callable[..., tuple[Path | None, int | None]],
    resolve_copilot_workspace_root: Callable[[Path | None], Path | None],
    action_envelope_for: Callable[..., GuardActionEnvelope | None],
    copilot_hook_stage_for: Callable[[dict[str, object]], str | None],
    copilot_runtime_tool_call_for: Callable[..., tuple[GuardArtifact, str, object] | None],
    config: GuardConfig,
) -> tuple[
    dict[str, object],
    dict[str, object] | None,
    bool,
    Path | None,
    int | None,
    GuardActionEnvelope | None,
    str | None,
    tuple[GuardArtifact, str, object] | None,
]:
    """Prepare the normalized payload after native authority declines."""

    payload = prepare_compatibility_hook_payload(payload, harness=args.harness)
    managed_install = managed_install_for(store, args.harness)
    workspace_was_explicit = workspace is not None
    runtime_workspace = workspace_from_hook_payload(payload, workspace)
    if runtime_workspace is None and args.harness == "copilot":
        with suppress(OSError):
            current_workspace = Path.cwd().resolve()
            if current_workspace.is_dir():
                runtime_workspace = current_workspace
    runtime_workspace, cursor_result = maybe_handle_cursor_post_tool(
        args=args,
        payload=payload,
        context=context,
        store=store,
        runtime_workspace=runtime_workspace,
    )
    if cursor_result is not None:
        return (
            payload,
            managed_install,
            workspace_was_explicit,
            runtime_workspace,
            cursor_result,
            None,
            None,
            None,
        )
    if args.harness == "copilot":
        runtime_workspace = resolve_copilot_workspace_root(runtime_workspace)
    action_envelope = action_envelope_for(
        harness=args.harness,
        payload=payload,
        home_dir=context.home_dir,
        workspace=runtime_workspace,
    )
    copilot_hook_stage = copilot_hook_stage_for(payload) if args.harness == "copilot" else None
    copilot_runtime_tool_call = (
        copilot_runtime_tool_call_for(
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
            config=config,
            preferred_workspace_config="ide" if workspace_was_explicit else "cli",
        )
        if args.harness == "copilot"
        else None
    )
    return (
        payload,
        managed_install,
        workspace_was_explicit,
        runtime_workspace,
        cursor_result,
        action_envelope,
        copilot_hook_stage,
        copilot_runtime_tool_call,
    )
