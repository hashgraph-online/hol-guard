"""Guard CLI hook command entrypoint."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._commands_shared import _now, _require_guard_config, _require_guard_context, _require_guard_store
    from .commands_support_claude_approval import _persist_claude_guard_question_decision
    from .commands_support_hook_payload import _hook_action_envelope, _load_hook_payload, _normalize_hook_payload
    from .commands_support_interaction import _emit
    from .commands_support_permission_store import (
        _discard_claude_pending_permissions,
        _persist_cursor_native_permission_after_shell,
    )
    from .commands_support_runtime_artifacts import _hook_event_name, _hook_runtime_artifact
    from .commands_support_runtime_policy import _runtime_action_data_flow_signals
    from .commands_support_runtime_resolution import (
        _canonical_harness_name,
        _copilot_hook_stage,
        _copilot_runtime_tool_call,
        _is_copilot_permission_request,
        _managed_install_for,
        _resolve_copilot_workspace_root,
    )
    from .commands_support_workspace import _workspace_from_cursor_project_dir


from ._commands_shared import *
from .commands_hook_claude import (
    _run_hook_claude_permission_prompt_notification,
    _run_hook_claude_permission_request,
)
from .commands_hook_copilot import (
    _run_hook_copilot_permission_request,
    _run_hook_copilot_pretool,
)
from .commands_hook_generic import _run_hook_generic_payload
from .commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from .commands_hook_runtime_finish import _finalize_runtime_artifact_hook
from .commands_hook_runtime_review import _review_runtime_artifact_hook
from .commands_parser_helpers import *


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
) -> int:
    if guard_home is None:
        raise RuntimeError("Guard home is required")
    context = _require_guard_context(context)
    store = _require_guard_store(store)
    config = _require_guard_config(config)
    request_env = getattr(args, "hook_env", None)
    resolved_env = os.environ if request_env is None else request_env
    runtime_harness = getattr(args, "runtime_harness", None)
    if isinstance(runtime_harness, str) and runtime_harness.strip():
        args.harness = runtime_harness.strip()
    else:
        args.harness = resolve_runtime_hook_harness(args.harness, env=resolved_env)
    payload = _load_hook_payload(
        getattr(args, "event_file", None),
        input_text=input_text,
        harness=args.harness,
    )
    if _canonical_harness_name(args.harness) == "cursor":
        from ..adapters.cursor_hooks import prepare_cursor_hook_payload

        payload = _normalize_hook_payload(prepare_cursor_hook_payload(payload), harness=args.harness)
    if _canonical_harness_name(args.harness) == "grok":
        from ..adapters.grok_hooks import prepare_grok_hook_payload

        payload = _normalize_hook_payload(prepare_grok_hook_payload(payload), harness=args.harness)
    if _canonical_harness_name(args.harness) == "zcode":
        from ..adapters.zcode_hooks import prepare_zcode_hook_payload

        payload = _normalize_hook_payload(prepare_zcode_hook_payload(payload), harness=args.harness)
    managed_install = _managed_install_for(store, args.harness)
    workspace_was_explicit = workspace is not None
    runtime_workspace = workspace
    if runtime_workspace is None and args.harness == "copilot":
        with suppress(OSError):
            current_workspace = Path.cwd().resolve()
            if current_workspace.is_dir():
                runtime_workspace = current_workspace
    if _canonical_harness_name(args.harness) == "cursor" and _hook_event_name(payload) in {
        "afterShellExecution",
        "afterMCPExecution",
    }:
        if runtime_workspace is None:
            runtime_workspace = _workspace_from_cursor_project_dir()
        saved = _persist_cursor_native_permission_after_shell(
            store=store,
            payload=payload,
            harness=args.harness,
            home_dir=context.home_dir,
            guard_home=context.guard_home,
            workspace=runtime_workspace,
            hook_env=resolved_env,
        )
        _emit(
            "hook",
            {
                "recorded": saved,
                "harness": "cursor",
                "session_approved": saved,
            },
            getattr(args, "json", False),
        )
        return 0
    if args.harness == "copilot":
        runtime_workspace = _resolve_copilot_workspace_root(runtime_workspace)
    action_envelope = _hook_action_envelope(
        harness=args.harness,
        payload=payload,
        home_dir=context.home_dir,
        workspace=runtime_workspace,
    )
    copilot_hook_stage = _copilot_hook_stage(payload) if args.harness == "copilot" else None
    copilot_runtime_tool_call = (
        _copilot_runtime_tool_call(
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
            preferred_workspace_config="ide" if workspace_was_explicit else "cli",
        )
        if args.harness == "copilot"
        else None
    )
    result = _run_hook_copilot_pretool(
        args,
        action_envelope=action_envelope,
        config=config,
        context=context,
        copilot_hook_stage=copilot_hook_stage,
        copilot_runtime_tool_call=copilot_runtime_tool_call,
        output_stream=output_stream,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
    )
    if result is not None:
        return result
    copilot_permission_request = (
        _copilot_runtime_tool_call(
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
            preferred_workspace_config="ide" if workspace_was_explicit else "cli",
        )
        if args.harness == "copilot" and _is_copilot_permission_request(payload)
        else None
    )
    result = _run_hook_copilot_permission_request(
        args,
        action_envelope=action_envelope,
        config=config,
        context=context,
        copilot_permission_request=copilot_permission_request,
        guard_home=guard_home,
        managed_install=managed_install,
        output_stream=output_stream,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
    )
    if result is not None:
        return result
    data_flow_signals = _runtime_action_data_flow_signals(action_envelope, workspace=runtime_workspace)
    runtime_artifact = _hook_runtime_artifact(
        harness=args.harness,
        payload=payload,
        action_envelope=action_envelope,
        data_flow_signals=data_flow_signals,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        workspace=runtime_workspace,
    )
    result = _run_hook_claude_permission_request(
        args,
        config=config,
        output_stream=output_stream,
        payload=payload,
        runtime_artifact=runtime_artifact,
        runtime_workspace=runtime_workspace,
        store=store,
    )
    if result is not None:
        return result
    result = _run_hook_claude_permission_prompt_notification(
        args,
        output_stream=output_stream,
        payload=payload,
        store=store,
    )
    if result is not None:
        return result
    if _canonical_harness_name(args.harness) == "claude-code" and _hook_event_name(payload) == "Stop":
        discarded = _discard_claude_pending_permissions(store, payload)
        store.add_event(
            "claude/turn_stop",
            {
                "session_id": payload.get("session_id"),
                "discarded_pending_permissions": discarded,
            },
            _now(),
        )
        return 0
    if _canonical_harness_name(args.harness) == "claude-code" and _persist_claude_guard_question_decision(
        store, payload
    ):
        return 0
    if runtime_artifact is not None:
        evaluated = _evaluate_runtime_artifact_hook(
            args,
            action_envelope=action_envelope,
            config=config,
            context=context,
            data_flow_signals=data_flow_signals,
            guard_home=guard_home,
            payload=payload,
            runtime_artifact=runtime_artifact,
            runtime_workspace=runtime_workspace,
            store=store,
        )
        if isinstance(evaluated, int):
            return evaluated
        result = _review_runtime_artifact_hook(
            evaluated,
            args,
            config=config,
            context=context,
            guard_home=guard_home,
            managed_install=managed_install,
            output_stream=output_stream,
            payload=payload,
            store=store,
            workspace=workspace,
        )
        if result is not None:
            return result
        return _finalize_runtime_artifact_hook(
            evaluated,
            args,
            config=config,
            output_stream=output_stream,
            payload=payload,
            store=store,
        )
    return _run_hook_generic_payload(
        args,
        action_envelope=action_envelope,
        config=config,
        home_dir=context.home_dir,
        output_stream=output_stream,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
    )


__all__ = [
    "_run_guard_hook_command",
]
