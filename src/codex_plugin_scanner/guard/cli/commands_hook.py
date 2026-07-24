"""Guard CLI hook command entrypoint."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..runtime.hook_review_types import HookOutputSummary, HookSourceFileRef
    from ._commands_shared import _now, _require_guard_config, _require_guard_context, _require_guard_store
    from .commands_support_claude_approval import _persist_claude_guard_question_decision
    from .commands_support_connect import _synced_policy_payload
    from .commands_support_hook_payload import _hook_action_envelope, _load_hook_payload, _normalize_hook_payload
    from .commands_support_interaction import _emit
    from .commands_support_permission_store import (
        _cursor_conversation_id,
        _cursor_shell_command_from_payload,
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
from .commands_support_command_activity import (
    hook_post_succeeded,
    record_command_activity_failure_best_effort,
    record_post_hook_command_activity_best_effort,
)


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
    runtime_harness = getattr(args, "runtime_harness", None)
    if isinstance(runtime_harness, str) and runtime_harness.strip():
        args.harness = runtime_harness.strip()
    else:
        args.harness = resolve_runtime_hook_harness(args.harness)
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
    if _canonical_harness_name(args.harness) == "adal":
        from ..adapters.adal_hooks import prepare_adal_hook_payload

        payload = _normalize_hook_payload(prepare_adal_hook_payload(payload), harness=args.harness)
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
        from ..runtime.command_activity_cursor import cursor_command_activity_observer_trusted

        cursor_conversation_id = _cursor_conversation_id(payload)
        cursor_command = _cursor_shell_command_from_payload(payload)
        try:
            command_activity_observer_trusted = (
                cursor_conversation_id is not None
                and cursor_command is not None
                and cursor_command_activity_observer_trusted(
                    guard_home=context.guard_home,
                    payload=payload,
                    conversation_id=cursor_conversation_id,
                    command=cursor_command,
                    env=os.environ,
                )
            )
        except Exception:
            command_activity_observer_trusted = False
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
        if command_activity_observer_trusted:
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
    # Fast path: if the payload contains guard_source_ref, try the hook
    # review engine before the full runtime artifact path. This avoids
    # CLI command layering cost for safe source-file reads.
    source_ref_result = _try_source_ref_fast_path(
        args,
        config=config,
        context=context,
        guard_home=guard_home,
        payload=payload,
        runtime_workspace=runtime_workspace,
        store=store,
    )
    if source_ref_result is not None:
        return source_ref_result
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
            config=config,
            preferred_workspace_config="ide" if workspace_was_explicit else "cli",
        )
        if args.harness == "copilot"
        else None
    )

    def fresh_copilot_tool_call_authority():
        fresh_config = overlay_synced_guard_policy(
            load_guard_config(guard_home, workspace=runtime_workspace),
            _synced_policy_payload(store),
        )
        fresh_tool_call = _copilot_runtime_tool_call(
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
            config=fresh_config,
            preferred_workspace_config="ide" if workspace_was_explicit else "cli",
        )
        if fresh_tool_call is None:
            return None
        fresh_artifact, fresh_artifact_hash, fresh_arguments = fresh_tool_call
        return fresh_config, fresh_artifact, fresh_artifact_hash, fresh_arguments

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
        fresh_tool_call_authority_provider=fresh_copilot_tool_call_authority,
    )
    if result is not None:
        return result
    copilot_permission_request = (
        _copilot_runtime_tool_call(
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
            config=config,
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
        fresh_tool_call_authority_provider=fresh_copilot_tool_call_authority,
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

        def evaluate_fresh_runtime_artifact(
            *,
            claimed_saved_allow_hash: str | None = None,
            claimed_trusted_request_override: bool = False,
            claimed_approval_request_id: str | None = None,
            trusted_request_override_hash: str | None = None,
        ):
            fresh_config = overlay_synced_guard_policy(
                load_guard_config(guard_home, workspace=runtime_workspace),
                _synced_policy_payload(store),
            )
            fresh_action_envelope = _hook_action_envelope(
                harness=args.harness,
                payload=payload,
                home_dir=context.home_dir,
                workspace=runtime_workspace,
            )
            fresh_data_flow_signals = _runtime_action_data_flow_signals(
                fresh_action_envelope,
                workspace=runtime_workspace,
            )
            fresh_runtime_artifact = _hook_runtime_artifact(
                harness=args.harness,
                payload=payload,
                action_envelope=fresh_action_envelope,
                data_flow_signals=fresh_data_flow_signals,
                home_dir=context.home_dir,
                guard_home=context.guard_home,
                workspace=runtime_workspace,
            )
            if fresh_runtime_artifact is None:
                return None
            return _evaluate_runtime_artifact_hook(
                args,
                action_envelope=fresh_action_envelope,
                config=fresh_config,
                context=context,
                data_flow_signals=fresh_data_flow_signals,
                guard_home=guard_home,
                payload=payload,
                runtime_artifact=fresh_runtime_artifact,
                runtime_workspace=runtime_workspace,
                store=store,
                trusted_request_override_hash=trusted_request_override_hash,
                post_claim_revalidator=(revalidate_runtime_after_claim if claimed_saved_allow_hash is None else None),
                _claimed_saved_allow_hash=claimed_saved_allow_hash,
                _claimed_trusted_request_override=claimed_trusted_request_override,
                _claimed_approval_request_id=claimed_approval_request_id,
                _claim_saved_approval=claimed_saved_allow_hash is None,
            )

        def revalidate_runtime_after_claim(
            claimed_artifact_hash: str,
            trusted_request_override: bool,
            approval_request_id: str | None,
        ):
            return evaluate_fresh_runtime_artifact(
                claimed_saved_allow_hash=claimed_artifact_hash,
                claimed_trusted_request_override=trusted_request_override,
                claimed_approval_request_id=approval_request_id,
            )

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
            post_claim_revalidator=revalidate_runtime_after_claim,
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

        def revalidate_after_browser_wait():
            fresh_evaluation = evaluate_fresh_runtime_artifact(
                trusted_request_override_hash=evaluated.runtime_artifact_hash,
            )
            return fresh_evaluation if not isinstance(fresh_evaluation, int) else None

        return _finalize_runtime_artifact_hook(
            evaluated,
            args,
            config=config,
            output_stream=output_stream,
            payload=payload,
            store=store,
            post_wait_revalidator=revalidate_after_browser_wait,
        )

    def revalidate_generic_after_claim(claimed_artifact_hash: str) -> int:
        fresh_config = overlay_synced_guard_policy(
            load_guard_config(guard_home, workspace=runtime_workspace),
            _synced_policy_payload(store),
        )
        fresh_action_envelope = _hook_action_envelope(
            harness=args.harness,
            payload=payload,
            home_dir=context.home_dir,
            workspace=runtime_workspace,
        )
        return _run_hook_generic_payload(
            args,
            action_envelope=fresh_action_envelope,
            config=fresh_config,
            home_dir=context.home_dir,
            output_stream=output_stream,
            payload=payload,
            runtime_workspace=runtime_workspace,
            store=store,
            _claimed_saved_allow_hash=claimed_artifact_hash,
            _claim_saved_approval=False,
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
        post_claim_revalidator=revalidate_generic_after_claim,
    )


def _try_source_ref_fast_path(
    args: argparse.Namespace,
    *,
    config: GuardConfig | None,
    context: HarnessContext,
    guard_home: Path,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
) -> int | None:
    """Try the hook review engine for source-ref payloads.

    Returns an exit code if the fast path handled the request, or None
    to fall through to the standard runtime artifact path.
    """
    if "guard_source_ref" not in payload:
        return None
    # CLI fallback is enabled by default. The HOL_GUARD_HOOK_SOURCE_REF=0
    # flag disables guard_source_ref generation in the Pi extension, but
    # the CLI should still handle source refs if they arrive.
    import os

    if os.environ.get("HOL_GUARD_HOOK_SOURCE_REF", "1") != "1":
        return None

    from collections.abc import Mapping

    from ..runtime.hook_content_scanner import ContentScanner
    from ..runtime.hook_decision_cache import HookDecisionCache
    from ..runtime.hook_review_engine import HookReviewEngine
    from ..runtime.hook_review_types import HookReviewRequest

    source_ref_raw = payload.get("guard_source_ref")
    if not isinstance(source_ref_raw, Mapping):
        return None

    source_ref = _parse_source_ref(source_ref_raw)
    output_summary = _parse_output_summary(payload.get("tool_response_summary"))

    request = HookReviewRequest(
        harness=args.harness,
        event_name=_hook_event_name(payload) or "PreToolUse",
        payload=payload,
        payload_kind="source_file_ref",
        config_path=None,
        cwd=runtime_workspace,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        source_scope=str(payload.get("source_scope") or "project"),
        source_ref=source_ref,
        output_summary=output_summary,
    )

    scanner = ContentScanner()
    cache = HookDecisionCache(store)
    engine = HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=lambda gh, ws: config if config is not None else load_guard_config(gh, workspace=ws),
    )

    response = engine.review(request)
    event_name = _hook_event_name(payload) or "PostToolUse"
    record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=context.guard_home,
        harness=_canonical_harness_name(args.harness),
        event=event_name,
        payload=payload,
        succeeded=hook_post_succeeded(event_name, payload),
    )
    _emit("hook", response.to_harness_json(), getattr(args, "json", False))
    return 0


def _parse_source_ref(ref: Mapping[str, object]) -> HookSourceFileRef:
    """Parse a guard_source_ref mapping into a HookSourceFileRef."""
    from ..runtime.hook_review_types import HookSourceFileRef

    version = ref.get("version")
    path = ref.get("path")
    output_sha256 = ref.get("output_sha256")
    output_chars = ref.get("output_chars")
    tool_input_path = ref.get("tool_input_path")
    adapter_stat = ref.get("adapter_stat")

    if not isinstance(version, int) or not isinstance(path, str) or not isinstance(output_sha256, str):
        return HookSourceFileRef(version=-1, path="", output_sha256="", output_chars=0)

    if not isinstance(output_chars, int):
        output_chars = 0
    if not isinstance(tool_input_path, str):
        tool_input_path = None
    stat_dict = dict(adapter_stat) if isinstance(adapter_stat, Mapping) else {}

    return HookSourceFileRef(
        version=version,
        path=path,
        output_sha256=output_sha256,
        output_chars=output_chars,
        tool_input_path=tool_input_path,
        adapter_stat=stat_dict,
    )


def _parse_output_summary(summary_raw: object) -> HookOutputSummary | None:
    """Parse a tool_response_summary mapping into a HookOutputSummary."""
    from collections.abc import Mapping as _Mapping

    from ..runtime.hook_review_types import HookOutputSummary

    if not isinstance(summary_raw, _Mapping):
        return None
    text_excerpt = summary_raw.get("text_excerpt") or summary_raw.get("excerpt") or ""
    if not isinstance(text_excerpt, str):
        text_excerpt = str(text_excerpt)
    excerpt_truncated = bool(summary_raw.get("excerpt_truncated", False))
    output_sha256 = summary_raw.get("output_sha256")
    if not isinstance(output_sha256, str):
        output_sha256 = None
    output_chars_raw = summary_raw.get("output_chars")
    output_chars = int(output_chars_raw) if isinstance(output_chars_raw, (int, float)) else None
    return HookOutputSummary(
        text_excerpt=text_excerpt,
        excerpt_truncated=excerpt_truncated,
        output_sha256=output_sha256,
        output_chars=output_chars,
    )


__all__ = [
    "_run_guard_hook_command",
]
