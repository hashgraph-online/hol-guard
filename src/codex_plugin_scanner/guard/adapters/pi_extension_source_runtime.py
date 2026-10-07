"""Version-one runtime renderer for generated Pi-family extension sources.

The renderer owns only the shared runtime bindings and approval continuation
fragments. Each caller supplies its pinned limits and source builders. The
previous generator deliberately remains on this v1 renderer and its own
previous builders; a future active source revision must add a new renderer
version instead of changing v1 in place.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .pi_extension_runtime_ownership import PiExtensionRuntimeOwnership

SourceHeaderBuilder = Callable[..., str]
SourceBodyBuilder = Callable[..., str]
SourceTailBuilder = Callable[..., str]
RuntimeResolver = Callable[..., PiExtensionRuntimeOwnership]
WindowsExecutablePath = Callable[[str], str | None]
LifecycleBuilder = Callable[[str], str]
ApprovalBuilder = Callable[[str], str]


@dataclass(frozen=True)
class ExtensionSourceRenderConfigV1:
    guard_home: Path
    home_dir: Path
    settings_path: Path
    harness: str
    display_name: str
    package_source: Path
    compatibility_version: int
    hook_timeout_ms: int
    deadline_reserve_ms: int
    daemon_hook_timeout_ms: int
    daemon_recovery_timeout_ms: int
    daemon_retry_timeout_ms: int
    cli_hook_timeout_ms: int
    text_limit_chars: int
    content_item_limit: int
    object_key_limit: int
    max_depth: int
    max_serialized_payload_chars: int
    runtime_resolver: RuntimeResolver
    windows_executable_path: WindowsExecutablePath
    platform_name: str
    build_header: SourceHeaderBuilder
    build_body: SourceBodyBuilder
    build_tail: SourceTailBuilder
    build_lifecycle: LifecycleBuilder
    build_approval: ApprovalBuilder


@dataclass(frozen=True)
class ExtensionSourceVariantV1:
    """Pinned variant inputs for the shared v1 renderer.

    Active and previous callers each construct a separate instance. Keeping
    these values outside the renderer prevents a future active change from
    silently changing the frozen previous contract.
    """

    hook_timeout_ms: int
    deadline_reserve_ms: int
    daemon_hook_timeout_ms: int
    daemon_recovery_timeout_ms: int
    daemon_retry_timeout_ms: int
    cli_hook_timeout_ms: int
    text_limit_chars: int
    content_item_limit: int
    object_key_limit: int
    max_depth: int
    max_serialized_payload_chars: int
    build_header: SourceHeaderBuilder
    build_body: SourceBodyBuilder
    build_tail: SourceTailBuilder
    build_lifecycle: LifecycleBuilder
    build_approval: ApprovalBuilder


def render_extension_source_variant_v1(
    *,
    guard_home: Path,
    home_dir: Path,
    settings_path: Path,
    harness: str,
    display_name: str,
    package_source: Path,
    compatibility_version: int,
    runtime_resolver: RuntimeResolver,
    windows_executable_path: WindowsExecutablePath,
    platform_name: str,
    variant: ExtensionSourceVariantV1,
) -> str:
    """Render one explicitly pinned active or frozen source variant."""

    return render_extension_source_v1(
        ExtensionSourceRenderConfigV1(
            guard_home=guard_home,
            home_dir=home_dir,
            settings_path=settings_path,
            harness=harness,
            display_name=display_name,
            package_source=package_source,
            compatibility_version=compatibility_version,
            hook_timeout_ms=variant.hook_timeout_ms,
            deadline_reserve_ms=variant.deadline_reserve_ms,
            daemon_hook_timeout_ms=variant.daemon_hook_timeout_ms,
            daemon_recovery_timeout_ms=variant.daemon_recovery_timeout_ms,
            daemon_retry_timeout_ms=variant.daemon_retry_timeout_ms,
            cli_hook_timeout_ms=variant.cli_hook_timeout_ms,
            text_limit_chars=variant.text_limit_chars,
            content_item_limit=variant.content_item_limit,
            object_key_limit=variant.object_key_limit,
            max_depth=variant.max_depth,
            max_serialized_payload_chars=variant.max_serialized_payload_chars,
            runtime_resolver=runtime_resolver,
            windows_executable_path=windows_executable_path,
            platform_name=platform_name,
            build_header=variant.build_header,
            build_body=variant.build_body,
            build_tail=variant.build_tail,
            build_lifecycle=variant.build_lifecycle,
            build_approval=variant.build_approval,
        )
    )


def build_lifecycle_abort_event_source_v1(harness: str) -> str:
    return '  pi.on("session_stop", () => { invalidateApprovalContinuations(); });\n' if harness == "omp" else ""


def build_tool_approval_continuation_source_v1(harness: str) -> str:
    if harness == "omp":
        return (
            "      if (!ompInteractiveContext(ctx)) {\n"
            "        return { block: true, reason };\n"
            "      }\n"
            "      const continuation = await runOmpInteractiveContinuation(ctx, async (continuationSignal) => {\n"
            "        const action = await pollApprovalResolution(\n"
            "          requestId,\n"
            "          approvalPollPath(response, requestId),\n"
            "          continuationSignal,\n"
            "          activity,\n"
            "        );\n"
            "        if (action !== 'allow') return { action, response };\n"
            "        if (continuationSignal.aborted || (activity && !continuationIsActive(activity))) {\n"
            "          return { action: 'aborted', response };\n"
            "        }\n"
            "        if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
            "          return { action: 'changed', response };\n"
            "        }\n"
            "        if (continuationSignal.aborted) return { action: 'aborted', response };\n"
            "        const revalidated = await runGuard(snapshot.payload, snapshot.cwd);\n"
            "        if (continuationSignal.aborted || (activity && !continuationIsActive(activity))) {\n"
            "          return { action: 'aborted', response: revalidated };\n"
            "        }\n"
            "        if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
            "          return { action: 'changed', response: revalidated };\n"
            "        }\n"
            "        return {\n"
            "          action: revalidated.decision === 'allow' ? 'allow' : 'block',\n"
            "          response: revalidated,\n"
            "        };\n"
            "      });\n"
            "      if (continuation.kind !== 'completed') {\n"
            "        const continuationReason = continuation.kind === 'unavailable'\n"
            "          ? reason\n"
            "          : approvalContinuationFailureReason(\n"
            "              response,\n"
            "              continuation.kind === 'aborted' ? 'aborted' : 'transport',\n"
            "            );\n"
            '        ctx.ui.notify(continuationReason, "warning");\n'
            "        return { block: true, reason: continuationReason };\n"
            "      }\n"
            "      const continuationResult = continuation.value;\n"
            "      if (continuationResult.action === 'allow') return undefined;\n"
            "      const continuationReason = continuationResult.action === 'changed'\n"
            '        ? "HOL Guard blocked this tool call because its original arguments or '
            'context changed during approval."\n'
            "        : approvalContinuationFailureReason(continuationResult.response, continuationResult.action);\n"
            '      ctx.ui.notify(continuationReason, "warning");\n'
            "      return { block: true, reason: continuationReason };\n"
        )
    return (
        "      const action = await pollApprovalResolution(\n"
        "        requestId,\n"
        "        approvalPollPath(response, requestId),\n"
        "        signal,\n"
        "        activity,\n"
        "      );\n"
        "      if (action !== 'allow') {\n"
        "        const blockedReason = approvalContinuationFailureReason(response, action);\n"
        '        ctx.ui.notify(blockedReason, "warning");\n'
        "        return { block: true, reason: blockedReason };\n"
        "      }\n"
        "      if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
        '        const changedReason = "HOL Guard blocked this tool call because its original arguments or '
        'context changed before approval was consumed.";\n'
        '        ctx.ui.notify(changedReason, "warning");\n'
        "        return { block: true, reason: changedReason };\n"
        "      }\n"
        "      if (signal?.aborted || (activity && !continuationIsActive(activity))) {\n"
        "        const cancelledReason = approvalContinuationFailureReason(response, 'aborted');\n"
        '        ctx.ui.notify(cancelledReason, "warning");\n'
        "        return { block: true, reason: cancelledReason };\n"
        "      }\n"
        "      const revalidated = await runGuard(snapshot.payload, snapshot.cwd);\n"
        "      if (signal?.aborted || (activity && !continuationIsActive(activity))) {\n"
        "        const cancelledReason = approvalContinuationFailureReason(revalidated, 'aborted');\n"
        '        ctx.ui.notify(cancelledReason, "warning");\n'
        "        return { block: true, reason: cancelledReason };\n"
        "      }\n"
        "      if (!toolCallStillMatches(event, ctx, GUARD_CONFIG_PATH, snapshot)) {\n"
        '        const changedReason = "HOL Guard blocked this tool call because its original arguments or '
        'context changed during approval revalidation.";\n'
        '        ctx.ui.notify(changedReason, "warning");\n'
        "        return { block: true, reason: changedReason };\n"
        "      }\n"
        '      if (revalidated.decision === "allow") return undefined;\n'
        "      const revalidationReason = revalidated.reason ?? "
        '"HOL Guard could not revalidate the exact approved tool call.";\n'
        '      ctx.ui.notify(revalidationReason, "warning");\n'
        "      return { block: true, reason: revalidationReason };\n"
    )


def render_extension_source_v1(config: ExtensionSourceRenderConfigV1) -> str:
    runtime = config.runtime_resolver(
        guard_home=config.guard_home,
        home_dir=config.home_dir,
        harness=config.harness,
        package_source=config.package_source,
    )
    guard_args_json = json.dumps(list(runtime.guard_args))
    guard_home_json = json.dumps(str(config.guard_home))
    home_dir_json = json.dumps(str(config.home_dir))
    home_dir_is_default_json = "true" if config.home_dir.resolve() == Path.home().resolve() else "false"
    config_path_json = json.dumps(str(config.settings_path))
    compatibility_version_json = json.dumps(config.compatibility_version)
    cli_wrapper_command_json = json.dumps(runtime.cli_command)
    cli_wrapper_args_json = json.dumps(runtime.cli_args)
    recovery_command_json = json.dumps(runtime.recovery_command)
    recovery_args_json = json.dumps(runtime.recovery_args)
    try:
        taskkill_path = config.windows_executable_path("taskkill.exe") if config.platform_name == "nt" else None
    except (OSError, ValueError):
        taskkill_path = None
    taskkill_path_json = json.dumps(taskkill_path)
    lifecycle_abort_event_source = config.build_lifecycle(config.harness)
    tool_approval_continuation_source = config.build_approval(config.harness)
    return (
        config.build_header(
            cli_wrapper_command_json=cli_wrapper_command_json,
            cli_wrapper_args_json=cli_wrapper_args_json,
            compatibility_version_json=compatibility_version_json,
            config_path_json=config_path_json,
            guard_args_json=guard_args_json,
            guard_home_json=guard_home_json,
            home_dir_is_default_json=home_dir_is_default_json,
            home_dir_json=home_dir_json,
            recovery_args_json=recovery_args_json,
            recovery_command_json=recovery_command_json,
            runtime=runtime,
            taskkill_path_json=taskkill_path_json,
            guard_cli_hook_timeout_ms=config.cli_hook_timeout_ms,
            guard_daemon_hook_timeout_ms=config.daemon_hook_timeout_ms,
            guard_daemon_recovery_timeout_ms=config.daemon_recovery_timeout_ms,
            guard_daemon_retry_timeout_ms=config.daemon_retry_timeout_ms,
            guard_hook_content_item_limit=config.content_item_limit,
            guard_hook_deadline_reserve_ms=config.deadline_reserve_ms,
            guard_hook_max_depth=config.max_depth,
            guard_hook_max_serialized_payload_chars=config.max_serialized_payload_chars,
            guard_hook_object_key_limit=config.object_key_limit,
            guard_hook_text_limit_chars=config.text_limit_chars,
            guard_hook_timeout_ms=config.hook_timeout_ms,
        )
        + config.build_body(harness=config.harness, display_name=config.display_name)
        + config.build_tail(
            display_name=config.display_name,
            harness=config.harness,
            lifecycle_abort_event_source=lifecycle_abort_event_source,
            tool_approval_continuation_source=tool_approval_continuation_source,
        )
    )
