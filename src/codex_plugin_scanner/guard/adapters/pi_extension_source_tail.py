"""Static hook handlers for the generated Pi-family extension source."""

from __future__ import annotations

from .pi_extension_contained_tests_source import with_contained_test_routing
from .pi_extension_input_source import INPUT_HANDLER_SOURCE
from .pi_extension_source_tail_shared_v1 import build_source_tail_shared_v1


def build_extension_source_tail(
    *,
    display_name: str,
    harness: str,
    lifecycle_abort_event_source: str,
    tool_approval_continuation_source: str,
) -> str:
    workspace_readiness_source = (
        "    const workspaceReadiness = await ensureGuardWorkspaceReady(snapshot.cwd, false);\n"
        "    if (!workspaceReadiness.ready) {\n"
        "      const reason = readinessFailureReason(workspaceReadiness);\n"
        '      ctx.ui.notify(reason, "warning");\n'
        "      return { block: true, reason };\n"
        "    }\n"
    )
    shared_source = build_source_tail_shared_v1(
        display_name=display_name,
        harness=harness,
        lifecycle_abort_event_source=lifecycle_abort_event_source,
        tool_approval_continuation_source=tool_approval_continuation_source,
        workspace_readiness_source=workspace_readiness_source,
    )
    input_start = shared_source.index('  pi.on("input",')
    input_end = shared_source.index('  pi.on("tool_call",', input_start)
    shared_source = shared_source[:input_start] + INPUT_HANDLER_SOURCE + shared_source[input_end:]
    if harness == "omp":
        shared_source = with_contained_test_routing(shared_source)
    return shared_source + (
        "    const hookDeadlineAt = Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS;\n"
        "    const signal = handlerAbortSignal(ctx);\n"
        "    const toolInput =\n"
        "      (event as { input?: Record<string, unknown> }).input ??\n"
        "      (event as { toolInput?: Record<string, unknown> }).toolInput ??\n"
        "      (event as { arguments?: Record<string, unknown> }).arguments ??\n"
        "      {};\n"
        "    const preprocessBudget = createTraversalBudget(hookDeadlineAt);\n"
        "    const digest = digestOutputText(event.content, hookDeadlineAt, preprocessBudget);\n"
        "    const boundedContent = boundValue(event.content, 0, new WeakSet(), preprocessBudget);\n"
        "    const boundedStdout = boundedOutputText(event.content, hookDeadlineAt, preprocessBudget);\n"
        "    const outputTruncated = boundedContent.truncated || boundedStdout.truncated"
        " || digest.excerptTruncated || digest.traversalTruncated;\n"
        "    const toolOutput = digest.textForExcerpt || (boundedStdout.value as string);\n"
        "    const reviewedContent = outputTruncated ? [{ type: 'text', text: toolOutput }] : boundedContent.value;\n"
        "    // OMP resolves bounded read selectors before returning output. Use that\n"
        "    // verified base path for source review, while retaining the raw input\n"
        "    // for directory and non-source tool results.\n"
        "    const details = event.details;\n"
        "    const detailsRecord = details && typeof details === 'object' && !Array.isArray(details)\n"
        "      ? details as Record<string, unknown> : undefined;\n"
        "    const resolvedDirectoryPath = detailsRecord &&\n"
        "      detailsRecord.isDirectory === true &&\n"
        "      typeof detailsRecord.resolvedPath === 'string' && detailsRecord.resolvedPath.trim()\n"
        "      ? detailsRecord.resolvedPath.trim() : undefined;\n"
        "    const reviewToolInput = (() => {\n"
        "      const toolName = typeof event.toolName === 'string' ? event.toolName : '';\n"
        "      if (!GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES.has(toolName) ||\n"
        "          !detailsRecord || resolvedDirectoryPath !== undefined) return toolInput;\n"
        "      const meta = detailsRecord.meta;\n"
        "      const source = meta && typeof meta === 'object'\n"
        "        ? (meta as Record<string, unknown>).source : undefined;\n"
        "      const resolvedPath = source && typeof source === 'object'\n"
        "        ? (source as Record<string, unknown>).value : undefined;\n"
        "      if (typeof resolvedPath !== 'string' || !resolvedPath.trim()) return toolInput;\n"
        "      for (const key of ['file_path', 'filePath', 'path', 'file', 'filename']) {\n"
        "        const inputPath = toolInput[key];\n"
        "        if (typeof inputPath === 'string' && inputPath.trim()) {\n"
        "          return { ...toolInput, [key]: resolvedPath.trim() };\n"
        "        }\n"
        "      }\n"
        "      return toolInput;\n"
        "    })();\n"
        "    const sourceRef = sourceFileRefForPostToolUse("
        "      event as Record<string, unknown>, reviewToolInput, digest);\n"
        "    // Preserve the original input for native pre/post digest parity.\n"
        "    // Rust revalidates directory targets, including bounded OMP selectors;\n"
        "    // host-resolved details are metadata, not an authority to rewrite it.\n"
        "    const guardToolInput = reviewToolInput;\n"
        "    const resolvedDirectoryTarget = resolvedDirectoryPath;\n"
        "    const guardPayload: Record<string, unknown> = {\n"
        '        hook_event_name: "PostToolUse",\n'
        "        config_path: GUARD_CONFIG_PATH,\n"
        "        tool_call_id: event.toolCallId,\n"
        "        tool_name: event.toolName,\n"
        "        tool_input: guardToolInput,\n"
        "        tool_response: toolOutput,\n"
        "        is_error: event.isError === true,\n"
        "    };\n"
        "    if (resolvedDirectoryTarget !== undefined) {\n"
        "      guardPayload.resolved_directory_target = resolvedDirectoryTarget;\n"
        "    }\n"
        "    // OMP's current ExtensionContext has no lifecycle signal. A managed\n"
        "    // structured destination therefore stays fail-closed there unless the\n"
        "    // host supplies the feature-detected signal used by the tool-call path.\n"
        "    const structuredOutputJson = signal === undefined\n"
        "      ? null\n"
        "      : structuredOutputJsonForPostToolUse(event.content, hookDeadlineAt);\n"
        "    if (structuredOutputJson !== null) guardPayload.structured_output_json = structuredOutputJson;\n"
        "    if (sourceRef) {\n"
        "      guardPayload.guard_source_ref = sourceRef;\n"
        "      guardPayload.tool_response_summary = {\n"
        "        kind: 'text',\n"
        "        text_excerpt: toolOutput,\n"
        "        excerpt_chars: toolOutput.length,\n"
        "        output_chars: digest.chars,\n"
        "        output_sha256: digest.sha256,\n"
        "        excerpt_truncated: outputTruncated,\n"
        "      };\n"
        "    } else {\n"
        "      guardPayload.tool_response = event.content;\n"
        "    }\n"
        "    const response = await runGuard(\n"
        "      guardPayload,\n"
        "      ctx.cwd,\n"
        "      { enforceSizeCap: true, deadlineAt: hookDeadlineAt },\n"
        "    );\n"
        "    if (signal?.aborted || Date.now() >= hookDeadlineAt) {\n"
        '      const reason = "HOL Guard withheld this tool output because its review lifecycle "\n'
        '        + "was cancelled or exceeded its deadline.";\n'
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(\n"
        "        `${reason} Resume the task to review the output again.`, event.details);\n"
        "    }\n"
        '    if (response.decision === "deny") {\n'
        '      const reason = response.reason ?? "Blocked by HOL Guard.";\n'
        "      const modelReason = modelVisibleBlockedReason(reason, response.reason_code);\n"
        "      const toolCallId = toolCallIdKey(event.toolCallId);\n"
        "      if (toolCallId) blockedToolResults.set(toolCallId, modelReason);\n"
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(modelReason, event.details);\n"
        "    }\n"
        "    const structuredMediation = response.structured_content_mediation;\n"
        "    if (response.observe_mode === true && structuredMediation === undefined) return undefined;\n"
        "    if (structuredMediation !== undefined) {\n"
        "      if (structuredMediation.action === 'forward' && signal === undefined) {\n"
        '        const reason = "HOL Guard withheld this structured tool output because the host exposes "\n'
        '          + "no cancellation signal.";\n'
        '        ctx.ui.notify(reason, "warning");\n'
        "        return blockedToolResult(\n"
        "          modelVisibleBlockedReason(reason, 'structured_cancellation_unsupported'), event.details);\n"
        "      }\n"
        "      if (signal?.aborted || Date.now() >= hookDeadlineAt) {\n"
        '        const reason = "HOL Guard withheld this structured tool output because its lifecycle ended "\n'
        '          + "before forwarding.";\n'
        '        ctx.ui.notify(reason, "warning");\n'
        "        return blockedToolResult(\n"
        "          modelVisibleBlockedReason(reason, 'structured_review_cancelled'), event.details);\n"
        "      }\n"
        "      const structuredCandidate = structuredOutputJsonForPostToolUse(event.content, hookDeadlineAt);\n"
        "      if (signal?.aborted || Date.now() >= hookDeadlineAt) {\n"
        '        const reason = "HOL Guard withheld this structured tool output because its lifecycle ended "\n'
        '          + "during forwarding proof.";\n'
        '        ctx.ui.notify(reason, "warning");\n'
        "        return blockedToolResult(\n"
        "          modelVisibleBlockedReason(reason, 'structured_review_cancelled'), event.details);\n"
        "      }\n"
        "      const structuredDigest = structuredCandidate === null\n"
        "        ? null\n"
        "        : createHash('sha256').update(structuredCandidate, 'utf8').digest('hex');\n"
        "      const structuredForwardProof =\n"
        '        response.decision === "allow" &&\n'
        '        response.model_output_action === "allow_original" &&\n'
        '        structuredMediation.action === "forward" &&\n'
        "        structuredMediation.native_decision_id !== undefined &&\n"
        "        structuredMediation.content_sha256 === structuredDigest;\n"
        "      if (!structuredForwardProof) {\n"
        '        const reason = "HOL Guard withheld this structured tool output because its full content "\n'
        '          + "could not be proven safe.";\n'
        '        ctx.ui.notify(reason, "warning");\n'
        "        return blockedToolResult(\n"
        "          modelVisibleBlockedReason(reason, structuredMediation.reason_code), event.details);\n"
        "      }\n"
        "    }\n"
        "    const originalOutputProof =\n"
        '      response.decision === "allow" &&\n'
        '      response.model_output_action === "allow_original" &&\n'
        "      typeof response.reviewed_output_sha256 === 'string' &&\n"
        "      response.reviewed_output_sha256 === digest.sha256;\n"
        "    if (originalOutputProof) {\n"
        "      if (signal?.aborted || Date.now() >= hookDeadlineAt) {\n"
        '        const reason = "HOL Guard withheld this tool output because its review lifecycle ended "\n'
        '          + "before preserving the original result.";\n'
        '        ctx.ui.notify(reason, "warning");\n'
        "        return blockedToolResult(\n"
        "          modelVisibleBlockedReason(reason, 'structured_review_cancelled'), event.details);\n"
        "      }\n"
        "      return undefined;\n"
        "    }\n"
        '    if (response.model_output_action === "allow_original") {\n'
        "      const reason = response.reason ||\n"
        '        "HOL Guard could not prove this tool output safe to preserve.";\n'
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(modelVisibleBlockedReason(reason, response.reason_code), event.details);\n"
        "    }\n"
        '    if (response.model_output_action === "replace_with_reviewed_excerpt") {\n'
        "      const excerptText = typeof response.reviewed_excerpt === 'string' ? response.reviewed_excerpt : '';\n"
        "      if (excerptText.length === 0) {\n"
        "        const reason = response.reason ||\n"
        '          "HOL Guard could not prove this tool output safe to preserve.";\n'
        '        ctx.ui.notify(reason, "warning");\n'
        "        return blockedToolResult("
        "modelVisibleBlockedReason(reason, response.reason_code), event.details);\n"
        "      }\n"
        "      const notice = response.reason ||\n"
        '        "HOL Guard returned a reviewed excerpt because this output could not be fully proven safe'
        ' within local limits.";\n'
        '      ctx.ui.notify(notice, "info");\n'
        "      return reviewedToolResult([{ type: 'text', text: excerptText }], "
        "event.details, event.isError === true, hookDeadlineAt);\n"
        "    }\n"
        "    if (outputTruncated) {\n"
        "      const notice = response.reason ||\n"
        '        "HOL Guard returned a reviewed excerpt because this output could not be fully proven safe'
        ' within local limits.";\n'
        '      if (response.notice === "excerpt"'
        ' || response.model_output_action === "replace_with_reviewed_excerpt") {\n'
        '        ctx.ui.notify(notice, "info");\n'
        "      }\n"
        "      return reviewedToolResult(reviewedContent, event.details, event.isError === true, hookDeadlineAt);\n"
        "    }\n"
        '    if (response.decision === "allow") return undefined;\n'
        "    const reason = response.reason ||\n"
        '      "HOL Guard could not prove this tool output safe to preserve.";\n'
        '    ctx.ui.notify(reason, "warning");\n'
        "    return blockedToolResult(modelVisibleBlockedReason(reason, response.reason_code), event.details);\n"
        "  });\n"
        "}\n"
    )
