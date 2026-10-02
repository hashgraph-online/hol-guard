"""Frozen previous Pi extension source tail."""

from __future__ import annotations

from .pi_extension_source_tail_shared_v1 import build_source_tail_shared_v1


def build_previous_source_tail(
    *,
    display_name: str,
    harness: str,
    lifecycle_abort_event_source: str,
    tool_approval_continuation_source: str,
) -> str:
    return build_source_tail_shared_v1(
        display_name=display_name,
        harness=harness,
        lifecycle_abort_event_source=lifecycle_abort_event_source,
        tool_approval_continuation_source=tool_approval_continuation_source,
    ) + (
        "    const toolInput =\n"
        "      (event as { input?: Record<string, unknown> }).input ??\n"
        "      (event as { toolInput?: Record<string, unknown> }).toolInput ??\n"
        "      (event as { arguments?: Record<string, unknown> }).arguments ??\n"
        "      {};\n"
        "    const digest = digestOutputText(event.content);\n"
        "    const boundedContent = boundValue(event.content);\n"
        "    const boundedStdout = boundedOutputText(event.content);\n"
        "    const outputTruncated = boundedContent.truncated || boundedStdout.truncated"
        " || digest.excerptTruncated || digest.traversalTruncated;\n"
        "    const toolOutput = digest.textForExcerpt || (boundedStdout.value as string);\n"
        "    const reviewedContent = outputTruncated ? [{ type: 'text', text: toolOutput }] : boundedContent.value;\n"
        "    const sourceRef = sourceFileRefForPostToolUse(event as Record<string, unknown>, toolInput, digest);\n"
        "    const guardPayload: Record<string, unknown> = {\n"
        '        hook_event_name: "PostToolUse",\n'
        "        config_path: GUARD_CONFIG_PATH,\n"
        "        tool_call_id: event.toolCallId,\n"
        "        tool_name: event.toolName,\n"
        "        tool_input: toolInput,\n"
        "        tool_response: toolOutput,\n"
        "        is_error: event.isError === true,\n"
        "    };\n"
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
        "      { enforceSizeCap: true },\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      const reason = response.reason ?? "Blocked by HOL Guard.";\n'
        "      const modelReason = modelVisibleBlockedReason(reason, response.reason_code);\n"
        "      const toolCallId = toolCallIdKey(event.toolCallId);\n"
        "      if (toolCallId) blockedToolResults.set(toolCallId, modelReason);\n"
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(modelReason, event.details);\n"
        "    }\n"
        "    if (response.observe_mode === true) return undefined;\n"
        "    const originalOutputProof =\n"
        '      response.decision === "allow" &&\n'
        '      response.model_output_action === "allow_original" &&\n'
        "      typeof response.reviewed_output_sha256 === 'string' &&\n"
        "      response.reviewed_output_sha256 === digest.sha256;\n"
        "    if (originalOutputProof) return undefined;\n"
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
        "event.details, event.isError === true);\n"
        "    }\n"
        "    if (outputTruncated) {\n"
        "      const notice = response.reason ||\n"
        '        "HOL Guard returned a reviewed excerpt because this output could not be fully proven safe'
        ' within local limits.";\n'
        '      if (response.notice === "excerpt"'
        ' || response.model_output_action === "replace_with_reviewed_excerpt") {\n'
        '        ctx.ui.notify(notice, "info");\n'
        "      }\n"
        "      return reviewedToolResult(reviewedContent, event.details, event.isError === true);\n"
        "    }\n"
        '    if (response.decision === "allow") return undefined;\n'
        "    const reason = response.reason ||\n"
        '      "HOL Guard could not prove this tool output safe to preserve.";\n'
        '    ctx.ui.notify(reason, "warning");\n'
        "    return blockedToolResult(modelVisibleBlockedReason(reason, response.reason_code), event.details);\n"
        "  });\n"
        "}\n"
    )
