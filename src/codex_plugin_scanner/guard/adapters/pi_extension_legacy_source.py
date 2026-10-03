"""Recognize the historical Pi install without depending on the active renderer."""

from pathlib import Path

from .pi_extension_previous_source import previous_managed_extension_source


def legacy_managed_extension_source(
    *,
    guard_home: Path,
    home_dir: Path,
    settings_path: Path,
    harness: str = "pi",
    display_name: str = "Pi",
) -> str:
    """Reconstruct the exact pre-response-contract extension for migration only."""

    source = previous_managed_extension_source(
        guard_home=guard_home,
        home_dir=home_dir,
        settings_path=settings_path,
        harness=harness,
        display_name=display_name,
    )

    # This renderer is a historical identity reader, never an installation source.
    # Start from the frozen previous revision, not today's adapter implementation.
    replacements = (
        ("    chars += Array.from(text).length;\n", "    chars += text.length;\n"),
        ('  decision: "allow" | "deny";\n', "  decision?: string;\n"),
        ("  observed_review_failure?: boolean;\n", ""),
        ("  policy_action?: string;\n", ""),
        ("  reviewed_excerpt?: string;\n", ""),
        (
            "function modelVisibleBlockedReason(reason: string, reasonCode?: string): string {\n"
            "  if (\n"
            '    reasonCode === "guard_cli_recovery_timeout" ||\n'
            '    reasonCode === "daemon_hook_deadline_exhausted" ||\n'
            '    reasonCode === "daemon_hook_process_deadline_exhausted"\n'
            "  ) {\n"
            f'    return "HOL Guard did not finish reviewing this output before the {display_name} '
            'deadline. Retry the action.";\n'
            "  }\n"
            f'  const prefix = "HOL Guard blocked this tool output before {display_name} could use it.";\n'
            "  const approvalUrl = reason.match(/https?:\\/\\/\\S+/)?.[0]?.replace(/[.,;:]+$/, '');\n"
            "  const approvalHint = approvalUrl ? ` Human approval is pending in HOL Guard: ${approvalUrl}.` : '';\n"
            "  return `${prefix}${approvalHint} Do not retry the same tool call automatically; wait for the user to "
            "approve or change the task.`;\n"
            "}\n",
            "function modelVisibleBlockedReason(reason: string): string {\n"
            f'  const prefix = "HOL Guard blocked this tool output before {display_name} could use it.";\n'
            "  const approvalUrl = reason.match(/https?:\\/\\/\\S+/)?.[0]?.replace(/[.,;:]+$/, '');\n"
            "  const approvalHint = approvalUrl ? ` Human approval is pending in HOL Guard: ${approvalUrl}.` : '';\n"
            "  return `${prefix}${approvalHint} Do not retry the same tool call automatically; wait for the user to "
            "approve or change the task.`;\n"
            "}\n",
        ),
        (
            "function normalizeGuardResponse(value: unknown): GuardResponse | null {\n"
            '  if (!value || typeof value !== "object" || Array.isArray(value)) return null;\n'
            "  const parsed = value as Record<string, unknown>;\n"
            "  if (parsed.reason !== undefined && parsed.reason !== null && "
            'typeof parsed.reason !== "string") return null;\n'
            '  if (parsed.decision === "allow" || parsed.decision === "deny") {\n'
            "    return parsed as GuardResponse;\n"
            "  }\n"
            '  if (parsed.decision === "block") {\n'
            '    return { ...parsed, decision: "deny" } as GuardResponse;\n'
            "  }\n"
            "  return null;\n"
            "}\n\n"
            "function fallbackGuardResponse(\n"
            "  reasonCode: string,\n"
            "  reason: string,\n"
            "): GuardResponse {\n"
            '  return { decision: "deny", reason, reason_code: reasonCode };\n'
            "}\n\n",
            "",
        ),
        (
            "function daemonResponseCanReturn(\n"
            "  payload: Record<string, unknown>,\n"
            "  response: GuardResponse,\n"
            "): boolean {\n"
            '  if (payload.hook_event_name !== "PostToolUse") return true;\n'
            "  if (response.observe_mode === true) return true;\n"
            '  if (response.model_output_action === "replace_with_reviewed_excerpt") return true;\n'
            '  if (response.model_output_action === "allow_original") {\n'
            '    return typeof response.reviewed_output_sha256 === "string" &&\n'
            "      response.reviewed_output_sha256.length > 0;\n"
            "  }\n"
            '  if (response.decision === "allow" || response.decision === "deny") return true;\n'
            "  return false;\n"
            "}\n\n",
            "",
        ),
        (
            '    if (!raw) return { response: null, recoveryKind: "transport-failure" };\n'
            "    try {\n"
            "      const parsed = JSON.parse(raw) as unknown;\n"
            "      const normalized = normalizeGuardResponse(parsed);\n"
            "      if (normalized !== null) {\n"
            "        return { response: normalized, recoveryKind: null };\n"
            "      }\n"
            '      return { response: null, recoveryKind: "transport-failure" };\n'
            "    } catch {}\n",
            "    if (!raw) return { response: {}, recoveryKind: null };\n"
            "    try {\n"
            "      const parsed = JSON.parse(raw) as GuardResponse;\n"
            "      if (parsed && typeof parsed === 'object') {\n"
            "        return { response: parsed, recoveryKind: null };\n"
            "      }\n"
            "    } catch {}\n",
        ),
        (
            "      const parsed = JSON.parse(lastLine) as unknown;\n"
            "      const normalized = normalizeGuardResponse(parsed);\n"
            '      if (normalized !== null && (result.status === 0 || normalized.decision === "deny")) {\n'
            "        return normalized;\n"
            "      }\n"
            "    } catch {}\n"
            "  }\n"
            "  if (result.status !== 0) {\n",
            "      const parsed = JSON.parse(lastLine) as GuardResponse;\n"
            '      if (parsed && typeof parsed === "object") return parsed;\n'
            "    } catch {}\n"
            "  }\n"
            "  if ((result.status ?? 0) !== 0) {\n",
        ),
        (
            "  return fallbackGuardResponse(\n"
            '    "guard_cli_invalid_response",\n'
            '    "HOL Guard fallback did not return a valid decision. Retry the action.",\n'
            "  );\n",
            '  return { decision: "allow" };\n',
        ),
        (
            "  if (\n"
            "    daemonAttempt.response &&\n"
            "    daemonResponseCanReturn(payload, daemonAttempt.response)\n"
            "  ) {\n"
            "    cleanupPayloadReference();\n"
            "    return daemonAttempt.response;\n"
            "  }\n"
            "  if (daemonAttempt.response) {\n"
            '    daemonAttempt = { response: null, recoveryKind: "transport-failure" };\n'
            "  }\n",
            "  if (daemonAttempt.response) {\n"
            "    cleanupPayloadReference();\n"
            "    return daemonAttempt.response;\n"
            "  }\n",
        ),
        (
            "      if (\n"
            "        daemonAttempt.response &&\n"
            "        daemonResponseCanReturn(payload, daemonAttempt.response)\n"
            "      ) {\n"
            "        cleanupPayloadReference();\n"
            "        return daemonAttempt.response;\n"
            "      }\n",
            "      if (daemonAttempt.response) {\n"
            "        cleanupPayloadReference();\n"
            "        return daemonAttempt.response;\n"
            "      }\n",
        ),
        (
            "        tool_response: toolOutput,\n",
            "        stdout: toolOutput,\n",
        ),
        (
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
            "    const response = await runGuard(\n",
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
            "    const response = await runGuard(\n",
        ),
        (
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
            "      const excerptText = typeof response.reviewed_excerpt === 'string' "
            "? response.reviewed_excerpt : '';\n"
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
            "    return blockedToolResult(modelVisibleBlockedReason(reason, response.reason_code), event.details);\n",
            "    if (response.observe_mode === true) return undefined;\n"
            "    if (outputTruncated) {\n"
            '      if (response.model_output_action === "allow_original" &&\n'
            "          typeof response.reviewed_output_sha256 === 'string' &&\n"
            "          response.reviewed_output_sha256 === digest.sha256) {\n"
            "        return undefined;\n"
            "      }\n"
            "      const notice = response.reason ||\n"
            '        "HOL Guard returned a reviewed excerpt because this output could not be fully proven safe'
            ' within local limits.";\n'
            '      if (response.notice === "excerpt"'
            ' || response.model_output_action === "replace_with_reviewed_excerpt") {\n'
            '        ctx.ui.notify(notice, "info");\n'
            "      }\n"
            "      return reviewedToolResult(reviewedContent, event.details, event.isError === true);\n"
            "    }\n"
            "    return undefined;\n",
        ),
        (
            "modelVisibleBlockedReason(reason, response.reason_code)",
            "modelVisibleBlockedReason(reason)",
        ),
    )
    for current, legacy in replacements:
        if source.count(current) != 1:
            raise RuntimeError("managed Pi extension legacy source contract drifted")
        source = source.replace(current, legacy, 1)
    return source
