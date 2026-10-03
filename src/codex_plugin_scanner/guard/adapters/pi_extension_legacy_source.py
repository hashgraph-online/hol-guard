from .pi_extension_source import Path, managed_extension_source
from .pi_extension_source_body import _STRUCTURED_BLOCKED_REASON_PRELUDE


def legacy_managed_extension_source(
    *,
    guard_home: Path,
    home_dir: Path,
    settings_path: Path,
    harness: str = "pi",
    display_name: str = "Pi",
) -> str:
    """Reconstruct the exact pre-response-contract extension for migration only."""

    source = managed_extension_source(
        guard_home=guard_home,
        home_dir=home_dir,
        settings_path=settings_path,
        harness=harness,
        display_name=display_name,
    )

    # Environment attestation was added after the frozen migration snapshot.
    stamp_start = source.find("  const activeEnvironment = Object.create(null);\n")
    stamp_end = source.find("  let serializedPayload = '';\n", stamp_start)
    if stamp_start < 0 or stamp_end < 0:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source[:stamp_start] + "  let payloadToSend = payload;\n" + source[stamp_end:]
    source = source.replace(
        "!payloadWithinSerializedBudget(payloadToSend, deadlineAt)",
        "!payloadWithinSerializedBudget(payload, deadlineAt)",
        1,
    )

    reference_environment = (
        "    ...(Object.prototype.hasOwnProperty.call(payload, 'guard_execution_environment')\n"
        "      ? { guard_execution_environment: payload.guard_execution_environment }\n"
        "      : {}),\n"
    )
    if source.count(reference_environment) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(reference_environment, "", 1)

    # The legacy source is a frozen migration artifact.  Remove additions from
    # the current managed source before applying the historical compatibility
    # substitutions below so the old byte contract remains exact.
    if source.count(_STRUCTURED_BLOCKED_REASON_PRELUDE) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(_STRUCTURED_BLOCKED_REASON_PRELUDE, "", 1)

    structured_constants = (
        "const GUARD_STRUCTURED_MAX_BYTES = 64 * 1024;\n"
        "const GUARD_STRUCTURED_MAX_DEPTH = 8;\n"
        "const GUARD_STRUCTURED_MAX_NODES = 128;\n"
        "const GUARD_STRUCTURED_MAX_FIELDS = 64;\n"
    )
    if source.count(structured_constants) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(structured_constants, "", 1)

    response_cap = (
        "// Python JSON responses can escape one astral character as two Unicode escapes.\n"
        "const GUARD_MAX_SERIALIZED_RESPONSE_CHARS =\n"
        "  12 * GUARD_TEXT_LIMIT_CHARS + GUARD_MAX_SERIALIZED_PAYLOAD_CHARS;\n"
    )
    if source.count(response_cap) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(response_cap, "", 1)

    reference_structured = (
        "    ...(typeof payload.structured_output_json === 'string'\n"
        "      ? { structured_output_json: payload.structured_output_json }\n"
        "      : {}),\n"
    )
    if source.count(reference_structured) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(reference_structured, "", 1)

    structured_type_start = source.find("  structured_content_mediation?: StructuredContentMediation;\n")
    structured_type_end = source.find("type GuardCliResult =", structured_type_start)
    if structured_type_start < 0 or structured_type_end < 0:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source[:structured_type_start] + "};\n\n" + source[structured_type_end:]

    valid_structured_start = source.find("function validStructuredContentMediation(")
    normalize_start = source.find("function normalizeGuardResponse(", valid_structured_start)
    if valid_structured_start < 0 or normalize_start < 0:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source[:valid_structured_start] + source[normalize_start:]

    normalize_structured_line = (
        "  if (parsed.structured_content_mediation !== undefined && "
        "validStructuredContentMediation(parsed.structured_content_mediation) === null) return null;\n"
    )
    if source.count(normalize_structured_line) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(normalize_structured_line, "", 1)

    structured_helper_start = source.find("function structuredOutputJsonForPostToolUse(")
    source_path_start = source.find("function sourcePathFromToolInput(", structured_helper_start)
    if structured_helper_start < 0 or source_path_start < 0:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source[:structured_helper_start] + source[source_path_start:]

    bounded_preprocessing_start = source.find("/* HOL Guard bounded preprocessing begins */\n")
    bounded_preprocessing_end = source.find("/* HOL Guard bounded preprocessing ends */\n", bounded_preprocessing_start)
    if bounded_preprocessing_start < 0 or bounded_preprocessing_end < 0:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    bounded_preprocessing_end += len("/* HOL Guard bounded preprocessing ends */\n")
    if source[bounded_preprocessing_end : bounded_preprocessing_end + 1] == "\n":
        bounded_preprocessing_end += 1
    source = source[:bounded_preprocessing_start] + source[bounded_preprocessing_end:]
    for current_name, legacy_name in (
        ("function legacyDigestOutputText(", "function digestOutputText("),
        ("function legacyBoundValue(", "function boundValue("),
        ("function legacyBoundedOutputText(", "function boundedOutputText("),
    ):
        if source.count(current_name) != 1:
            raise RuntimeError("managed Pi extension legacy source contract drifted")
        source = source.replace(current_name, legacy_name, 1)
    if source.count("legacyBoundValue(") != 2:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace("legacyBoundValue(", "boundValue(")

    tool_result_prelude = (
        "    const hookDeadlineAt = Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS;\n"
        "    const signal = handlerAbortSignal(ctx);\n"
    )
    if source.count(tool_result_prelude) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(tool_result_prelude, "", 1)

    reviewed_tool_result_current = (
        "function reviewedToolResult(content: unknown, details: unknown, isError?: boolean, deadlineAt?: number) {\n"
        "  let body = '';\n"
        "  if (Array.isArray(content)) {\n"
        "    body = boundedOutputText(content, deadlineAt).value as string;\n"
    )
    reviewed_tool_result_legacy = (
        "function reviewedToolResult(content: unknown, details: unknown, isError?: boolean) {\n"
        "  let body = '';\n"
        "  if (Array.isArray(content)) {\n"
        "    body = boundedOutputText(content).value as string;\n"
    )
    if source.count(reviewed_tool_result_current) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(reviewed_tool_result_current, reviewed_tool_result_legacy, 1)

    bounded_preprocessing_calls = (
        "    const preprocessBudget = createTraversalBudget(hookDeadlineAt);\n"
        "    const digest = digestOutputText(event.content, hookDeadlineAt, preprocessBudget);\n"
        "    const boundedContent = boundValue(event.content, 0, new WeakSet(), preprocessBudget);\n"
        "    const boundedStdout = boundedOutputText(event.content, hookDeadlineAt, preprocessBudget);\n"
    )
    legacy_preprocessing_calls = (
        "    const digest = digestOutputText(event.content);\n"
        "    const boundedContent = boundValue(event.content);\n"
        "    const boundedStdout = boundedOutputText(event.content);\n"
    )
    if source.count(bounded_preprocessing_calls) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(bounded_preprocessing_calls, legacy_preprocessing_calls, 1)

    structured_payload_lines = (
        "    // OMP's current ExtensionContext has no lifecycle signal. A managed\n"
        "    // structured destination therefore stays fail-closed there unless the\n"
        "    // host supplies the feature-detected signal used by the tool-call path.\n"
        "    const structuredOutputJson = signal === undefined\n"
        "      ? null\n"
        "      : structuredOutputJsonForPostToolUse(event.content, hookDeadlineAt);\n"
        "    if (structuredOutputJson !== null) guardPayload.structured_output_json = structuredOutputJson;\n"
    )
    if source.count(structured_payload_lines) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(structured_payload_lines, "", 1)

    run_guard_deadline_options = "      { enforceSizeCap: true, deadlineAt: hookDeadlineAt },\n"
    if source.count(run_guard_deadline_options) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(run_guard_deadline_options, "      { enforceSizeCap: true },\n", 1)

    post_tool_cancellation = (
        "    if (signal?.aborted || Date.now() >= hookDeadlineAt) {\n"
        '      const reason = "HOL Guard withheld this tool output because its review lifecycle "\n'
        '        + "was cancelled or exceeded its deadline.";\n'
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(\n"
        "        `${reason} Resume the task to review the output again.`, event.details);\n"
        "    }\n"
    )
    if source.count(post_tool_cancellation) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(post_tool_cancellation, "", 1)

    structured_mediation_start = source.find("    const structuredMediation = response.structured_content_mediation;\n")
    original_output_start = source.find("    const originalOutputProof =", structured_mediation_start)
    if structured_mediation_start < 0 or original_output_start < 0:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = (
        source[:structured_mediation_start]
        + "    if (response.observe_mode === true) return undefined;\n"
        + source[original_output_start:]
    )

    run_guard_options_line = "  options?: { enforceSizeCap?: boolean; deadlineAt?: number },\n"
    if source.count(run_guard_options_line) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(run_guard_options_line, "  options?: { enforceSizeCap?: boolean },\n", 1)
    run_guard_deadline_line = (
        "  const deadlineAt = options?.deadlineAt ?? Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS;\n"
    )
    if source.count(run_guard_deadline_line) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(
        run_guard_deadline_line,
        "  const deadlineAt = Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS;\n",
        1,
    )

    payload_preflight = (
        "  if (\n"
        "    options?.enforceSizeCap === true &&\n"
        "    !payloadWithinSerializedBudget(payload, deadlineAt)\n"
        "  ) {\n"
        "    return {\n"
        '      decision: "deny",\n'
        '      reason: "HOL Guard withheld this hook payload before review '
        'because its size or shape could not be bounded safely.",\n'
        '      reason_code: "hook_payload_unbounded",\n'
        "    };\n"
        "  }\n"
    )
    if source.count(payload_preflight) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(payload_preflight, "", 1)

    bounded_error_body = (
        "        const errorBody = await boundedResponseText(response, GUARD_TEXT_LIMIT_CHARS, deadlineAt);\n"
        "        if (errorBody === null) {\n"
        '          reasonCode = "daemon_response_body_unbounded";\n'
        "        } else {\n"
        "          const errorPayload = JSON.parse(errorBody) as { error?: unknown };\n"
        "          if (typeof errorPayload.error === 'string' && errorPayload.error) {\n"
        "            reasonCode = errorPayload.error;\n"
        "          }\n"
        "        }\n"
    )
    legacy_error_body = (
        "        const errorPayload = JSON.parse((await response.text()).slice(0, GUARD_TEXT_LIMIT_CHARS)) as {\n"
        "          error?: unknown;\n"
        "        };\n"
        "        if (typeof errorPayload.error === 'string' && errorPayload.error) {\n"
        "          reasonCode = errorPayload.error;\n"
        "        }\n"
    )
    if source.count(bounded_error_body) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(bounded_error_body, legacy_error_body, 1)

    bounded_success_body = (
        "    const rawResponse = await boundedResponseText(\n"
        "      response, GUARD_MAX_SERIALIZED_RESPONSE_CHARS, deadlineAt,\n"
        "    );\n"
        '    if (rawResponse === null) return { response: null, recoveryKind: "transport-failure" };\n'
        "    const raw = rawResponse.trim();\n"
    )
    legacy_success_body = "    const raw = (await response.text()).trim();\n"
    if source.count(bounded_success_body) != 1:
        raise RuntimeError("managed Pi extension legacy source contract drifted")
    source = source.replace(bounded_success_body, legacy_success_body, 1)

    replacements = (
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
