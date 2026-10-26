"""Frozen v1 shared middle fragment for generated Pi-family sources."""

from __future__ import annotations


def build_source_body_shared_v1(*, display_name: str, blocked_reason_prelude: str = "") -> str:
    return (
        "  try {\n"
        "    serializedPayload = JSON.stringify(payloadToSend);\n"
        "  } catch (error) {\n"
        "    return {\n"
        '      decision: "deny",\n'
        f"      reason: `HOL Guard could not serialize {display_name} hook payload: ${{\n"
        "        error instanceof Error ? error.message : String(error)\n"
        "      }`,\n"
        "    };\n"
        "  }\n"
        "  if (\n"
        "    options?.enforceSizeCap === true &&\n"
        "    serializedPayload.length > GUARD_MAX_SERIALIZED_PAYLOAD_CHARS\n"
        "  ) {\n"
        "    const referenced = referencedPayload(payloadToSend, serializedPayload);\n"
        "    payloadToSend = referenced.payload;\n"
        "    cleanupPayloadReference = referenced.cleanup;\n"
        "    try {\n"
        "      serializedPayload = JSON.stringify(payloadToSend);\n"
        "    } catch (error) {\n"
        "      cleanupPayloadReference();\n"
        "      return {\n"
        '        decision: "deny",\n'
        f"        reason: `HOL Guard could not serialize {display_name} hook payload reference: ${{\n"
        "          error instanceof Error ? error.message : String(error)\n"
        "        }`,\n"
        "      };\n"
        "    }\n"
        "  }\n"
        "  if (\n"
        "    options?.enforceSizeCap === true &&\n"
        "    serializedPayload.length > GUARD_MAX_SERIALIZED_PAYLOAD_CHARS\n"
        "  ) {\n"
        "    cleanupPayloadReference();\n"
        "    return {\n"
        '      decision: "deny",\n'
        f'      reason: "HOL Guard blocked this {display_name} hook payload before review because it exceeded '
        '"\n'
        '        + "the safe size limit.",\n'
        "    };\n"
        "  }\n"
        "  let daemonAttempt = await daemonGuardResponse(\n"
        "    serializedPayload, cwd, GUARD_DAEMON_TIMEOUT_MS, deadlineAt,\n"
        "  );\n"
        "  if (\n"
        "    daemonAttempt.response &&\n"
        "    daemonResponseCanReturn(payload, daemonAttempt.response)\n"
        "  ) {\n"
        "    cleanupPayloadReference();\n"
        "    return daemonAttempt.response;\n"
        "  }\n"
        "  if (daemonAttempt.response) {\n"
        '    daemonAttempt = { response: null, recoveryKind: "transport-failure" };\n'
        "  }\n"
        "  if (daemonAttempt.recoveryKind !== null) {\n"
        "    const recoveryTimeoutMs = Math.min(\n"
        "      GUARD_DAEMON_RECOVERY_TIMEOUT_MS,\n"
        "      Math.max(deadlineAt - Date.now(), 1),\n"
        "    );\n"
        "    if (await recoverGuardDaemon(recoveryTimeoutMs, daemonAttempt.recoveryKind)) {\n"
        "      daemonAttempt = await daemonGuardResponse(\n"
        "        serializedPayload,\n"
        "        cwd,\n"
        "        Math.min(GUARD_DAEMON_RETRY_TIMEOUT_MS, Math.max(deadlineAt - Date.now(), 1)),\n"
        "        deadlineAt,\n"
        "      );\n"
        "      if (\n"
        "        daemonAttempt.response &&\n"
        "        daemonResponseCanReturn(payload, daemonAttempt.response)\n"
        "      ) {\n"
        "        cleanupPayloadReference();\n"
        "        return daemonAttempt.response;\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "  if (guardCliContainmentFailed) {\n"
        "    cleanupPayloadReference();\n"
        "    return {\n"
        '      decision: "deny",\n'
        '      reason: "HOL Guard cannot safely start another fallback because prior child cleanup "\n'
        '        + "was not confirmed.",\n'
        '      reason_code: "guard_cli_containment_failed",\n'
        "    };\n"
        "  }\n"
        "  if (guardCliEvaluationInFlight) {\n"
        "    cleanupPayloadReference();\n"
        "    return {\n"
        '      decision: "deny",\n'
        '      reason: "HOL Guard recovery is already reviewing another action. Retry after it completes.",\n'
        '      reason_code: "guard_cli_recovery_busy",\n'
        "    };\n"
        "  }\n"
        "  guardCliEvaluationInFlight = true;\n"
        "  let result: GuardCliResult | null = null;\n"
        "  const cliTimeoutMs = Math.min(GUARD_CLI_TIMEOUT_MS, Math.max(deadlineAt - Date.now(), 1));\n"
        "  try {\n"
        "    result = await runGuardCliCommand(\n"
        "      GUARD_CLI_WRAPPER_COMMAND,\n"
        "      GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS\n"
        "        ? [...GUARD_CLI_WRAPPER_ARGS, JSON.stringify(args)]\n"
        "        : args,\n"
        "      serializedPayload,\n"
        "      cliTimeoutMs,\n"
        "    );\n"
        "  } finally {\n"
        "    guardCliEvaluationInFlight = false;\n"
        "  }\n"
        "  cleanupPayloadReference();\n"
        "  if (result === null) {\n"
        "    return {\n"
        '      decision: "deny",\n'
        f'      reason: "HOL Guard {display_name} hook failed before completing review: '
        'Guard CLI was not found.",\n'
        "    };\n"
        "  }\n"
        "  if (result.error) {\n"
        "    const errorMessage = result.error.message;\n"
        "    const errorCode = typeof result.error.code === 'string' ? result.error.code : '';\n"
        "    if (errorCode === 'ETIMEDOUT') {\n"
        "      return {\n"
        '        decision: "deny",\n'
        f'        reason: "HOL Guard could not complete fallback review before the {display_name} '
        'deadline. Retry the action.",\n'
        '        reason_code: "guard_cli_recovery_timeout",\n'
        "      };\n"
        "    }\n"
        "    return {\n"
        '      decision: "deny",\n'
        f"      reason: `HOL Guard {display_name} hook failed before completing review: "
        "${errorMessage}`,\n"
        "    };\n"
        "  }\n"
        '  const lines = (result.stdout ?? "").split(/\\r?\\n/).map((line) => line.trim()).filter(Boolean);\n'
        "  const lastLine = lines.length > 0 ? lines[lines.length - 1] : null;\n"
        "  if (lastLine) {\n"
        "    try {\n"
        "      const parsed = JSON.parse(lastLine) as unknown;\n"
        "      const normalized = normalizeGuardResponse(parsed);\n"
        '      if (normalized !== null && (result.status === 0 || normalized.decision === "deny")) {\n'
        "        return normalized;\n"
        "      }\n"
        "    } catch {}\n"
        "  }\n"
        "  if (result.status !== 0) {\n"
        "    return {\n"
        '      decision: "deny",\n'
        '      reason: (result.stderr ?? "").trim() || "Blocked by HOL Guard.",\n'
        "    };\n"
        "  }\n"
        "  return fallbackGuardResponse(\n"
        '    "guard_cli_invalid_response",\n'
        '    "HOL Guard fallback did not return a valid decision. Retry the action.",\n'
        "  );\n"
        "}\n"
        "\n"
        "function modelVisibleBlockedReason(reason: string, reasonCode?: string): string {\n"
        + blocked_reason_prelude
        + "  if (\n"
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
        "}\n"
        "\n"
        "function blockedToolResult(reason: string, details: unknown) {\n"
        "  return {\n"
        '    content: [{ type: "text", text: reason }],\n'
        "    details,\n"
        "    isError: true,\n"
        "  };\n"
        "}\n"
        "\n"
    )
