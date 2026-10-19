"""Shared middle fragment for current generated Pi-family sources.

Unlike the frozen v1 fragment, a hook the daemon cannot answer after recovery
is denied; no Guard CLI process reviews it instead.
"""

from __future__ import annotations


def build_source_body_shared_v2(*, display_name: str, blocked_reason_prelude: str = "") -> str:
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
        "  cleanupPayloadReference();\n"
        "  // The daemon and its recovery are the only reviewers; never decide locally.\n"
        "  return fallbackGuardResponse(\n"
        '    "daemon_unavailable",\n'
        '    "HOL Guard could not reach its local review service before the deadline. Retry the action.",\n'
        "  );\n"
        "}\n"
        "\n"
        "function modelVisibleBlockedReason(reason: string, reasonCode?: string): string {\n"
        + blocked_reason_prelude
        + "  if (\n"
        '    reasonCode === "daemon_unavailable" ||\n'
        '    reasonCode === "daemon_hook_deadline_exhausted" ||\n'
        '    reasonCode === "daemon_hook_process_deadline_exhausted"\n'
        "  ) {\n"
        f'    return "HOL Guard did not finish reviewing this output before the {display_name} '
        'deadline. Retry the action.";\n'
        "  }\n"
        f'  const prefix = "HOL Guard blocked this tool output before {display_name} could use it.";\n'
        "  // The native reason can quote the blocked output, so it stays with the\n"
        "  // user notice. The reason code is Guard's own token and names the cause\n"
        "  // without carrying any of the text, which is what the agent needs to\n"
        "  // stop guessing and say something useful to the user.\n"
        "  const cause =\n"
        '    reasonCode === "output_secret_match" || reasonCode === "native_secret_exfiltration"\n'
        '      ? " The output carried credential-shaped text, which HOL Guard keeps out of the model context."\n'
        '      : reasonCode === "native_prompt_injection_review"\n'
        '        ? " The output carried instructions addressed to the agent, which the user reviews first."\n'
        "        : reasonCode && /^[a-z][a-z0-9_]{2,63}$/.test(reasonCode)\n"
        "          ? ` HOL Guard recorded this as ${reasonCode}.`\n"
        "          : '';\n"
        "  const approvalUrl = reason.match(/https?:\\/\\/\\S+/)?.[0]?.replace(/[.,;:]+$/, '');\n"
        "  const approvalHint = approvalUrl ? ` Human approval is pending in HOL Guard: ${approvalUrl}.` : '';\n"
        "  return `${prefix}${cause}${approvalHint} Do not retry the same tool call "
        "automatically; wait for the user to approve or change the task.`;\n"
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
