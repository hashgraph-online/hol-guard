"""Static middle section for the generated Pi-family extension source."""

from __future__ import annotations

from .pi_extension_approval_source import APPROVAL_RESUME_HELPERS_SOURCE
from .pi_extension_source_body_shared_v1 import build_source_body_shared_v1

_STRUCTURED_BLOCKED_REASON_PRELUDE = (
    '  if (reasonCode === "structured_review_deadline_exceeded") {\n'
    '    return "HOL Guard withheld this structured tool output because its review deadline expired. '
    'Retry the action.";\n'
    "  }\n"
    '  if (reasonCode === "structured_review_cancelled") {\n'
    '    return "HOL Guard withheld this structured tool output because its review was cancelled. '
    'Ask the user to resume or change the task.";\n'
    "  }\n"
    '  if (reasonCode?.startsWith("structured_")) {\n'
    '    return "HOL Guard withheld this structured tool output because it could not be validated '
    'for this destination. Ask the user to review the output or change the task.";\n'
    "  }\n"
)


def build_extension_source_body(*, harness: str, display_name: str) -> str:
    # The shared approval source is frozen for previous-extension matching.
    # Only current extensions opt out of reusing a retiring daemon socket.
    approval_helpers = APPROVAL_RESUME_HELPERS_SOURCE.replace(
        "headers: { 'X-Guard-Token': connection.authToken },",
        "headers: { 'X-Guard-Token': connection.authToken, 'Connection': 'close' },",
        1,
    )
    return (
        "type GuardDaemonConnection = { port: number; "
        "authToken: string; stateId: string | null };\n"
        "type GuardDaemonAttempt = {\n"
        "  response: GuardResponse | null;\n"
        "  recoveryKind: GuardDaemonRecoveryKind | null;\n"
        "};\n"
        "\n"
        "function validStructuredContentMediation(value: unknown): StructuredContentMediation | null {\n"
        '  if (!value || typeof value !== "object" || Array.isArray(value)) return null;\n'
        "  const parsed = value as Record<string, unknown>;\n"
        '  if (parsed.schema !== "guard-structured-content-mediation.v1") return null;\n'
        '  if (parsed.action !== "forward" && parsed.action !== "withhold") return null;\n'
        '  if (typeof parsed.reason_code !== "string" || '
        "!/^structured_[a-z0-9_]+$/.test(parsed.reason_code)) return null;\n"
        "  if (parsed.native_decision_id !== undefined && "
        '(typeof parsed.native_decision_id !== "string" || '
        "!/^[A-Za-z0-9_.:-]{1,256}$/.test(parsed.native_decision_id))) return null;\n"
        '  if (parsed.action === "forward") {\n'
        '    if (typeof parsed.native_decision_id !== "string" || '
        'typeof parsed.content_sha256 !== "string") return null;\n'
        "    if (!/^[0-9a-f]{64}$/.test(parsed.content_sha256)) return null;\n"
        '    if (Object.keys(parsed).some((key) => !["schema", "action", '
        '"reason_code", "native_decision_id", "content_sha256"].includes(key))) return null;\n'
        "  } else {\n"
        "    if (parsed.content_sha256 !== undefined) return null;\n"
        '    if (Object.keys(parsed).some((key) => !["schema", "action", '
        '"reason_code", "native_decision_id"].includes(key))) return null;\n'
        "  }\n"
        "  return parsed as StructuredContentMediation;\n"
        "}\n"
        "\n"
        "function normalizeGuardResponse(value: unknown): GuardResponse | null {\n"
        '  if (!value || typeof value !== "object" || Array.isArray(value)) return null;\n'
        "  const parsed = value as Record<string, unknown>;\n"
        "  if (parsed.reason !== undefined && parsed.reason !== null && "
        'typeof parsed.reason !== "string") return null;\n'
        "  if (parsed.structured_content_mediation !== undefined && "
        "validStructuredContentMediation(parsed.structured_content_mediation) === null) return null;\n"
        '  if (parsed.decision === "allow" || parsed.decision === "deny") {\n'
        "    return parsed as GuardResponse;\n"
        "  }\n"
        '  if (parsed.decision === "block") {\n'
        '    return { ...parsed, decision: "deny" } as GuardResponse;\n'
        "  }\n"
        "  return null;\n"
        "}\n"
        "\n"
        "function fallbackGuardResponse(\n"
        "  reasonCode: string,\n"
        "  reason: string,\n"
        "): GuardResponse {\n"
        '  return { decision: "deny", reason, reason_code: reasonCode };\n'
        "}\n"
        "\n"
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
        "}\n"
        "\n"
        "function loadGuardDaemonConnection(): GuardDaemonConnection | null {\n"
        "  let port = 0;\n"
        "  let authToken = '';\n"
        "  let stateId: string | null = null;\n"
        "  try {\n"
        "    const daemonState = JSON.parse(\n"
        "      readFileSync(join(GUARD_HOME, 'daemon-state.json'), 'utf8'),\n"
        "    ) as { compatibility_version?: unknown; package_version?: unknown; port?: unknown; state_id?: unknown };\n"
        "    // Prefer protocol compatibility over exact package version. Exact package pins\n"
        "    // go stale after hol-guard update and force a cold CLI fallback that times out.\n"
        "    if (daemonState.compatibility_version !== GUARD_COMPATIBILITY_VERSION) return null;\n"
        "    port = typeof daemonState.port === 'number' ? daemonState.port : 0;\n"
        "    stateId = typeof daemonState.state_id === 'string' && "
        "/^[A-Za-z0-9_-]{1,256}$/.test(daemonState.state_id)\n"
        "      ? daemonState.state_id\n"
        "      : null;\n"
        "    authToken = readFileSync(join(GUARD_HOME, 'daemon-auth-token'), 'utf8').trim();\n"
        "  } catch {\n"
        "    return null;\n"
        "  }\n"
        "  if (!(port > 0) || authToken.length === 0) return null;\n"
        "  return { port, authToken, stateId };\n"
        "}\n"
        "\n"
        "async function daemonGuardResponse(\n"
        "  serializedPayload: string,\n"
        "  cwd?: string,\n"
        "  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,\n"
        "  deadlineAt?: number,\n"
        "): Promise<GuardDaemonAttempt> {\n"
        '  if (typeof fetch !== "function") {\n'
        '    return { response: null, recoveryKind: "transport-failure" };\n'
        "  }\n"
        "  const connection = loadGuardDaemonConnection();\n"
        '  if (!connection) return { response: null, recoveryKind: "transport-failure" };\n'
        '  const workspace = typeof cwd === "string" && cwd ? cwd : process.cwd();\n'
        "  const params = new URLSearchParams({ 'guard-home': GUARD_HOME });\n"
        "  if (workspace) params.set('workspace', workspace);\n"
        "  if (!GUARD_HOME_DIR_IS_DEFAULT && GUARD_HOME_DIR) params.set('home', GUARD_HOME_DIR);\n"
        "  const controller = typeof AbortController === 'function' ? new AbortController() : undefined;\n"
        "  const timeoutHandle = setTimeout(() => controller?.abort(), timeoutMs);\n"
        "  try {\n"
        "    let daemonPayload = serializedPayload;\n"
        "    try {\n"
        "      const parsedPayload = JSON.parse(serializedPayload) as Record<string, unknown>;\n"
        "      const remainingMs = deadlineAt === undefined ? timeoutMs : deadlineAt - Date.now();\n"
        "      parsedPayload.guard_remaining_ms = Math.min(60_000, Math.max(1, Math.min(timeoutMs, remainingMs)));\n"
        "      daemonPayload = JSON.stringify(parsedPayload);\n"
        "    } catch {}\n"
        f"    const response = await fetch(`http://127.0.0.1:${{connection.port}}"
        f"/v1/hooks/{harness}?${{params.toString()}}`, {{\n"
        "      method: 'POST',\n"
        "      headers: {\n"
        "        'Content-Type': 'application/json',\n"
        "        'X-Guard-Token': connection.authToken,\n"
        "        // The local daemon closes each response; never reuse a retiring socket.\n"
        "        'Connection': 'close',\n"
        "      },\n"
        "      body: daemonPayload,\n"
        "      signal: controller?.signal,\n"
        "    });\n"
        "    if (!response.ok) {\n"
        "      let reasonCode = `daemon_http_${response.status}`;\n"
        "      try {\n"
        "        const errorBody = await boundedResponseText(response, GUARD_TEXT_LIMIT_CHARS, deadlineAt);\n"
        "        if (errorBody === null) {\n"
        '          reasonCode = "daemon_response_body_unbounded";\n'
        "        } else {\n"
        "          const errorPayload = JSON.parse(errorBody) as { error?: unknown };\n"
        "          if (typeof errorPayload.error === 'string' && errorPayload.error) {\n"
        "            reasonCode = errorPayload.error;\n"
        "          }\n"
        "        }\n"
        "      } catch {}\n"
        "      if (response.status === 401 || response.status === 403) {\n"
        "        return {\n"
        "          response: null,\n"
        '          recoveryKind: "authenticated-control-plane-failure",\n'
        "        };\n"
        "      }\n"
        "      return {\n"
        "        response: {\n"
        '          decision: "deny",\n'
        "          reason: `HOL Guard could not safely review this action (${reasonCode}).`,\n"
        "          reason_code: reasonCode,\n"
        "        },\n"
        "        recoveryKind: null,\n"
        "      };\n"
        "    }\n"
        "    const rawResponse = await boundedResponseText(\n"
        "      response, GUARD_MAX_SERIALIZED_RESPONSE_CHARS, deadlineAt,\n"
        "    );\n"
        '    if (rawResponse === null) return { response: null, recoveryKind: "transport-failure" };\n'
        "    const raw = rawResponse.trim();\n"
        '    if (!raw) return { response: null, recoveryKind: "transport-failure" };\n'
        "    try {\n"
        "      const parsed = JSON.parse(raw) as unknown;\n"
        "      const normalized = normalizeGuardResponse(parsed);\n"
        "      if (normalized !== null) {\n"
        "        return { response: normalized, recoveryKind: null };\n"
        "      }\n"
        '      return { response: null, recoveryKind: "transport-failure" };\n'
        "    } catch {}\n"
        "    return {\n"
        "      response: {\n"
        '        decision: "deny",\n'
        '        reason: "HOL Guard received an invalid response from the authenticated local daemon.",\n'
        '        reason_code: "daemon_invalid_response",\n'
        "      },\n"
        "      recoveryKind: null,\n"
        "    };\n"
        "  } catch (error) {\n"
        "    if (error instanceof Error && error.name === 'AbortError') {\n"
        "      // Classified transport recovery preserves a live overloaded daemon.\n"
        '      return { response: null, recoveryKind: "transport-failure" };\n'
        "    }\n"
        '    return { response: null, recoveryKind: "transport-failure" };\n'
        "  } finally {\n"
        "    clearTimeout(timeoutHandle);\n"
        "  }\n"
        "}\n"
        "\n"
        "const GUARD_DAEMON_READINESS_TIMEOUT_MS = 26_000;\n"
        "const GUARD_DAEMON_READINESS_RESPONSE_RESERVE_MS = 1_000;\n"
        "\n"
        "async function daemonWorkspaceReadiness(cwd) {\n"
        "  const deadlineAt = Date.now() + GUARD_DAEMON_READINESS_TIMEOUT_MS;\n"
        '  if (typeof fetch !== "function") {\n'
        '    return { ready: false, reasonCode: "daemon_readiness_transport_failure" };\n'
        "  }\n"
        "  let connection = loadGuardDaemonConnection();\n"
        "  if (connection === null || connection.stateId === null) {\n"
        "    let recovered = false;\n"
        "    try {\n"
        "      recovered = await recoverGuardDaemon(\n"
        "        Math.max(deadlineAt - Date.now(), 1),\n"
        '        "authenticated-control-plane-failure",\n'
        "      );\n"
        "    } catch {}\n"
        '    if (!recovered) return { ready: false, reasonCode: "daemon_readiness_transport_failure" };\n'
        "    connection = loadGuardDaemonConnection();\n"
        "  }\n"
        '  if (!connection) return { ready: false, reasonCode: "daemon_readiness_transport_failure" };\n'
        '  if (connection.stateId === null) return { ready: false, reasonCode: "daemon_identity_unavailable" };\n'
        "  const readinessStateId = connection.stateId;\n"
        '  const workspace = typeof cwd === "string" && cwd ? cwd : process.cwd();\n'
        "  const params = new URLSearchParams({ 'guard-home': GUARD_HOME, workspace });\n"
        "  if (!GUARD_HOME_DIR_IS_DEFAULT && GUARD_HOME_DIR) params.set('home', GUARD_HOME_DIR);\n"
        "  const controller = typeof AbortController === 'function' ? new AbortController() : undefined;\n"
        "  const timeoutMs = Math.max(deadlineAt - GUARD_DAEMON_READINESS_RESPONSE_RESERVE_MS - Date.now(), 1);\n"
        "  const timeoutHandle = setTimeout(() => controller?.abort(), timeoutMs);\n"
        "  try {\n"
        f"    const response = await fetch(`http://127.0.0.1:${{connection.port}}"
        f"/v1/hooks/{harness}/readiness?${{params.toString()}}`, {{\n"
        "      method: 'POST',\n"
        "      headers: {\n"
        "        'X-Guard-Token': connection.authToken,\n"
        "        'Connection': 'close',\n"
        "      },\n"
        "      signal: controller?.signal,\n"
        "    });\n"
        "    let readiness = {};\n"
        "    try {\n"
        "      const raw = await boundedResponseText(response, GUARD_TEXT_LIMIT_CHARS, deadlineAt);\n"
        "      const parsed = raw === null ? null : JSON.parse(raw) as unknown;\n"
        "      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {\n"
        "        readiness = parsed as Record<string, unknown>;\n"
        "      }\n"
        "    } catch {}\n"
        "    const reasonCode = typeof readiness.reason_code === 'string' &&\n"
        "      /^[a-z0-9_]{1,96}$/.test(readiness.reason_code)\n"
        "      ? readiness.reason_code\n"
        "      : `daemon_readiness_http_${response.status}`;\n"
        "    if (!response.ok || readiness.ready !== true) {\n"
        "      return { ready: false, reasonCode, daemonStateId: readinessStateId };\n"
        "    }\n"
        "    if (readiness.native_required === true &&\n"
        "      (readiness.native_route !== 'native_resident' ||\n"
        "        readiness.workspace_acknowledged !== true || readiness.worker_ready !== true)) {\n"
        '      return { ready: false, reasonCode: "native_readiness_unconfirmed", daemonStateId: readinessStateId };\n'
        "    }\n"
        "    return { ready: true, daemonStateId: connection.stateId };\n"
        "  } catch {\n"
        '    return { ready: false, reasonCode: "daemon_readiness_transport_failure", '
        "daemonStateId: readinessStateId };\n"
        "  } finally {\n"
        "    clearTimeout(timeoutHandle);\n"
        "  }\n"
        "}\n"
        "\n"
        "async function runGuard(\n"
        "  payload: Record<string, unknown>,\n"
        "  cwd?: string,\n"
        "  options?: { enforceSizeCap?: boolean; deadlineAt?: number },\n"
        "): Promise<GuardResponse> {\n"
        "  const deadlineAt = options?.deadlineAt ?? Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS;\n"
        "  const args = [...GUARD_ARGS];\n"
        '  const workspace = typeof cwd === "string" && cwd ? cwd : process.cwd();\n'
        '  if (workspace) args.push("--workspace", workspace);\n'
        "  const activeEnvironment = Object.create(null);\n"
        "  for (const [name, value] of Object.entries(process.env)) {\n"
        "    if (typeof value === 'string' && value.length > 0) activeEnvironment[name] = value;\n"
        "  }\n"
        "  const environmentNames = Object.keys(activeEnvironment).sort();\n"
        "  const canonicalEnvironment = JSON.stringify(\n"
        "    Object.fromEntries(environmentNames.map((name) => [name, activeEnvironment[name]])),\n"
        "  )?.replace(/[^\\x00-\\x7F]/g, (character) =>\n"
        "    `\\\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`,\n"
        "  ) ?? '';\n"
        "  let payloadToSend = {\n"
        "    ...payload,\n"
        "    guard_execution_environment: {\n"
        "      path: typeof process.env.PATH === 'string' ? process.env.PATH : '',\n"
        "      environment_names: environmentNames,\n"
        "      environment_digest: createHash('sha256').update(canonicalEnvironment, 'utf8').digest('hex'),\n"
        "      xdg_config_home: typeof process.env.XDG_CONFIG_HOME === 'string' &&\n"
        "        process.env.XDG_CONFIG_HOME.length > 0\n"
        "        ? process.env.XDG_CONFIG_HOME\n"
        "        : null,\n"
        "      git_config_no_system: typeof process.env.GIT_CONFIG_NOSYSTEM === 'string' &&\n"
        "        ['1', 'true', 'yes', 'on'].includes(process.env.GIT_CONFIG_NOSYSTEM.toLowerCase()),\n"
        "      home: typeof process.env.HOME === 'string' ? process.env.HOME : null,\n"
        "      git_pager_disabled: process.env.GIT_PAGER === '' || process.env.GIT_PAGER === 'cat',\n"
        "      pager_disabled: process.env.PAGER === '' || process.env.PAGER === 'cat',\n"
        "    },\n"
        "  };\n"
        "  let serializedPayload = '';\n"
        "  let cleanupPayloadReference = () => {};\n"
        "  if (\n"
        "    options?.enforceSizeCap === true &&\n"
        "    !payloadWithinSerializedBudget(payloadToSend, deadlineAt)\n"
        "  ) {\n"
        "    return {\n"
        '      decision: "deny",\n'
        '      reason: "HOL Guard withheld this hook payload before review '
        'because its size or shape could not be bounded safely.",\n'
        '      reason_code: "hook_payload_unbounded",\n'
        "    };\n"
        "  }\n"
        + build_source_body_shared_v1(
            display_name=display_name, blocked_reason_prelude=_STRUCTURED_BLOCKED_REASON_PRELUDE
        )
        + "function reviewedToolResult(content: unknown, details: unknown, isError?: boolean, deadlineAt?: number) {\n"
        "  let body = '';\n"
        "  if (Array.isArray(content)) {\n"
        "    body = boundedOutputText(content, deadlineAt).value as string;\n"
        "  } else if (typeof content === 'string') {\n"
        "    body = content;\n"
        "  } else if (content !== undefined && content !== null) {\n"
        "    try { body = JSON.stringify(content); } catch {}\n"
        "  }\n"
        "  const result = {\n"
        '    content: body.length > 0 ? [{ type: "text", text: body }] : [],\n'
        "    details,\n"
        "  } as { content: unknown[]; details: unknown; isError?: boolean };\n"
        "  if (isError) result.isError = true;\n"
        "  return result;\n"
        "}\n"
        "\n" + approval_helpers + "export default function (pi: ExtensionAPI) {\n"  # pyright: ignore[reportImplicitStringConcatenation]
        "  const blockedToolResults = new Map<string, string>();\n"
        "  type InputApprovalResumeBinding = {\n"
        "    generation: number;\n"
        "    sessionId: string;\n"
        "    cwd: string;\n"
        "  };\n"
        "  const pendingApprovalResumes = new Map<string, InputApprovalResumeBinding>();\n"
        "  const openedApprovalUrls = new Set<string>();\n"
        "  let approvalContinuationGeneration = 0;\n"
        "  let inputApprovalResumeGeneration = 0;\n"
        "  const invalidateToolApprovalContinuations = () => { approvalContinuationGeneration += 1; };\n"
        "  const invalidateInputApprovalResumes = () => { inputApprovalResumeGeneration += 1; };\n"
        "  const invalidateApprovalContinuations = () => {\n"
        "    invalidateToolApprovalContinuations();\n"
        "    invalidateInputApprovalResumes();\n"
        "  };\n"
        "  let workspaceReadiness = null;\n"
        "  const ensureGuardWorkspaceReady = (cwd, allowSetup = true) => {\n"
        "    const workspace = typeof cwd === 'string' && cwd ? cwd : process.cwd();\n"
        "    if (workspaceReadiness?.cwd === workspace) {\n"
        "      const currentConnection = loadGuardDaemonConnection();\n"
        "      if (workspaceReadiness.daemonStateId === null && !workspaceReadiness.settled) {\n"
        "        return workspaceReadiness.result;\n"
        "      }\n"
        "      if (workspaceReadiness.daemonStateId !== null &&\n"
        "        currentConnection?.stateId === workspaceReadiness.daemonStateId) {\n"
        "        return workspaceReadiness.result;\n"
        "      }\n"
        "      if (!allowSetup) {\n"
        '        return Promise.resolve({ ready: false, reasonCode: "daemon_restarted_requires_session_setup" });\n'
        "      }\n"
        "      workspaceReadiness = null;\n"
        "    }\n"
        "    if (!allowSetup) {\n"
        '      return Promise.resolve({ ready: false, reasonCode: "native_workspace_setup_required" });\n'
        "    }\n"
        "    const daemonStateId = loadGuardDaemonConnection()?.stateId ?? null;\n"
        "    const result = daemonWorkspaceReadiness(workspace);\n"
        "    const readinessEntry = { cwd: workspace, result, daemonStateId, settled: false };\n"
        "    workspaceReadiness = readinessEntry;\n"
        "    void result.then((readiness) => {\n"
        "      readinessEntry.settled = true;\n"
        "      if (workspaceReadiness === readinessEntry && typeof readiness.daemonStateId === 'string') {\n"
        "        readinessEntry.daemonStateId = readiness.daemonStateId;\n"
        "      }\n"
        "    }).catch(() => { readinessEntry.settled = true; });\n"
        "    return result;\n"
        "  };\n"
        "  const prepareGuardWorkspaceForTurn = async (cwd) => {\n"
        "    workspaceReadiness = null;\n"
        "    return ensureGuardWorkspaceReady(cwd, true);\n"
        "  };\n"
        "  const readinessFailureReason = (readiness) =>\n"
        "    `HOL Guard blocked this tool call because native workspace readiness was not confirmed "
        '(${readiness.reasonCode ?? "native_workspace_not_ready"}).`;\n'
        "  const approvalContinuationActivity = (): ApprovalContinuationActivity => {\n"
        "    const generation = approvalContinuationGeneration;\n"
        "    return () => generation === approvalContinuationGeneration;\n"
        "  };\n"
        "  const captureInputApprovalResumeBinding = (ctx: unknown): InputApprovalResumeBinding | null => {\n"
        "    const sessionId = contextSessionId(ctx);\n"
        "    const cwd = contextCwd(ctx);\n"
        "    if (!sessionId || !cwd) return null;\n"
        "    return { generation: inputApprovalResumeGeneration, sessionId, cwd };\n"
        "  };\n"
        "  const inputApprovalResumeBindingIsActive = (\n"
        "    ctx: unknown,\n"
        "    binding: InputApprovalResumeBinding | null,\n"
        "  ): boolean =>\n"
        "    binding !== null &&\n"
        "    binding.generation === inputApprovalResumeGeneration &&\n"
        "    contextSessionId(ctx) === binding.sessionId &&\n"
        "    contextCwd(ctx) === binding.cwd;\n"
        '  pi.on("agent_start", async (_event, ctx) => {\n'
        "    invalidateApprovalContinuations();\n"
        "    const readiness = await prepareGuardWorkspaceForTurn(contextCwd(ctx) ?? process.cwd());\n"
        '    if (!readiness.ready) ctx.ui.notify(readinessFailureReason(readiness), "warning");\n'
        "  });\n"
        '  pi.on("agent_end", () => { invalidateToolApprovalContinuations(); });\n'
        '  pi.on("session_start", async (_event, ctx) => {\n'
        "    invalidateApprovalContinuations();\n"
        "    const readiness = await prepareGuardWorkspaceForTurn(contextCwd(ctx) ?? process.cwd());\n"
        '    if (!readiness.ready) ctx.ui.notify(readinessFailureReason(readiness), "warning");\n'
        "  });\n"
        '  pi.on("session_shutdown", () => { invalidateApprovalContinuations(); workspaceReadiness = null; });\n'
    )
