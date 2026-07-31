"""Generated Pi managed extension source."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from ..codex_hook_windows_job import windows_system_executable_path
from ..daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from .pi_extension_approval_source import APPROVAL_RESUME_HELPERS_SOURCE
from .pi_extension_cli_runtime_source import CLI_RUNTIME_HELPERS_SOURCE
from .pi_extension_content_source import CONTENT_REVIEW_HELPERS_SOURCE

# Pi terminates extension hooks at roughly 4.5 seconds. Keep Guard's daemon and
# recovery/fallback paths below that host deadline so a fail-safe result returns.
GUARD_HOOK_TIMEOUT_MS = 4_250
GUARD_HOOK_DEADLINE_RESERVE_MS = 250
GUARD_DAEMON_HOOK_TIMEOUT_MS = 1_700
GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250
GUARD_DAEMON_RETRY_TIMEOUT_MS = 150
GUARD_CLI_HOOK_TIMEOUT_MS = 1_400
GUARD_HOOK_TEXT_LIMIT_CHARS = 12_000
GUARD_HOOK_CONTENT_ITEM_LIMIT = 24
GUARD_HOOK_OBJECT_KEY_LIMIT = 24
GUARD_HOOK_MAX_DEPTH = 24
GUARD_HOOK_MAX_SERIALIZED_PAYLOAD_CHARS = 24_000


def managed_extension_source(*, guard_home: Path, home_dir: Path, settings_path: Path) -> str:
    guard_args = ["hook", "--json", "--guard-home", str(guard_home), "--harness", "pi"]
    if home_dir.resolve() != Path.home().resolve():
        guard_args.extend(["--home", str(home_dir)])
    guard_args_json = json.dumps(guard_args)
    guard_home_json = json.dumps(str(guard_home))
    home_dir_json = json.dumps(str(home_dir))
    home_dir_is_default_json = "true" if home_dir.resolve() == Path.home().resolve() else "false"
    config_path_json = json.dumps(str(settings_path))
    compatibility_version_json = json.dumps(GUARD_DAEMON_COMPATIBILITY_VERSION)
    package_root = Path(__file__).resolve().parents[3]
    cli_wrapper_bootstrap = (
        "import json,os,sys;"
        f"sys.path.insert(0,{str(package_root)!r});"
        "from codex_plugin_scanner.guard.codex_hook_windows_job import "
        "assign_current_process_to_windows_hook_job;"
        "_windows_job=assign_current_process_to_windows_hook_job() if os.name=='nt' else None;"
        "sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;"
        "sys.stderr.flush() if _windows_job is not None else None;"
        "from pathlib import Path;"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import run_bounded_cli_hook;"
        "argv=json.loads(sys.argv[1]);"
        "config={'python_executable':sys.executable,"
        f"'package_root':{str(package_root)!r},"
        f"'guard_home':{str(guard_home)!r},"
        "'cli_args':argv,'harness':'pi','timeout_seconds':0.75};"
        "raise SystemExit(run_bounded_cli_hook(config,input_text=sys.stdin.read(1000001)))"
    )
    cli_wrapper_command_json = json.dumps(str(Path(sys.executable).expanduser().absolute()))
    cli_wrapper_args_json = json.dumps(["-I", "-c", cli_wrapper_bootstrap])
    recovery_bootstrap = (
        "import os,sys;"
        f"sys.path.insert(0,{str(package_root)!r});"
        "from codex_plugin_scanner.guard.codex_hook_windows_job import "
        "assign_current_process_to_windows_hook_job;"
        "_windows_job=assign_current_process_to_windows_hook_job(allow_breakaway=True) if os.name=='nt' else None;"
        "sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;"
        "sys.stderr.flush() if _windows_job is not None else None;"
        "from pathlib import Path;"
        "from codex_plugin_scanner.guard.daemon import schedule_guard_daemon_recovery;"
        f"schedule_guard_daemon_recovery(Path({str(guard_home)!r}),"
        f"home_dir=Path({str(home_dir)!r}),failure_kind=sys.argv[1])"
    )
    recovery_command_json = json.dumps(str(Path(sys.executable).expanduser().absolute()))
    recovery_args_json = json.dumps(["-I", "-c", recovery_bootstrap])
    try:
        taskkill_path = windows_system_executable_path("taskkill.exe") if os.name == "nt" else None
    except (OSError, ValueError):
        taskkill_path = None
    taskkill_path_json = json.dumps(taskkill_path)
    return (
        'import { spawn } from "node:child_process";\n'
        + 'import { createCipheriv, createHash, randomBytes } from "node:crypto";\n'  # pyright: ignore[reportImplicitStringConcatenation]
        'import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";\n'
        'import { tmpdir } from "node:os";\n'
        'import { join } from "node:path";\n'
        'import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";\n'
        "\n"
        f"const GUARD_CLI_WRAPPER_COMMAND = {cli_wrapper_command_json};\n"
        f"const GUARD_CLI_WRAPPER_ARGS = {cli_wrapper_args_json};\n"
        f"const GUARD_DAEMON_RECOVERY_COMMAND = {recovery_command_json};\n"
        f"const GUARD_DAEMON_RECOVERY_ARGS = {recovery_args_json};\n"
        f"const GUARD_TASKKILL_PATH = {taskkill_path_json};\n"
        f"const GUARD_ARGS = {guard_args_json};\n"
        f"const GUARD_HOME = {guard_home_json};\n"
        f"const GUARD_HOME_DIR = {home_dir_json};\n"
        f"const GUARD_HOME_DIR_IS_DEFAULT = {home_dir_is_default_json};\n"
        f"const GUARD_CONFIG_PATH = {config_path_json};\n"
        f"const GUARD_COMPATIBILITY_VERSION = {compatibility_version_json};\n"
        f"const GUARD_TIMEOUT_MS = {GUARD_HOOK_TIMEOUT_MS};\n"
        f"const GUARD_DEADLINE_RESERVE_MS = {GUARD_HOOK_DEADLINE_RESERVE_MS};\n"
        f"const GUARD_DAEMON_TIMEOUT_MS = {GUARD_DAEMON_HOOK_TIMEOUT_MS};\n"
        f"const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = {GUARD_DAEMON_RECOVERY_TIMEOUT_MS};\n"
        f"const GUARD_DAEMON_RETRY_TIMEOUT_MS = {GUARD_DAEMON_RETRY_TIMEOUT_MS};\n"
        f"const GUARD_CLI_TIMEOUT_MS = {GUARD_CLI_HOOK_TIMEOUT_MS};\n"
        f"const GUARD_TEXT_LIMIT_CHARS = {GUARD_HOOK_TEXT_LIMIT_CHARS};\n"
        f"const GUARD_CONTENT_ITEM_LIMIT = {GUARD_HOOK_CONTENT_ITEM_LIMIT};\n"
        f"const GUARD_OBJECT_KEY_LIMIT = {GUARD_HOOK_OBJECT_KEY_LIMIT};\n"
        f"const GUARD_MAX_DEPTH = {GUARD_HOOK_MAX_DEPTH};\n"
        f"const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = {GUARD_HOOK_MAX_SERIALIZED_PAYLOAD_CHARS};\n"
        "const GUARD_APPROVAL_RESUME_POLL_INTERVAL_MS = 2_000;\n"
        "const GUARD_APPROVAL_RESUME_FETCH_TIMEOUT_MS = 1_500;\n"
        "const GUARD_APPROVAL_RESUME_MAX_WAIT_MS = 10 * 60 * 1_000;\n"
        "const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;\n"
        "const GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES = new Set([\n"
        '  "read", "read_file", "open_file", "view", "view_file", "cat_file", "Read", "View"\n'
        "]);\n"
        "\n"
        "type GuardResponse = {\n"
        "  decision?: string;\n"
        "  reason?: string;\n"
        "  approval_request_id?: string;\n"
        "  approval_url?: string;\n"
        "  approval_center_url?: string;\n"
        "  resume_poll_path?: string;\n"
        '  model_output_action?: "allow_original" | "replace_with_reviewed_excerpt" | "block" | "not_applicable";\n'
        "  reviewed_output_sha256?: string;\n"
        "  observed_policy_action?: string;\n"
        "  observe_mode?: boolean;\n"
        '  notice?: "none" | "excerpt" | "warning";\n'
        "  reason_code?: string;\n"
        "};\n"
        + CLI_RUNTIME_HELPERS_SOURCE
        + CONTENT_REVIEW_HELPERS_SOURCE
        + "type GuardDaemonConnection = { port: number; authToken: string };\n"
        + "type GuardDaemonAttempt = {\n"  # pyright: ignore[reportImplicitStringConcatenation]
        "  response: GuardResponse | null;\n"
        "  recoveryKind: GuardDaemonRecoveryKind | null;\n"
        "  transientOverload?: { retryAfterMs: number; estimatedServiceMs: number };\n"
        "};\n"
        "\n"
        "function loadGuardDaemonConnection(): GuardDaemonConnection | null {\n"
        "  let port = 0;\n"
        "  let authToken = '';\n"
        "  try {\n"
        "    const daemonState = JSON.parse(\n"
        "      readFileSync(join(GUARD_HOME, 'daemon-state.json'), 'utf8'),\n"
        "    ) as { compatibility_version?: unknown; package_version?: unknown; port?: unknown };\n"
        "    // Prefer protocol compatibility over exact package version. Exact package pins\n"
        "    // go stale after hol-guard update and force a cold CLI fallback that times out.\n"
        "    if (daemonState.compatibility_version !== GUARD_COMPATIBILITY_VERSION) return null;\n"
        "    port = typeof daemonState.port === 'number' ? daemonState.port : 0;\n"
        "    authToken = readFileSync(join(GUARD_HOME, 'daemon-auth-token'), 'utf8').trim();\n"
        "  } catch {\n"
        "    return null;\n"
        "  }\n"
        "  if (!(port > 0) || authToken.length === 0) return null;\n"
        "  return { port, authToken };\n"
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
        "    const response = await fetch(`http://127.0.0.1:${connection.port}/v1/hooks/pi?${params.toString()}`, {\n"
        "      method: 'POST',\n"
        "      headers: {\n"
        "        'Content-Type': 'application/json',\n"
        "        'X-Guard-Token': connection.authToken,\n"
        "      },\n"
        "      body: daemonPayload,\n"
        "      signal: controller?.signal,\n"
        "    });\n"
        "    if (!response.ok) {\n"
        "      let reasonCode = `daemon_http_${response.status}`;\n"
        "      try {\n"
        "        const errorPayload = JSON.parse((await response.text()).slice(0, GUARD_TEXT_LIMIT_CHARS)) as {\n"
        "          error?: unknown;\n"
        "          reason_code?: unknown;\n"
        "          retry_after_ms?: unknown;\n"
        "          estimated_service_ms?: unknown;\n"
        "        };\n"
        "        if (errorPayload.reason_code === 'transient_overload') {\n"
        "          const retryAfterMs = typeof errorPayload.retry_after_ms === 'number'\n"
        "            ? Math.min(75, Math.max(25, Math.floor(errorPayload.retry_after_ms))) : 25;\n"
        "          const estimatedServiceMs = typeof errorPayload.estimated_service_ms === 'number'\n"
        "            ? Math.min(2800, Math.max(100, Math.floor(errorPayload.estimated_service_ms))) : 750;\n"
        "          return {\n"
        "            response: null,\n"
        "            recoveryKind: null,\n"
        "            transientOverload: { retryAfterMs, estimatedServiceMs },\n"
        "          };\n"
        "        }\n"
        "        if (typeof errorPayload.error === 'string' && errorPayload.error) {\n"
        "          reasonCode = errorPayload.error;\n"
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
        "    const raw = (await response.text()).trim();\n"
        "    if (!raw) return { response: {}, recoveryKind: null };\n"
        "    try {\n"
        "      const parsed = JSON.parse(raw) as GuardResponse;\n"
        "      if (parsed && typeof parsed === 'object') {\n"
        "        return { response: parsed, recoveryKind: null };\n"
        "      }\n"
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
        "      // A request timeout does not prove the live daemon is unhealthy. Preserve the\n"
        "      // remaining host deadline for fail-safe review instead of restarting it.\n"
        "      return { response: null, recoveryKind: null };\n"
        "    }\n"
        '    return { response: null, recoveryKind: "transport-failure" };\n'
        "  } finally {\n"
        "    clearTimeout(timeoutHandle);\n"
        "  }\n"
        "}\n"
        "\n"
        "async function runGuard(\n"
        "  payload: Record<string, unknown>,\n"
        "  cwd?: string,\n"
        "  options?: { enforceSizeCap?: boolean },\n"
        "): Promise<GuardResponse> {\n"
        "  const deadlineAt = Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS;\n"
        "  const args = [...GUARD_ARGS];\n"
        '  const workspace = typeof cwd === "string" && cwd ? cwd : process.cwd();\n'
        '  if (workspace) args.push("--workspace", workspace);\n'
        "  let payloadToSend = payload;\n"
        "  let serializedPayload = '';\n"
        "  let cleanupPayloadReference = () => {};\n"
        "  try {\n"
        "    serializedPayload = JSON.stringify(payloadToSend);\n"
        "  } catch (error) {\n"
        "    return {\n"
        '      decision: "deny",\n'
        "      reason: `HOL Guard could not serialize Pi hook payload: ${\n"
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
        "        reason: `HOL Guard could not serialize Pi hook payload reference: ${\n"
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
        '      reason: "HOL Guard blocked this Pi hook payload before review because it exceeded "\n'
        '        + "the safe size limit.",\n'
        "    };\n"
        "  }\n"
        "  let daemonAttempt = await daemonGuardResponse(\n"
        "    serializedPayload, cwd, GUARD_DAEMON_TIMEOUT_MS, deadlineAt,\n"
        "  );\n"
        "  if (daemonAttempt.transientOverload) {\n"
        "    const jitterMs = Math.max(\n"
        "      daemonAttempt.transientOverload.retryAfterMs,\n"
        "      25 + Math.floor(Math.random() * 51),\n"
        "    );\n"
        "    const requiredMs = jitterMs + daemonAttempt.transientOverload.estimatedServiceMs + 100;\n"
        "    if (deadlineAt - Date.now() >= requiredMs) {\n"
        "      await new Promise((resolve) => setTimeout(resolve, jitterMs));\n"
        "      daemonAttempt = await daemonGuardResponse(\n"
        "        serializedPayload,\n"
        "        cwd,\n"
        "        Math.max(deadlineAt - Date.now(), 1),\n"
        "        deadlineAt,\n"
        "      );\n"
        "    }\n"
        "    if (daemonAttempt.transientOverload) {\n"
        "      cleanupPayloadReference();\n"
        "      return {\n"
        '        decision: "deny",\n'
        '        reason: "HOL Guard is temporarily saturated and kept this action blocked. "\n'
        '          + "No approval was requested; retry the action.",\n'
        '        reason_code: "transient_overload",\n'
        "      };\n"
        "    }\n"
        "  }\n"
        "  if (daemonAttempt.response) {\n"
        "    cleanupPayloadReference();\n"
        "    return daemonAttempt.response;\n"
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
        "      if (daemonAttempt.response) {\n"
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
        "      [...GUARD_CLI_WRAPPER_ARGS, JSON.stringify(args)],\n"
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
        '      reason: "HOL Guard Pi hook failed before completing review: Guard CLI was not found.",\n'
        "    };\n"
        "  }\n"
        "  if (result.error) {\n"
        "    const errorMessage = result.error.message;\n"
        "    const errorCode = typeof result.error.code === 'string' ? result.error.code : '';\n"
        "    if (errorCode === 'ETIMEDOUT') {\n"
        "      return {\n"
        '        decision: "deny",\n'
        '        reason: "HOL Guard could not complete fallback review before the Pi deadline. Retry the action.",\n'
        '        reason_code: "guard_cli_recovery_timeout",\n'
        "      };\n"
        "    }\n"
        "    return {\n"
        '      decision: "deny",\n'
        "      reason: `HOL Guard Pi hook failed before completing review: ${errorMessage}`,\n"
        "    };\n"
        "  }\n"
        '  const lines = (result.stdout ?? "").split(/\\r?\\n/).map((line) => line.trim()).filter(Boolean);\n'
        "  const lastLine = lines.length > 0 ? lines[lines.length - 1] : null;\n"
        "  if (lastLine) {\n"
        "    try {\n"
        "      const parsed = JSON.parse(lastLine) as GuardResponse;\n"
        '      if (parsed && typeof parsed === "object") return parsed;\n'
        "    } catch {}\n"
        "  }\n"
        "  if ((result.status ?? 0) !== 0) {\n"
        "    return {\n"
        '      decision: "deny",\n'
        '      reason: (result.stderr ?? "").trim() || "Blocked by HOL Guard.",\n'
        "    };\n"
        "  }\n"
        '  return { decision: "allow" };\n'
        "}\n"
        "\n"
        "function modelVisibleBlockedReason(reason: string): string {\n"
        '  const prefix = "HOL Guard blocked this tool output before Pi could use it.";\n'
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
        "function reviewedToolResult(content: unknown, details: unknown, isError?: boolean) {\n"
        "  let body = '';\n"
        "  if (Array.isArray(content)) {\n"
        "    body = boundedOutputText(content).value as string;\n"
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
        "\n" + APPROVAL_RESUME_HELPERS_SOURCE + "export default function (pi: ExtensionAPI) {\n"  # pyright: ignore[reportImplicitStringConcatenation]
        "  const blockedToolResults = new Map<string, string>();\n"
        "  const pendingApprovalResumes = new Set<string>();\n"
        "  const openedApprovalCenters = new Set<string>();\n"
        "  function scheduleApprovalResume(\n"
        "    response: GuardResponse,\n"
        "    ctx: { ui: { notify(message: string, kind?: 'info' | 'warning'): void } },\n"
        "    details: { kind: 'input' | 'tool_call'; prompt?: string; toolName?: string },\n"
        "  ): void {\n"
        "    const requestId = approvalRequestId(response);\n"
        "    if (!requestId || pendingApprovalResumes.has(requestId)) return;\n"
        "    pendingApprovalResumes.add(requestId);\n"
        "    if (details.kind === 'input') void openApprovalUrl(response, openedApprovalCenters);\n"
        "    const pollPath = approvalPollPath(response, requestId);\n"
        "    void (async () => {\n"
        "      try {\n"
        "        const action = await pollApprovalResolution(requestId, pollPath);\n"
        "        if (action === 'allow') {\n"
        "          pi.sendMessage(\n"
        "            {\n"
        "              customType: 'hol_guard_approval_resume',\n"
        "              content: approvalResumeMessage({ ...details, requestId }),\n"
        "              display: false,\n"
        "              details: { requestId, approvalUrl: response.approval_url ?? null },\n"
        "              attribution: 'agent',\n"
        "            },\n"
        "            { triggerTurn: true, deliverAs: 'nextTurn' },\n"
        "          );\n"
        "          ctx.ui.notify('HOL Guard approved this request. Pi is continuing the task.', 'info');\n"
        "        } else if (action === 'block') {\n"
        "          ctx.ui.notify('HOL Guard kept this request blocked. Pi will not retry it.', 'warning');\n"
        "        }\n"
        "      } finally {\n"
        "        pendingApprovalResumes.delete(requestId);\n"
        "      }\n"
        "    })();\n"
        "  }\n"
        '  pi.on("input", async (event, ctx) => {\n'
        '    if (event.source === "extension") return { action: "continue" };\n'
        "    const response = await runGuard(\n"
        '      { hook_event_name: "UserPromptSubmit", prompt: event.text, config_path: GUARD_CONFIG_PATH },\n'
        "      ctx.cwd,\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      const reason = approvalBlockedReason(response, response.reason ?? "Blocked by HOL Guard.");\n'
        "      scheduleApprovalResume(response, ctx, { kind: 'input', prompt: event.text });\n"
        '      ctx.ui.notify(reason, "warning");\n'
        '      return { action: "handled", handled: true };\n'
        "    }\n"
        '    if (response.notice === "warning" && typeof response.reason === "string" && response.reason) {\n'
        '      ctx.ui.notify(response.reason, "warning");\n'
        "    }\n"
        '    return { action: "continue" };\n'
        "  });\n"
        '  pi.on("tool_call", async (event, ctx) => {\n'
        "    const toolInput =\n"
        "      (event as { input?: Record<string, unknown> }).input ??\n"
        "      (event as { toolInput?: Record<string, unknown> }).toolInput ??\n"
        "      (event as { arguments?: Record<string, unknown> }).arguments ??\n"
        "      {};\n"
        "    const response = await runGuard(\n"
        "      {\n"
        '        hook_event_name: "PreToolUse",\n'
        "        config_path: GUARD_CONFIG_PATH,\n"
        "        tool_call_id: event.toolCallId,\n"
        "        tool_name: event.toolName,\n"
        "        tool_input: toolInput,\n"
        "      },\n"
        "      ctx.cwd,\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      const reason = approvalBlockedReason(response, response.reason ?? "Blocked by HOL Guard.");\n'
        "      scheduleApprovalResume(response, ctx, { kind: 'tool_call', toolName: event.toolName });\n"
        '      ctx.ui.notify(reason, "warning");\n'
        "      return { block: true, reason };\n"
        "    }\n"
        '    if (response.notice === "warning" && typeof response.reason === "string" && response.reason) {\n'
        '      ctx.ui.notify(response.reason, "warning");\n'
        "    }\n"
        "    return undefined;\n"
        "  });\n"
        '  pi.on("message_end", async (event) => {\n'
        '    if (event.message.role !== "toolResult") return;\n'
        "    const toolCallId = toolCallIdKey(event.message.toolCallId);\n"
        "    if (!toolCallId) return;\n"
        "    const reason = blockedToolResults.get(toolCallId);\n"
        "    if (!reason) return;\n"
        "    blockedToolResults.delete(toolCallId);\n"
        "    return {\n"
        "      message: {\n"
        "        ...event.message,\n"
        '        content: [{ type: "text", text: reason }],\n'
        "        isError: true,\n"
        "      },\n"
        "    };\n"
        "  });\n"
        '  pi.on("tool_result", async (event, ctx) => {\n'
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
        "        stdout: toolOutput,\n"
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
        "      const modelReason = modelVisibleBlockedReason(reason);\n"
        "      const toolCallId = toolCallIdKey(event.toolCallId);\n"
        "      if (toolCallId) blockedToolResults.set(toolCallId, modelReason);\n"
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(modelReason, event.details);\n"
        "    }\n"
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
        "    return undefined;\n"
        "  });\n"
        "}\n"
    )
