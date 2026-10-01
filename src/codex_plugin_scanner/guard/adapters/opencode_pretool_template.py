"""Generated OpenCode pretool entrypoint and review wiring."""

from .opencode_process_template import OPENCODE_PROCESS_TEMPLATE

_PLUGIN_TEMPLATE = (
    """// Managed by HOL Guard. Re-run `hol-guard install opencode` after moving Guard home.
import { spawn as nodeSpawn } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join as joinPath, resolve as resolvePath } from "node:path";

const GUARD_HOME = __GUARD_HOME__;
const GUARD_PYTHON = __GUARD_PYTHON__;
const GUARD_FROZEN = __GUARD_FROZEN__;
const GUARD_HOOK_LAUNCHER = __GUARD_HOOK_LAUNCHER__;
const GUARD_HOOK_ENV = __GUARD_HOOK_ENV__;
const GUARD_INHERIT_ENV_KEYS = __GUARD_INHERIT_ENV_KEYS__;
const GUARD_TASKKILL_PATH = __GUARD_TASKKILL_PATH__;
const INTERCEPT_TOOLS = new Set(__INTERCEPT_TOOLS__);
const GUARD_HOOK_TIMEOUT_MS = 30_000;
const GUARD_WINDOWS_JOB_MARKER = "HOL_GUARD_WINDOWS_JOB_CONTAINED\\n";
let fallbackInFlight = false;
let fallbackContainmentFailed = false;

const GUARD_RUNTIME_MISSING =
  "HOL Guard's OpenCode plugin cannot find the Guard runtime that generated it. " +
  "Run `hol-guard install opencode` in a host terminal outside OpenCode, then restart OpenCode.";

export function resolveGuardPythonTarget(): string {
  try {
    const invocationStat = lstatSync(GUARD_PYTHON.invocationPath, { bigint: true });
    let invocationType = "other";
    if (invocationStat.isSymbolicLink()) {
      invocationType = "symlink";
    } else if (invocationStat.isFile()) {
      invocationType = "file";
    }
    if (invocationType !== "file" && invocationType !== "symlink") {
      throw new Error("invocation is not a file");
    }
    const resolved = realpathSync(GUARD_PYTHON.invocationPath);
    const targetStat = lstatSync(resolved, { bigint: true });
    if (!targetStat.isFile() || realpathSync(resolved) !== resolved) {
      throw new Error("target is not a regular file");
    }
    // Guard updates replace the interpreter in place. Keep reviewing with the
    // same launcher path instead of blocking every OpenCode shell tool.
    return resolved;
  } catch {
    throw new Error(GUARD_RUNTIME_MISSING);
  }
}

export function verifyGuardPythonIdentity(): void {
  resolveGuardPythonTarget();
}

export function isGuardSelfRepairCommand(command: string): boolean {
  const normalized = command.trim();
  if (/[&|;`$<>()\\n]/.test(normalized)) {
    return false;
  }
  const argv = normalized.split(/\\s+/);
  const binary = argv[0] ?? "";
  const name = binary.replace(/\\\\/g, "/").split("/").pop() ?? "";
  if (name !== "hol-guard" && name !== "hol-guard.exe") {
    return false;
  }
  const rest = argv.slice(1).join(" ");
  return rest === "update" || rest === "doctor" || rest === "start" || rest === "install opencode";
}

function hookProcessEnv(guardArgv: string[]) {
  const env: Record<string, string> = { ...GUARD_HOOK_ENV };
  for (const key of GUARD_INHERIT_ENV_KEYS) {
    const value = process.env[key];
    if (typeof value === "string" && value.length > 0) {
      env[key] = value;
    }
  }
  env.__HOOK_ARGV_ENV__ = JSON.stringify(guardArgv);
  return env;
}

function normalizeCommand(command: unknown): string | null {
  if (typeof command === "string" && command.trim()) {
    return command.trim();
  }
  if (Array.isArray(command) && command.length > 0 && command.every((part) => typeof part === "string")) {
    return command.join(" ");
  }
  return null;
}

function effectiveWorkingDirectory(directory: string, workdir: unknown): string {
  // Directory names can contain spaces. Review the same path the tool uses.
  const baseDirectory = directory || process.cwd();
  if (workdir === undefined) return baseDirectory;
  if (typeof workdir !== "string") {
    throw new Error("HOL Guard could not review this command: workdir must be a string.");
  }
  let target = workdir;
  if (process.platform === "win32") {
    const drive = target.match(/^\\/(?:(?:cygdrive|mnt)\\/)?([a-zA-Z])(?:\\/|$)/)
      ?? target.match(/^\\/([a-zA-Z]):(?:[\\\\/]|$)/);
    if (drive) target = `${drive[1].toUpperCase()}:/${target.slice(drive[0].length)}`;
  }
  if (target === "~") {
    target = homedir();
  } else if (target.startsWith("~/") || (process.platform === "win32" && target.startsWith("~\\\\"))) {
    target = joinPath(homedir(), target.slice(2));
  }
  return resolvePath(baseDirectory, target);
}

"""
    + OPENCODE_PROCESS_TEMPLATE
    + """async function runGuardHook(
  workspace: string,
  payload: Record<string, unknown>,
  deadlineMs: number,
) {
  const guardArgv = [
    ...(GUARD_FROZEN ? [] : ["guard"]),
    "hook",
    "--guard-home",
    GUARD_HOME,
    "--harness",
    "opencode",
    "--workspace",
    workspace,
    "--json",
  ];
  return spawnGuardProcess({
    args: GUARD_FROZEN ? guardArgv : ["-I", "-S", "-s", "-c", GUARD_HOOK_LAUNCHER],
    cwd: GUARD_HOME,
    deadlineMs,
    env: hookProcessEnv(guardArgv),
    stdin: JSON.stringify(payload),
  });
}

function parseGuardPayload(stdout: string): Record<string, unknown> | null {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return null;
  }
  const parseCandidate = (candidate: string): Record<string, unknown> | null => {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {}
    return null;
  };
  const direct = parseCandidate(trimmed);
  if (direct !== null) {
    return direct;
  }
  const lines = trimmed.split(/\\r?\\n/);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const candidate = lines[index]?.trim();
    if (!candidate) {
      continue;
    }
    const parsed = parseCandidate(candidate);
    if (parsed !== null) {
      return parsed;
    }
  }
  return null;
}

function guardReviewUrl(payload: Record<string, unknown>): string | null {
  const primary = typeof payload.primary_approval_url === "string" ? payload.primary_approval_url.trim() : "";
  if (primary) {
    return primary;
  }
  const reviewUrl = typeof payload.review_url === "string" ? payload.review_url.trim() : "";
  if (reviewUrl) {
    return reviewUrl;
  }
  const queued = payload.approval_requests;
  if (Array.isArray(queued)) {
    for (const item of queued) {
      if (!item || typeof item !== "object") {
        continue;
      }
      const approvalUrl = (item as { approval_url?: unknown }).approval_url;
      if (typeof approvalUrl === "string" && approvalUrl.trim()) {
        return approvalUrl.trim().replace(/\\/approvals\\//g, "/requests/");
      }
    }
  }
  const center = typeof payload.approval_center_url === "string" ? payload.approval_center_url.trim() : "";
  return center || null;
}

export function guardBlockMessage(stdout: string, stderr: string): string {
  const payload = parseGuardPayload(stdout);
  if (payload === null) {
    return stderr.trim() || "HOL Guard blocked this OpenCode action.";
  }
  const decision = payload.decision_v2_json;
  const decisionPayload =
    decision && typeof decision === "object"
      ? (decision as { harness_message?: unknown; retry_instruction?: unknown })
      : null;
  const reviewHint = typeof payload.review_hint === "string" ? payload.review_hint.trim() : "";
  const retryInstruction =
    typeof decisionPayload?.retry_instruction === "string" ? decisionPayload.retry_instruction.trim() : "";
  const harnessMessage =
    typeof decisionPayload?.harness_message === "string" ? decisionPayload.harness_message.trim() : "";
  const baseMessage =
    reviewHint ||
    retryInstruction ||
    harnessMessage ||
    stderr.trim() ||
    "HOL Guard blocked this OpenCode action.";
  const reviewUrl = guardReviewUrl(payload);
  if (!reviewUrl || baseMessage.includes(reviewUrl)) {
    return baseMessage;
  }
  return (
    `${baseMessage} Open HOL Guard to approve or keep this blocked: ${reviewUrl}. `
    + "After you choose, retry the same OpenCode action."
  );
}

export const HolGuardPretoolPlugin = async ({
  directory,
}: {
  directory: string;
}) => {
  return {
    "tool.execute.before": async (
      input: { tool: string },
      output: { args: Record<string, unknown> },
    ) => {
      if (!INTERCEPT_TOOLS.has(input.tool)) {
        return;
      }
      const command = normalizeCommand(output.args?.command);
      if (command === null) {
        return;
      }
      const workspace = effectiveWorkingDirectory(directory, output.args?.workdir);
      const deadlineMs = Date.now() + GUARD_HOOK_TIMEOUT_MS;
      let result;
      try {
        result = await runGuardHook(
          directory || process.cwd(),
          {
            hook_event_name: "PreToolUse",
            event: "PreToolUse",
            tool_name: input.tool,
            tool_input: { command, workdir: workspace },
            cwd: workspace,
            workspace_root: directory || process.cwd(),
            source_scope: directory?.trim() ? "project" : "global",
          },
          deadlineMs,
        );
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (detail.includes(GUARD_RUNTIME_MISSING) && isGuardSelfRepairCommand(command)) {
          return;
        }
        throw new Error(
          `HOL Guard could not review this ${input.tool} command (${detail}). ` +
            "Run `hol-guard install opencode` in a host terminal outside OpenCode, then restart OpenCode.",
        );
      }
      if (result.exitCode === 0) {
        return;
      }
      if (result.exitCode === 1) {
        throw new Error(guardBlockMessage(result.stdout, result.stderr));
      }
      throw new Error(
        result.stderr.trim() ||
          `HOL Guard hook failed while reviewing this ${input.tool} command.`,
      );
    },
  };
};

"""
)
