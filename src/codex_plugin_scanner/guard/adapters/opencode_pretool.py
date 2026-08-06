"""OpenCode pretool plugin generation for HOL Guard runtime interception."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..codex_hook_windows_job import windows_system_executable_path
from .base import HarnessContext
from .hook_python import (
    HookPythonExecutableIdentity,
    HookPythonFileMetadata,
    attest_guard_hook_python,
)

PLUGIN_FILENAME = "hol-guard-pretool.ts"
_INTERCEPT_TOOLS = ("bash", "ctx_shell", "shell", "sh", "zsh", "terminal")
_HOOK_ARGV_ENV = "HOL_GUARD_HOOK_ARGV"
_INHERIT_ENV_KEYS = ("PATH", "HOME", "USER", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SYSTEMROOT")

_PLUGIN_TEMPLATE = """// Managed by HOL Guard. Re-run `hol-guard install opencode` after moving Guard home.
import { createHash } from "node:crypto";
import { spawn as nodeSpawn } from "node:child_process";
import { lstatSync, readFileSync, readlinkSync, realpathSync } from "node:fs";

const GUARD_HOME = __GUARD_HOME__;
const GUARD_PYTHON = __GUARD_PYTHON__;
const GUARD_HOOK_LAUNCHER = __GUARD_HOOK_LAUNCHER__;
const GUARD_HOOK_ENV = __GUARD_HOOK_ENV__;
const GUARD_INHERIT_ENV_KEYS = __GUARD_INHERIT_ENV_KEYS__;
const GUARD_TASKKILL_PATH = __GUARD_TASKKILL_PATH__;
const INTERCEPT_TOOLS = new Set(__INTERCEPT_TOOLS__);
const GUARD_HOOK_TIMEOUT_MS = 30_000;
const GUARD_WINDOWS_JOB_MARKER = "HOL_GUARD_WINDOWS_JOB_CONTAINED\\n";
type GuardStderrMarkerState = {
  pending: string;
  contained: boolean;
};

function consumeGuardStderrChunk(
  state: GuardStderrMarkerState,
  chunk: string,
  flush: boolean,
): string {
  state.pending += chunk;
  if (state.pending.includes(GUARD_WINDOWS_JOB_MARKER)) {
    state.contained = true;
    state.pending = state.pending.replaceAll(GUARD_WINDOWS_JOB_MARKER, "");
  }
  const retainedChars = flush
    ? 0
    : Math.min(state.pending.length, GUARD_WINDOWS_JOB_MARKER.length - 1);
  const emitted = state.pending.slice(0, state.pending.length - retainedChars);
  state.pending = state.pending.slice(state.pending.length - retainedChars);
  return emitted;
}
let fallbackInFlight = false;
let fallbackContainmentFailed = false;

type GuardFileMetadata = {
  device: string;
  inode: string;
  mode: string;
  size: string;
  mtimeNs: string;
};

function metadataMatches(
  actual: { dev: bigint; ino: bigint; mode: bigint; size: bigint; mtimeNs: bigint },
  expected: GuardFileMetadata,
): boolean {
  return (
    actual.dev.toString() === expected.device &&
    actual.ino.toString() === expected.inode &&
    actual.mode.toString() === expected.mode &&
    actual.size.toString() === expected.size &&
    actual.mtimeNs.toString() === expected.mtimeNs
  );
}

export function verifyGuardPythonIdentity(): void {
  try {
    const invocationStat = lstatSync(GUARD_PYTHON.invocationPath, { bigint: true });
    let invocationType = "other";
    if (invocationStat.isSymbolicLink()) {
      invocationType = "symlink";
    } else if (invocationStat.isFile()) {
      invocationType = "file";
    }
    if (
      invocationType !== GUARD_PYTHON.invocationType ||
      !metadataMatches(invocationStat, GUARD_PYTHON.invocationStat)
    ) {
      throw new Error("invocation metadata changed");
    }
    const linkTarget = invocationStat.isSymbolicLink() ? readlinkSync(GUARD_PYTHON.invocationPath) : null;
    if (linkTarget !== GUARD_PYTHON.invocationLinkTarget) {
      throw new Error("invocation link changed");
    }
    if (realpathSync(GUARD_PYTHON.invocationPath) !== GUARD_PYTHON.targetPath) {
      throw new Error("resolved target changed");
    }
    const targetStat = lstatSync(GUARD_PYTHON.targetPath, { bigint: true });
    if (
      !targetStat.isFile() ||
      realpathSync(GUARD_PYTHON.targetPath) !== GUARD_PYTHON.targetPath ||
      !metadataMatches(targetStat, GUARD_PYTHON.targetStat)
    ) {
      throw new Error("target metadata changed");
    }
    const digest = createHash("sha256").update(readFileSync(GUARD_PYTHON.targetPath)).digest("hex");
    if (digest !== GUARD_PYTHON.targetSha256) {
      throw new Error("target content changed");
    }
  } catch {
    throw new Error(
      "HOL Guard Python changed after this OpenCode plugin was generated. " +
        "Re-run `hol-guard install opencode` before retrying.",
    );
  }
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

function waitForGuardProcessExit(
  proc: ReturnType<typeof nodeSpawn>,
  timeoutMs: number,
): Promise<boolean> {
  if (proc.exitCode !== null || proc.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (exited: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      resolve(exited);
    };
    const watchdog = setTimeout(
      () => finish(proc.exitCode !== null || proc.signalCode !== null),
      timeoutMs,
    );
    proc.once("exit", () => finish(true));
  });
}

function guardProcessErrorCode(error: unknown): string | null {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string"
  ) ? error.code : null;
}

function guardProcessGroupExited(processGroupId: number): boolean {
  try {
    process.kill(-processGroupId, 0);
    return false;
  } catch (error) {
    return guardProcessErrorCode(error) === "ESRCH";
  }
}

async function waitForGuardProcessGroupExit(
  processGroupId: number,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (guardProcessGroupExited(processGroupId)) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return guardProcessGroupExited(processGroupId);
}

async function terminateGuardProcessGroup(
  proc: ReturnType<typeof nodeSpawn>,
  windowsJobContained: boolean,
): Promise<boolean> {
  try {
    const processGroupId = proc.pid;
    if (
      process.platform === "win32" &&
      windowsJobContained &&
      (proc.exitCode !== null || proc.signalCode !== null)
    ) return true;
    if (process.platform === "win32" && typeof processGroupId === "number") {
      if (GUARD_TASKKILL_PATH !== null) {
        const treeKilled = await new Promise<boolean>((resolve) => {
          let taskkill: ReturnType<typeof nodeSpawn>;
          try {
            taskkill = nodeSpawn(
              GUARD_TASKKILL_PATH,
              ["/PID", String(processGroupId), "/T", "/F"],
              { stdio: "ignore", windowsHide: true },
            );
          } catch {
            resolve(false);
            return;
          }
          let settled = false;
          const finish = (killed: boolean) => {
            if (settled) return;
            settled = true;
            clearTimeout(watchdog);
            resolve(killed);
          };
          const watchdog = setTimeout(() => {
            try {
              taskkill.kill("SIGKILL");
            } catch {}
            finish(false);
          }, 200);
          taskkill.once("error", () => finish(false));
          taskkill.once("close", (status) => finish(status === 0));
        });
        if (!treeKilled) {
          try {
            proc.kill("SIGKILL");
          } catch {}
          const parentExited = await waitForGuardProcessExit(proc, 200);
          return windowsJobContained && parentExited;
        }
        return waitForGuardProcessExit(proc, 200);
      }
      try {
        proc.kill("SIGKILL");
      } catch {}
      await waitForGuardProcessExit(proc, 200);
      return false;
    }
    try {
      if (process.platform === "win32") {
        proc.kill("SIGTERM");
      } else if (typeof processGroupId === "number") {
        process.kill(-processGroupId, "SIGTERM");
      }
    } catch {}
    await waitForGuardProcessExit(proc, 100);
    try {
      if (process.platform === "win32") {
        proc.kill("SIGKILL");
      } else if (typeof processGroupId === "number") {
        // The direct parent may have exited while descendants still hold hook pipes.
        process.kill(-processGroupId, "SIGKILL");
      }
    } catch {}
    const parentExited = await waitForGuardProcessExit(proc, 200);
    const groupExited =
      process.platform === "win32" ||
      (typeof processGroupId === "number" && await waitForGuardProcessGroupExit(processGroupId, 200));
    return parentExited && groupExited;
  } catch {
    return false;
  }
}

export async function spawnGuardProcess(options: {
  args: string[];
  cwd: string;
  deadlineMs: number;
  env: Record<string, string>;
  stdin: string;
}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    if (fallbackContainmentFailed) {
      reject(new Error("HOL Guard fallback containment previously failed"));
      return;
    }
    if (fallbackInFlight) {
      reject(new Error("HOL Guard fallback review is already in progress"));
      return;
    }
    const remainingMs = options.deadlineMs - Date.now();
    if (remainingMs <= 0) {
      reject(new Error("HOL Guard fallback review deadline expired"));
      return;
    }
    fallbackInFlight = true;
    let settled = false;
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (
      outcome:
        | { kind: "resolve"; value: { exitCode: number; stdout: string; stderr: string } }
        | { kind: "reject"; error: unknown },
    ) => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      fallbackInFlight = false;
      if (outcome.kind === "resolve") {
        resolve(outcome.value);
      } else {
        reject(outcome.error);
      }
    };
    try {
      verifyGuardPythonIdentity();
    } catch (error) {
      finish({ kind: "reject", error });
      return;
    }
    let proc: ReturnType<typeof nodeSpawn>;
    try {
      proc = nodeSpawn(GUARD_PYTHON.targetPath, options.args, {
        cwd: options.cwd,
        detached: process.platform !== "win32",
        env: options.env,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (error) {
      finish({ kind: "reject", error });
      return;
    }
    let stdout = "";
    let stderr = "";
    let windowsJobContained = false;
    const stderrMarkerState: GuardStderrMarkerState = { pending: "", contained: false };
    proc.stdout?.setEncoding("utf8");
    proc.stderr?.setEncoding("utf8");
    proc.stdout?.on("data", (chunk: string) => {
      stdout += chunk;
    });
    proc.stderr?.on("data", (chunk: string) => {
      stderr += consumeGuardStderrChunk(stderrMarkerState, chunk, false);
      windowsJobContained = stderrMarkerState.contained;
    });
    proc.on("error", (error) => {
      if (timedOut) return;
      finish({ kind: "reject", error });
    });
    proc.on("close", (code: number | null) => {
      if (timedOut) return;
      stderr += consumeGuardStderrChunk(stderrMarkerState, "", true);
      finish({ kind: "resolve", value: { exitCode: code ?? 1, stdout, stderr } });
    });
    timer = setTimeout(() => {
      timedOut = true;
      const containmentFailure = () => {
        fallbackContainmentFailed = true;
        finish({
          kind: "reject",
          error: new Error("HOL Guard fallback containment could not be confirmed"),
        });
      };
      void terminateGuardProcessGroup(proc, windowsJobContained).then(
        (terminated) => {
          if (!terminated) {
            containmentFailure();
            return;
          }
          finish({ kind: "reject", error: new Error("HOL Guard fallback review timed out") });
        },
        containmentFailure,
      );
    }, remainingMs);
    timer.unref();
    proc.stdin?.on("error", () => {});
    proc.stdin?.end(options.stdin);
  });
}

async function runGuardHook(
  directory: string,
  payload: Record<string, unknown>,
  deadlineMs: number,
) {
  const workspace = directory?.trim() || process.cwd();
  const guardedPayload = {
    ...payload,
    guard_remaining_ms: Math.min(60_000, Math.max(1, deadlineMs - Date.now())),
  };
  const guardArgv = [
    "guard",
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
    args: ["-I", "-S", "-s", "-c", GUARD_HOOK_LAUNCHER],
    cwd: GUARD_HOME,
    deadlineMs,
    env: hookProcessEnv(guardArgv),
    stdin: JSON.stringify(guardedPayload),
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
      const workspace = directory?.trim() || process.cwd();
      const deadlineMs = Date.now() + GUARD_HOOK_TIMEOUT_MS;
      let result;
      try {
        result = await runGuardHook(
          directory,
          {
            hook_event_name: "PreToolUse",
            event: "PreToolUse",
            tool_name: input.tool,
            tool_input: { command },
            cwd: workspace,
            source_scope: directory?.trim() ? "project" : "global",
          },
          deadlineMs,
        );
        const firstPayload = parseGuardPayload(result.stdout);
        if (firstPayload?.reason_code === "transient_overload") {
          const retryAfter = typeof firstPayload.retry_after_ms === "number"
            ? Math.min(75, Math.max(25, Math.floor(firstPayload.retry_after_ms)))
            : 25;
          const estimatedService = typeof firstPayload.estimated_service_ms === "number"
            ? Math.min(2_800, Math.max(100, Math.floor(firstPayload.estimated_service_ms)))
            : 750;
          const jitterMs = Math.max(retryAfter, 25 + Math.floor(Math.random() * 51));
          if (deadlineMs - Date.now() >= jitterMs + estimatedService + 100) {
            await new Promise((resolve) => setTimeout(resolve, jitterMs));
            result = await runGuardHook(
              directory,
              {
                hook_event_name: "PreToolUse",
                event: "PreToolUse",
                tool_name: input.tool,
                tool_input: { command },
                cwd: workspace,
                source_scope: directory?.trim() ? "project" : "global",
              },
              deadlineMs,
            );
          }
          if (parseGuardPayload(result.stdout)?.reason_code === "transient_overload") {
            throw new Error(
              "HOL Guard is temporarily saturated and kept this action blocked. " +
                "No approval was requested; retry the action.",
            );
          }
        }
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (detail.startsWith("HOL Guard is temporarily saturated")) {
          throw new Error(detail);
        }
        throw new Error(
          `HOL Guard could not review this ${input.tool} command (${detail}). ` +
            "Re-run `hol-guard install opencode` and ensure the Guard CLI is available.",
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


def _trusted_pythonpath_entries(package_root: str) -> list[str]:
    trimmed = package_root.strip()
    return [trimmed] if trimmed else []


def _pretool_hook_launcher_code(
    *,
    import_roots: tuple[str, ...] = (),
    package_root: str | None = None,
) -> str:
    trusted_entries = list(import_roots)
    if not trusted_entries and package_root is not None:
        trusted_entries = _trusted_pythonpath_entries(package_root)
    return (
        "import json,os,sys;"
        f"trusted={json.dumps(trusted_entries)};"
        "sys.path[:0]=trusted;"
        "from codex_plugin_scanner.guard.codex_hook_windows_job import "
        "assign_current_process_to_windows_hook_job;"
        "_windows_job=assign_current_process_to_windows_hook_job() if os.name=='nt' else None;"
        "sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;"
        "sys.stderr.flush() if _windows_job is not None else None;"
        "from pathlib import Path;"
        "import codex_plugin_scanner;"
        "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import run_bounded_cli_hook;"
        f"argv=json.loads(os.environ[{_HOOK_ARGV_ENV!r}]);"
        "guard_index=argv.index('--guard-home');"
        "guard_home=argv[guard_index+1];"
        "package_root=Path(codex_plugin_scanner.__file__).resolve().parent.parent;"
        "config={'python_executable':sys.executable,'package_root':str(package_root),"
        "'guard_home':guard_home,'cli_args':argv,'harness':'opencode','timeout_seconds':25};"
        "raise SystemExit(run_bounded_cli_hook(config,input_text=sys.stdin.read(1000001)))"
    )


def _pretool_hook_env(*, package_root: str | None = None) -> dict[str, str]:
    del package_root
    return {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }


def managed_plugin_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "plugins" / PLUGIN_FILENAME


def global_plugin_path(context: HarnessContext) -> Path:
    return context.home_dir / ".config" / "opencode" / "plugins" / PLUGIN_FILENAME


def _metadata_payload(metadata: HookPythonFileMetadata) -> dict[str, str]:
    return {
        "device": str(metadata.device),
        "inode": str(metadata.inode),
        "mode": str(metadata.mode),
        "size": str(metadata.size),
        "mtimeNs": str(metadata.mtime_ns),
    }


def _python_identity_payload(identity: HookPythonExecutableIdentity) -> dict[str, object]:
    return {
        "invocationPath": str(identity.invocation_path),
        "invocationType": identity.invocation_type,
        "invocationLinkTarget": identity.invocation_link_target,
        "invocationStat": _metadata_payload(identity.invocation_stat),
        "targetPath": str(identity.target_path),
        "targetStat": _metadata_payload(identity.target_stat),
        "targetSha256": identity.target_sha256,
    }


def pretool_plugin_source(context: HarnessContext) -> str:
    attestation = attest_guard_hook_python(context)
    import_roots = tuple(str(root) for root in attestation.import_roots)
    try:
        taskkill_path = windows_system_executable_path("taskkill.exe") if os.name == "nt" else None
    except (OSError, ValueError):
        taskkill_path = None
    template = _PLUGIN_TEMPLATE.replace("__HOOK_ARGV_ENV__", _HOOK_ARGV_ENV)
    return (
        template.replace("__GUARD_HOME__", json.dumps(str(context.guard_home.resolve())))
        .replace("__GUARD_PYTHON__", json.dumps(_python_identity_payload(attestation.identity)))
        .replace("__GUARD_HOOK_LAUNCHER__", json.dumps(_pretool_hook_launcher_code(import_roots=import_roots)))
        .replace("__GUARD_HOOK_ENV__", json.dumps(_pretool_hook_env()))
        .replace("__GUARD_INHERIT_ENV_KEYS__", json.dumps(list(_INHERIT_ENV_KEYS)))
        .replace("__GUARD_TASKKILL_PATH__", json.dumps(taskkill_path))
        .replace("__INTERCEPT_TOOLS__", json.dumps(list(_INTERCEPT_TOOLS)))
    )


def install_pretool_plugin(context: HarnessContext) -> dict[str, object]:
    source = pretool_plugin_source(context)
    managed_path = managed_plugin_path(context)
    global_path = global_plugin_path(context)
    managed_path.parent.mkdir(parents=True, exist_ok=True)
    global_path.parent.mkdir(parents=True, exist_ok=True)
    managed_path.write_text(source, encoding="utf-8")
    global_path.write_text(source, encoding="utf-8")
    return {
        "managed_plugin_path": str(managed_path),
        "global_plugin_path": str(global_path),
    }


def remove_pretool_plugin(context: HarnessContext) -> dict[str, object]:
    managed_path = managed_plugin_path(context)
    global_path = global_plugin_path(context)
    removed_paths: list[str] = []
    for path in (global_path, managed_path):
        if path.is_file():
            path.unlink()
            removed_paths.append(str(path))
    return {"removed_plugin_paths": removed_paths}


def opencode_config_has_mcp_servers(config_path: Path) -> bool:
    from ...ecosystems.opencode import _load_json_or_jsonc

    if not config_path.is_file():
        return False
    payload, parse_error, _ = _load_json_or_jsonc(config_path)
    if parse_error or not isinstance(payload, dict):
        return False
    mcp = payload.get("mcp")
    return isinstance(mcp, dict) and bool(mcp)


def _mcp_command_uses_guard_proxy(command: object) -> bool:
    if isinstance(command, list):
        return any("opencode-mcp-proxy" in str(part) for part in command)
    if isinstance(command, str):
        return "opencode-mcp-proxy" in command
    return False


def opencode_config_uses_guard_proxy(config_path: Path) -> bool:
    from ...ecosystems.opencode import _load_json_or_jsonc

    if not config_path.is_file():
        return False
    payload, parse_error, _ = _load_json_or_jsonc(config_path)
    if parse_error or not isinstance(payload, dict):
        return False
    mcp = payload.get("mcp")
    if not isinstance(mcp, dict):
        return False
    native_servers: dict[str, dict[str, object]] = {}
    companions: dict[str, dict[str, object]] = {}
    for name, server in mcp.items():
        if not isinstance(name, str) or not isinstance(server, dict):
            continue
        if name.startswith("hol-guard::"):
            companions[name] = server
        else:
            native_servers[name] = server
    if not native_servers:
        return any(_mcp_command_uses_guard_proxy(server.get("command")) for server in companions.values())
    for name, server in native_servers.items():
        if _mcp_command_uses_guard_proxy(server.get("command")):
            continue
        companion = companions.get(f"hol-guard::{name}")
        if companion is None or not _mcp_command_uses_guard_proxy(companion.get("command")):
            return False
    return True


__all__ = [
    "PLUGIN_FILENAME",
    "global_plugin_path",
    "install_pretool_plugin",
    "managed_plugin_path",
    "opencode_config_has_mcp_servers",
    "opencode_config_uses_guard_proxy",
    "pretool_plugin_source",
    "remove_pretool_plugin",
]
