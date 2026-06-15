"""OpenCode pretool plugin generation for HOL Guard runtime interception."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .base import HarnessContext
from .hook_python import package_root_from_python, resolve_guard_hook_python

PLUGIN_FILENAME = "hol-guard-pretool.ts"
_INTERCEPT_TOOLS = ("bash", "shell", "sh", "zsh", "terminal")
_HOOK_ARGV_ENV = "HOL_GUARD_HOOK_ARGV"
_INHERIT_ENV_KEYS = ("PATH", "HOME", "USER", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SYSTEMROOT")

_PLUGIN_TEMPLATE = """// Managed by HOL Guard. Re-run `hol-guard install opencode` after moving Guard home.
const GUARD_HOME = __GUARD_HOME__;
const GUARD_PYTHON = __GUARD_PYTHON__;
const GUARD_HOOK_LAUNCHER = __GUARD_HOOK_LAUNCHER__;
const GUARD_HOOK_ENV = __GUARD_HOOK_ENV__;
const GUARD_INHERIT_ENV_KEYS = __GUARD_INHERIT_ENV_KEYS__;
const INTERCEPT_TOOLS = new Set(__INTERCEPT_TOOLS__);

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

async function spawnGuardProcess(options: {
  command: string[];
  cwd: string;
  env: Record<string, string>;
  stdin: string;
}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const bun = (globalThis as { Bun?: { spawn?: Function } }).Bun;
  if (typeof bun?.spawn === "function") {
    const proc = bun.spawn(options.command, {
      cwd: options.cwd,
      env: options.env,
      stdin: new Blob([options.stdin]),
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdoutPromise = new Response(proc.stdout).text();
    const stderrPromise = new Response(proc.stderr).text();
    const exitCode = await proc.exited;
    return {
      exitCode,
      stdout: await stdoutPromise,
      stderr: await stderrPromise,
    };
  }

  const { spawn } = await import("node:child_process");
  return await new Promise((resolve, reject) => {
    const proc = spawn(options.command[0], options.command.slice(1), {
      cwd: options.cwd,
      env: options.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    proc.stdout?.on("data", (chunk: Buffer | string) => {
      stdout += String(chunk);
    });
    proc.stderr?.on("data", (chunk: Buffer | string) => {
      stderr += String(chunk);
    });
    proc.on("error", reject);
    proc.on("close", (code: number | null) => {
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });
    proc.stdin?.end(options.stdin);
  });
}

async function runGuardHook(directory: string, payload: Record<string, unknown>) {
  const workspace = directory?.trim() || process.cwd();
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
    command: [GUARD_PYTHON, "-c", GUARD_HOOK_LAUNCHER],
    cwd: GUARD_HOME,
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
      const workspace = directory?.trim() || process.cwd();
      let result;
      try {
        result = await runGuardHook(directory, {
          hook_event_name: "PreToolUse",
          event: "PreToolUse",
          tool_name: input.tool,
          tool_input: { command },
          cwd: workspace,
          source_scope: directory?.trim() ? "project" : "global",
        });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
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


def _pretool_hook_launcher_code(*, package_root: str) -> str:
    trusted_entries = _trusted_pythonpath_entries(package_root)
    return (
        "import json,os,sys;"
        f"trusted={json.dumps(trusted_entries)};"
        "sys.path=[entry for entry in sys.path if entry and os.path.realpath(entry) != os.path.realpath(os.getcwd())];"
        "sys.path[:0]=trusted;"
        "from codex_plugin_scanner.cli import main;"
        f"raise SystemExit(main(json.loads(os.environ[{_HOOK_ARGV_ENV!r}])))"
    )


def _pretool_hook_env(*, package_root: str) -> dict[str, str]:
    entries = _trusted_pythonpath_entries(package_root)
    env = {"PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1"}
    if entries:
        env["PYTHONPATH"] = os.pathsep.join(entries)
    return env


def managed_plugin_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "plugins" / PLUGIN_FILENAME


def global_plugin_path(context: HarnessContext) -> Path:
    return context.home_dir / ".config" / "opencode" / "plugins" / PLUGIN_FILENAME


def pretool_plugin_source(context: HarnessContext) -> str:
    guard_python = resolve_guard_hook_python(context)
    package_root = package_root_from_python(guard_python)
    template = _PLUGIN_TEMPLATE.replace("__HOOK_ARGV_ENV__", _HOOK_ARGV_ENV)
    return (
        template.replace("__GUARD_HOME__", json.dumps(str(context.guard_home.resolve())))
        .replace("__GUARD_PYTHON__", json.dumps(str(guard_python)))
        .replace("__GUARD_HOOK_LAUNCHER__", json.dumps(_pretool_hook_launcher_code(package_root=package_root)))
        .replace("__GUARD_HOOK_ENV__", json.dumps(_pretool_hook_env(package_root=package_root)))
        .replace("__GUARD_INHERIT_ENV_KEYS__", json.dumps(list(_INHERIT_ENV_KEYS)))
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
    native_servers: dict[str, dict] = {}
    companions: dict[str, dict] = {}
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
