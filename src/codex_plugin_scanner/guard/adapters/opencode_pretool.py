"""OpenCode pretool plugin generation for HOL Guard runtime interception."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

from ..launcher import merge_guard_launcher_env
from .base import HarnessContext

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
  const proc = Bun.spawn([GUARD_PYTHON, "-c", GUARD_HOOK_LAUNCHER], {
    cwd: GUARD_HOME,
    env: hookProcessEnv(guardArgv),
    stdin: new Blob([JSON.stringify(payload)]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdoutPromise = new Response(proc.stdout).text();
  const stderrPromise = new Response(proc.stderr).text();
  const exitCode = await proc.exited;
  const stdout = await stdoutPromise;
  const stderr = await stderrPromise;
  return { exitCode, stdout, stderr };
}

function guardBlockMessage(stdout: string, stderr: string): string {
  try {
    const payload = JSON.parse(stdout) as {
      review_hint?: string;
      decision_v2_json?: { harness_message?: string; retry_instruction?: string };
    };
    const decision = payload.decision_v2_json;
    return (
      payload.review_hint ||
      decision?.retry_instruction ||
      decision?.harness_message ||
      stderr.trim() ||
      "HOL Guard blocked this OpenCode action."
    );
  } catch {
    return stderr.trim() || "HOL Guard blocked this OpenCode action.";
  }
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


def _trusted_package_root() -> Path:
    spec = importlib.util.find_spec("codex_plugin_scanner")
    if spec is None:
        raise RuntimeError("Guard could not locate the codex_plugin_scanner package")
    if spec.submodule_search_locations:
        locations = tuple(spec.submodule_search_locations)
        if not locations:
            raise RuntimeError("Guard could not resolve codex_plugin_scanner package locations")
        return Path(locations[0]).resolve().parent
    if spec.origin is None:
        raise RuntimeError("Guard could not determine the codex_plugin_scanner package root")
    return Path(spec.origin).resolve().parent.parent


def _trusted_pythonpath_entries() -> list[str]:
    launcher_env = merge_guard_launcher_env(pin_package=True)
    path_entries = [entry for entry in launcher_env.get("PYTHONPATH", "").split(os.pathsep) if entry.strip()]
    package_root = str(_trusted_package_root())
    if package_root not in path_entries:
        path_entries.insert(0, package_root)
    return path_entries


def _pretool_hook_launcher_code() -> str:
    trusted_entries = _trusted_pythonpath_entries()
    return (
        "import json,os,sys;"
        f"sys.path[:0]={json.dumps(trusted_entries)};"
        "from codex_plugin_scanner.cli import main;"
        f"raise SystemExit(main(json.loads(os.environ[{_HOOK_ARGV_ENV!r}])))"
    )


def _pretool_hook_env() -> dict[str, str]:
    env = merge_guard_launcher_env(pin_package=True)
    return {key: value for key, value in env.items() if key == "PYTHONPATH" and value.strip()}


def managed_plugin_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "plugins" / PLUGIN_FILENAME


def global_plugin_path(context: HarnessContext) -> Path:
    return context.home_dir / ".config" / "opencode" / "plugins" / PLUGIN_FILENAME


def pretool_plugin_source(context: HarnessContext) -> str:
    template = _PLUGIN_TEMPLATE.replace("__HOOK_ARGV_ENV__", _HOOK_ARGV_ENV)
    return (
        template.replace("__GUARD_HOME__", json.dumps(str(context.guard_home.resolve())))
        .replace("__GUARD_PYTHON__", json.dumps(str(Path(sys.executable).resolve())))
        .replace("__GUARD_HOOK_LAUNCHER__", json.dumps(_pretool_hook_launcher_code()))
        .replace("__GUARD_HOOK_ENV__", json.dumps(_pretool_hook_env()))
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
    for server in mcp.values():
        if not isinstance(server, dict):
            continue
        command = server.get("command")
        if isinstance(command, list) and any("opencode-mcp-proxy" in str(part) for part in command):
            return True
        if isinstance(command, str) and "opencode-mcp-proxy" in command:
            return True
    return False


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
