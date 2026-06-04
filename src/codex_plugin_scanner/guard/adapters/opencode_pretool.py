"""OpenCode pretool plugin generation for HOL Guard runtime interception."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .base import HarnessContext

PLUGIN_FILENAME = "hol-guard-pretool.ts"
_INTERCEPT_TOOLS = ("bash", "shell", "sh", "zsh", "terminal")

_PLUGIN_TEMPLATE = """// Managed by HOL Guard. Re-run `hol-guard install opencode` after moving Guard home.
const GUARD_HOME = __GUARD_HOME__;
const GUARD_PYTHON = __GUARD_PYTHON__;
const INTERCEPT_TOOLS = new Set(__INTERCEPT_TOOLS__);

async function runGuardHook(directory: string, payload: Record<string, unknown>) {
  const workspace = directory?.trim() || process.cwd();
  const proc = Bun.spawn(
    [
      GUARD_PYTHON,
      "-m",
      "codex_plugin_scanner.cli",
      "guard",
      "hook",
      "--guard-home",
      GUARD_HOME,
      "--harness",
      "opencode",
      "--workspace",
      workspace,
      "--json",
    ],
    {
      cwd: workspace,
      stdin: new TextEncoder().encode(JSON.stringify(payload)),
      stdout: "pipe",
      stderr: "pipe",
    },
  );
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
      const command = output.args?.command;
      if (typeof command !== "string" || !command.trim()) {
        return;
      }
      const result = await runGuardHook(directory, {
        hook_event_name: "PreToolUse",
        event: "PreToolUse",
        tool_name: input.tool,
        tool_input: { command },
        cwd: directory,
        source_scope: "project",
      });
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


def managed_plugin_path(context: HarnessContext) -> Path:
    return context.guard_home / "opencode" / "plugins" / PLUGIN_FILENAME


def global_plugin_path(context: HarnessContext) -> Path:
    return context.home_dir / ".config" / "opencode" / "plugins" / PLUGIN_FILENAME


def pretool_plugin_source(context: HarnessContext) -> str:
    return (
        _PLUGIN_TEMPLATE.replace("__GUARD_HOME__", json.dumps(str(context.guard_home.resolve())))
        .replace("__GUARD_PYTHON__", json.dumps(str(Path(sys.executable).resolve())))
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
    "opencode_config_uses_guard_proxy",
    "pretool_plugin_source",
    "remove_pretool_plugin",
]
