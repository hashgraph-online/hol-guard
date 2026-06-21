"""Support helpers for the Pi harness adapter."""

from __future__ import annotations

import hashlib
import json
from glob import glob
from pathlib import Path

from ..models import GuardArtifact

PI_DIR = ".pi"
PI_AGENT_DIR = ".pi/agent"
OMP_DIR = ".omp"
OMP_AGENT_DIR = ".omp/agent"
PI_SETTINGS_FILE = "settings.json"
PI_MANAGED_EXTENSION_NAME = "hol-guard.ts"
EXTENSION_SUFFIXES = (".ts", ".js", ".mts", ".cts", ".mjs", ".cjs")
THEME_SUFFIXES = (".json", ".js", ".ts", ".yaml", ".yml")
REMOTE_RESOURCE_PREFIXES = ("npm:", "git:", "http://", "https://", "ssh://")
GUARD_HOOK_TIMEOUT_MS = 10_000


def append_found_path(found_paths: list[str], path: Path) -> None:
    candidate = str(path)
    if candidate not in found_paths:
        found_paths.append(candidate)


def json_payload(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def stable_suffix(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def artifact(
    *,
    artifact_id: str,
    name: str,
    artifact_type: str,
    scope: str,
    path: Path,
    metadata: dict[str, object] | None = None,
    publisher: str | None = None,
) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name=name,
        harness="pi",
        artifact_type=artifact_type,
        source_scope=scope,
        config_path=str(path),
        publisher=publisher,
        metadata=metadata or {},
    )


def append_artifact(
    artifacts: list[GuardArtifact],
    seen_keys: set[str],
    next_artifact: GuardArtifact,
    *,
    dedupe_key: str,
) -> None:
    if dedupe_key in seen_keys:
        return
    seen_keys.add(dedupe_key)
    artifacts.append(next_artifact)


def is_remote_resource(value: str) -> bool:
    return value.startswith(REMOTE_RESOURCE_PREFIXES)


def resolve_configured_paths(settings_path: Path, value: str) -> tuple[Path, ...]:
    if is_remote_resource(value):
        return ()
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = (settings_path.parent / candidate).expanduser()
    pattern = str(candidate)
    if any(char in pattern for char in "*?["):
        matches = [Path(item).expanduser().resolve() for item in glob(pattern, recursive=True)]
        return tuple(sorted(path for path in matches if path.exists()))
    resolved = candidate.resolve()
    return (resolved,) if resolved.exists() else ()


def enable_managed_extension(*, settings_path: Path, extension_path: Path) -> None:
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json_payload(settings_path) if settings_path.is_file() else {}
    raw_extensions = payload.get("extensions")
    extensions = [item for item in raw_extensions if isinstance(item, str)] if isinstance(raw_extensions, list) else []
    extension_value = str(extension_path)
    if extension_value not in extensions:
        extensions.append(extension_value)
    payload["extensions"] = extensions
    settings_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def disable_managed_extension(*, settings_path: Path, extension_path: Path) -> None:
    if not settings_path.is_file():
        return
    payload = json_payload(settings_path)
    raw_extensions = payload.get("extensions")
    if not isinstance(raw_extensions, list):
        return
    extension_value = str(extension_path)
    payload["extensions"] = [item for item in raw_extensions if isinstance(item, str) and item != extension_value]
    settings_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def managed_extension_source(*, guard_home: Path, home_dir: Path, settings_path: Path) -> str:
    guard_args = ["guard", "hook", "--guard-home", str(guard_home), "--harness", "pi"]
    if home_dir.resolve() != Path.home().resolve():
        guard_args.extend(["--home", str(home_dir)])
    guard_args_json = json.dumps(guard_args)
    config_path_json = json.dumps(str(settings_path))
    return (
        'import { spawnSync } from "node:child_process";\n'
        'import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";\n'
        "\n"
        f"const GUARD_ARGS = {guard_args_json};\n"
        f"const GUARD_CONFIG_PATH = {config_path_json};\n"
        f"const GUARD_TIMEOUT_MS = {GUARD_HOOK_TIMEOUT_MS};\n"
        "\n"
        "type GuardResponse = { decision?: string; reason?: string };\n"
        "\n"
        "function runGuard(payload: Record<string, unknown>, cwd?: string): GuardResponse {\n"
        "  const args = [...GUARD_ARGS];\n"
        '  const workspace = typeof cwd === "string" && cwd ? cwd : process.cwd();\n'
        '  if (workspace) args.push("--workspace", workspace);\n'
        '  const result = spawnSync("hol-guard", args, {\n'
        "    input: `${JSON.stringify(payload)}\\n`,\n"
        '    encoding: "utf-8",\n'
        "    timeout: GUARD_TIMEOUT_MS,\n"
        "  });\n"
        '  if (result.error) return { decision: "allow" };\n'
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
        "function contentText(content: unknown): string {\n"
        '  if (typeof content === "string") return content;\n'
        '  if (!Array.isArray(content)) return "";\n'
        "  return content\n"
        "    .map((item) => {\n"
        '      if (!item || typeof item !== "object") return "";\n'
        "      const type = (item as { type?: unknown }).type;\n"
        "      const text = (item as { text?: unknown }).text;\n"
        '      return type === "text" && typeof text === "string" ? text : "";\n'
        "    })\n"
        "    .filter(Boolean)\n"
        '    .join("\\n");\n'
        "}\n"
        "\n"
        "export default function (pi: ExtensionAPI) {\n"
        '  pi.on("input", async (event, ctx) => {\n'
        '    if (event.source === "extension") return { action: "continue" };\n'
        "    const response = runGuard(\n"
        '      { hook_event_name: "UserPromptSubmit", prompt: event.text, config_path: GUARD_CONFIG_PATH },\n'
        "      ctx.cwd,\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      ctx.ui.notify(response.reason ?? "Blocked by HOL Guard.", "warning");\n'
        '      return { action: "handled", handled: true };\n'
        "    }\n"
        '    return { action: "continue" };\n'
        "  });\n"
        '  pi.on("tool_call", async (event, ctx) => {\n'
        "    const toolInput =\n"
        "      (event as { input?: Record<string, unknown> }).input ??\n"
        "      (event as { toolInput?: Record<string, unknown> }).toolInput ??\n"
        "      (event as { arguments?: Record<string, unknown> }).arguments ??\n"
        "      {};\n"
        "    const response = runGuard(\n"
        "      {\n"
        '        hook_event_name: "PreToolUse",\n'
        "        config_path: GUARD_CONFIG_PATH,\n"
        "        tool_name: event.toolName,\n"
        "        tool_input: toolInput,\n"
        "      },\n"
        "      ctx.cwd,\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      ctx.ui.notify(response.reason ?? "Blocked by HOL Guard.", "warning");\n'
        '      return { block: true, reason: response.reason ?? "Blocked by HOL Guard." };\n'
        "    }\n"
        "    return undefined;\n"
        "  });\n"
        '  pi.on("tool_result", async (event, ctx) => {\n'
        "    const toolOutput = contentText(event.content);\n"
        "    const toolInput =\n"
        "      (event as { input?: Record<string, unknown> }).input ??\n"
        "      (event as { toolInput?: Record<string, unknown> }).toolInput ??\n"
        "      (event as { arguments?: Record<string, unknown> }).arguments ??\n"
        "      {};\n"
        "    const response = runGuard(\n"
        "      {\n"
        '        hook_event_name: "PostToolUse",\n'
        "        config_path: GUARD_CONFIG_PATH,\n"
        "        tool_name: event.toolName,\n"
        "        tool_input: toolInput,\n"
        "        tool_response: event.content,\n"
        "        stdout: toolOutput,\n"
        "        is_error: event.isError === true,\n"
        "      },\n"
        "      ctx.cwd,\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      const reason = response.reason ?? "Blocked by HOL Guard.";\n'
        '      ctx.ui.notify(reason, "warning");\n'
        "      return {\n"
        '        content: [{ type: "text", text: reason }],\n'
        "        details: event.details,\n"
        "        isError: true,\n"
        "      };\n"
        "    }\n"
        "    return undefined;\n"
        "  });\n"
        "}\n"
    )
