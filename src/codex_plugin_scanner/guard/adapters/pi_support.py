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
GUARD_HOOK_TEXT_LIMIT_CHARS = 12_000
GUARD_HOOK_CONTENT_ITEM_LIMIT = 24
GUARD_HOOK_OBJECT_KEY_LIMIT = 24
GUARD_HOOK_MAX_DEPTH = 24
GUARD_HOOK_MAX_SERIALIZED_PAYLOAD_CHARS = 24_000


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
        f"const GUARD_TEXT_LIMIT_CHARS = {GUARD_HOOK_TEXT_LIMIT_CHARS};\n"
        f"const GUARD_CONTENT_ITEM_LIMIT = {GUARD_HOOK_CONTENT_ITEM_LIMIT};\n"
        f"const GUARD_OBJECT_KEY_LIMIT = {GUARD_HOOK_OBJECT_KEY_LIMIT};\n"
        f"const GUARD_MAX_DEPTH = {GUARD_HOOK_MAX_DEPTH};\n"
        f"const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = {GUARD_HOOK_MAX_SERIALIZED_PAYLOAD_CHARS};\n"
        "\n"
        "type GuardResponse = { decision?: string; reason?: string };\n"
        "type BoundedValue = { value: unknown; truncated: boolean };\n"
        'const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"] as const;\n'
        "\n"
        "function truncateText(value: string, limit = GUARD_TEXT_LIMIT_CHARS): string {\n"
        "  if (value.length <= limit) return value;\n"
        "  return `${value.slice(0, Math.max(limit, 0))}\\n...[truncated by HOL Guard]...`;\n"
        "}\n"
        "\n"
        "function boundValue(value: unknown, depth = 0, seen = new WeakSet<object>()): BoundedValue {\n"
        "  if (typeof value === 'string') {\n"
        "    return value.length <= GUARD_TEXT_LIMIT_CHARS\n"
        "      ? { value, truncated: false }\n"
        "      : { value: truncateText(value), truncated: true };\n"
        "  }\n"
        "  if (value === undefined) return { value: undefined, truncated: false };\n"
        "  if (typeof value === 'bigint') return { value: value.toString(), truncated: false };\n"
        "  if (\n"
        "    value === null ||\n"
        "    typeof value === 'number' ||\n"
        "    typeof value === 'boolean'\n"
        "  ) {\n"
        "    return { value, truncated: false };\n"
        "  }\n"
        "  if (typeof value !== 'object') {\n"
        "    return { value: String(value), truncated: true };\n"
        "  }\n"
        "  const objectValue = value as object;\n"
        "  if (seen.has(objectValue)) {\n"
        "    return { value: '[cycle omitted by HOL Guard]', truncated: true };\n"
        "  }\n"
        "  if (depth > GUARD_MAX_DEPTH) {\n"
        "    return { value: '[deep object omitted by HOL Guard]', truncated: true };\n"
        "  }\n"
        "  seen.add(objectValue);\n"
        "  try {\n"
        "    if (Array.isArray(value)) {\n"
        "      const truncated = value.length > GUARD_CONTENT_ITEM_LIMIT;\n"
        "      const items = value.slice(0, GUARD_CONTENT_ITEM_LIMIT);\n"
        "      const nextItems: unknown[] = [];\n"
        "      let childTruncated = truncated;\n"
        "      for (const item of items) {\n"
        "        const next = boundValue(item, depth + 1, seen);\n"
        "        nextItems.push(next.value);\n"
        "        childTruncated = childTruncated || next.truncated;\n"
        "      }\n"
        "      return { value: nextItems, truncated: childTruncated };\n"
        "    }\n"
        "    const record = value as Record<string, unknown>;\n"
        "    const nextRecord: Record<string, unknown> = {};\n"
        "    let truncated = false;\n"
        "    let keyCount = 0;\n"
        "    for (const key in record) {\n"
        "      if (!Object.prototype.hasOwnProperty.call(record, key)) continue;\n"
        "      if (keyCount >= GUARD_OBJECT_KEY_LIMIT) {\n"
        "        truncated = true;\n"
        "        break;\n"
        "      }\n"
        "      keyCount += 1;\n"
        "      const entryValue = record[key];\n"
        "      const next = boundValue(entryValue, depth + 1, seen);\n"
        "      nextRecord[key] = next.value;\n"
        "      truncated = truncated || next.truncated;\n"
        "    }\n"
        "    return { value: nextRecord, truncated };\n"
        "  } finally {\n"
        "    seen.delete(objectValue);\n"
        "  }\n"
        "}\n"
        "\n"
        "function appendBoundedText(accumulator: { text: string; truncated: boolean }, value: string): void {\n"
        "  if (accumulator.truncated || value.length === 0) return;\n"
        '  const prefix = accumulator.text ? "\\n" : "";\n'
        "  const available = GUARD_TEXT_LIMIT_CHARS - accumulator.text.length - prefix.length;\n"
        "  if (available <= 0) {\n"
        "    accumulator.truncated = true;\n"
        "    return;\n"
        "  }\n"
        "  if (value.length > available) {\n"
        "    accumulator.text += `${prefix}${value.slice(0, available)}`;\n"
        "    accumulator.truncated = true;\n"
        "    return;\n"
        "  }\n"
        "  accumulator.text += `${prefix}${value}`;\n"
        "}\n"
        "\n"
        "function collectOutputText(\n"
        "  value: unknown,\n"
        "  accumulator: { text: string; truncated: boolean; itemCount: number },\n"
        "  depth = 0,\n"
        "  seen = new WeakSet<object>(),\n"
        "): void {\n"
        "  if (accumulator.truncated) return;\n"
        "  if (typeof value === 'string') {\n"
        "    appendBoundedText(accumulator, value);\n"
        "    return;\n"
        "  }\n"
        "  if (typeof value === 'bigint') {\n"
        "    appendBoundedText(accumulator, value.toString());\n"
        "    return;\n"
        "  }\n"
        "  if (\n"
        "    value === undefined ||\n"
        "    value === null ||\n"
        "    typeof value === 'number' ||\n"
        "    typeof value === 'boolean'\n"
        "  ) {\n"
        "    return;\n"
        "  }\n"
        "  if (typeof value !== 'object') {\n"
        "    accumulator.truncated = true;\n"
        "    return;\n"
        "  }\n"
        "  const objectValue = value as object;\n"
        "  if (seen.has(objectValue) || depth > GUARD_MAX_DEPTH) {\n"
        "    accumulator.truncated = true;\n"
        "    return;\n"
        "  }\n"
        "  seen.add(objectValue);\n"
        "  try {\n"
        "    if (Array.isArray(value)) {\n"
        "      const arrayItems = value as unknown[];\n"
        "      for (const item of arrayItems) {\n"
        "        if (accumulator.itemCount >= GUARD_CONTENT_ITEM_LIMIT) {\n"
        "          accumulator.truncated = true;\n"
        "          break;\n"
        "        }\n"
        "        accumulator.itemCount += 1;\n"
        "        collectOutputText(item, accumulator, depth + 1, seen);\n"
        "        if (accumulator.truncated) break;\n"
        "      }\n"
        "      if (arrayItems.length > GUARD_CONTENT_ITEM_LIMIT) accumulator.truncated = true;\n"
        "      return;\n"
        "    }\n"
        "    const record = value as Record<string, unknown>;\n"
        "    if (record.type === 'text' && typeof record.text === 'string') {\n"
        "      appendBoundedText(accumulator, record.text);\n"
        "      return;\n"
        "    }\n"
        "    for (const key of OUTPUT_TEXT_KEYS) {\n"
        "      if (!(key in record)) continue;\n"
        "      collectOutputText(record[key], accumulator, depth + 1, seen);\n"
        "      if (accumulator.truncated) break;\n"
        "    }\n"
        "  } finally {\n"
        "    seen.delete(objectValue);\n"
        "  }\n"
        "}\n"
        "\n"
        "function boundedOutputText(value: unknown): BoundedValue {\n"
        "  const accumulator = { text: '', truncated: false, itemCount: 0 };\n"
        "  collectOutputText(value, accumulator);\n"
        "  return { value: accumulator.text, truncated: accumulator.truncated };\n"
        "}\n"
        "\n"
        "function toolCallIdKey(value: unknown): string | null {\n"
        "  if (typeof value !== 'string') return null;\n"
        "  const trimmed = value.trim();\n"
        "  return trimmed.length > 0 ? trimmed : null;\n"
        "}\n"
        "\n"
        "function runGuard(\n"
        "  payload: Record<string, unknown>,\n"
        "  cwd?: string,\n"
        "  options?: { enforceSizeCap?: boolean },\n"
        "): GuardResponse {\n"
        "  const args = [...GUARD_ARGS];\n"
        '  const workspace = typeof cwd === "string" && cwd ? cwd : process.cwd();\n'
        '  if (workspace) args.push("--workspace", workspace);\n'
        "  let payloadToSend = payload;\n"
        "  let serializedPayload = '';\n"
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
        "    serializedPayload.length > GUARD_MAX_SERIALIZED_PAYLOAD_CHARS &&\n"
        '    payloadToSend.hook_event_name === "PostToolUse" &&\n'
        '    typeof payloadToSend.stdout === "string"\n'
        "  ) {\n"
        "    const reducedPayload = { ...payloadToSend };\n"
        "    delete reducedPayload.stdout;\n"
        "    try {\n"
        "      const reducedSerializedPayload = JSON.stringify(reducedPayload);\n"
        "      if (reducedSerializedPayload.length <= GUARD_MAX_SERIALIZED_PAYLOAD_CHARS) {\n"
        "        payloadToSend = reducedPayload;\n"
        "        serializedPayload = reducedSerializedPayload;\n"
        "      }\n"
        "    } catch {}\n"
        "  }\n"
        "  if (\n"
        "    options?.enforceSizeCap === true &&\n"
        "    serializedPayload.length > GUARD_MAX_SERIALIZED_PAYLOAD_CHARS\n"
        "  ) {\n"
        "    return {\n"
        '      decision: "deny",\n'
        '      reason: "HOL Guard blocked this Pi hook payload before review because it exceeded "\n'
        '        + "the safe size limit.",\n'
        "    };\n"
        "  }\n"
        '  const result = spawnSync("hol-guard", args, {\n'
        "    input: `${serializedPayload}\\n`,\n"
        '    encoding: "utf-8",\n'
        "    timeout: GUARD_TIMEOUT_MS,\n"
        "  });\n"
        "  if (result.error) {\n"
        "    const resultError = result.error as (Error & { code?: unknown }) | undefined;\n"
        "    const errorMessage = resultError instanceof Error ? resultError.message : String(result.error);\n"
        "    const errorCode = typeof resultError?.code === 'string' ? resultError.code : '';\n"
        "    return {\n"
        '      decision: "deny",\n'
        "      reason: errorCode === 'ETIMEDOUT' || result.error?.name === 'TimeoutError'\n"
        "        ? `HOL Guard Pi hook timed out after ${GUARD_TIMEOUT_MS}ms while reviewing this action.`\n"
        "        : `HOL Guard Pi hook failed before completing review: ${errorMessage}`,\n"
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
        "\n"
        "export default function (pi: ExtensionAPI) {\n"
        "  const blockedToolResults = new Map<string, string>();\n"
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
        "    const boundedToolInput = boundValue(\n"
        "      (event as { input?: Record<string, unknown> }).input ??\n"
        "      (event as { toolInput?: Record<string, unknown> }).toolInput ??\n"
        "      (event as { arguments?: Record<string, unknown> }).arguments ??\n"
        "      {},\n"
        "    );\n"
        "    const boundedContent = boundValue(event.content);\n"
        "    const boundedStdout = boundedOutputText(event.content);\n"
        "    // Only the reviewed *output* content determines whether the result is\n"
        "    // replaced with the bounded excerpt. A truncated tool input alone does\n"
        "    // not mean the output reached the model unreviewed.\n"
        "    const outputTruncated = boundedContent.truncated || boundedStdout.truncated;\n"
        "    const toolOutput = boundedStdout.value as string;\n"
        "    const reviewedContent = outputTruncated ? [{ type: 'text', text: toolOutput }] : boundedContent.value;\n"
        "    const oversizeNotice = outputTruncated\n"
        '        ? "HOL Guard reviewed a size-bounded excerpt of a large Pi tool result; "\n'
        '          + "the model receives the reviewed excerpt, not the full output."\n'
        "        : null;\n"
        '    if (oversizeNotice) ctx.ui.notify(oversizeNotice, "info");\n'
        "    const toolInput =\n"
        "      boundedToolInput.value as Record<string, unknown>;\n"
        "    const response = runGuard(\n"
        "      {\n"
        '        hook_event_name: "PostToolUse",\n'
        "        config_path: GUARD_CONFIG_PATH,\n"
        "        tool_name: event.toolName,\n"
        "        tool_input: toolInput,\n"
        "        tool_response: reviewedContent,\n"
        "        stdout: toolOutput,\n"
        "        is_error: event.isError === true,\n"
        "      },\n"
        "      ctx.cwd,\n"
        "      { enforceSizeCap: true },\n"
        "    );\n"
        '    if (response.decision === "deny") {\n'
        '      const reason = response.reason ?? "Blocked by HOL Guard.";\n'
        "      const toolCallId = toolCallIdKey(event.toolCallId);\n"
        "      if (toolCallId) blockedToolResults.set(toolCallId, reason);\n"
        '      ctx.ui.notify(reason, "warning");\n'
        "      return blockedToolResult(reason, event.details);\n"
        "    }\n"
        "    if (!outputTruncated) return undefined;\n"
        "    // The full tool result was larger than the review window. Returning\n"
        "    // undefined would leave Pi's original full event.content intact, so the\n"
        "    // unreviewed tail would still reach the model. Instead, replace the\n"
        "    // result with the bounded excerpt Guard actually reviewed.\n"
        "    return reviewedToolResult(reviewedContent, event.details, event.isError === true);\n"
        "  });\n"
        "}\n"
    )
