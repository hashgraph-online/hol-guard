from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from tests.pi_extension_response_source_support import (
    _generated_digest_helper,
    _generated_output_text_keys,
    _generated_preprocessing_helper,
    _generated_structured_helper,
)


def _run_generated_callback_payload(
    source: str,
    content: object,
    guard_response: dict[str, object],
    *,
    tool_name: str = "Bash",
    tool_input: dict[str, object] | None = None,
    details: object | None = None,
    include_signal: bool = True,
    abort_before_guard: bool = False,
    abort_during_guard: bool = False,
    abort_during_structured_proof: bool = False,
    expire_during_structured_proof: bool = False,
    guard_timeout_ms: int = 4250,
    use_generated_blocked_reason: bool = False,
) -> dict[str, object]:
    handler_start = source.index('  pi.on("tool_result", async (event, ctx) => {')
    handler_end = source.index("\n  });\n}", handler_start) + len("\n  });")
    handler = source[handler_start:handler_end]
    for old, new in {
        "(event as { input?: Record<string, unknown> })": "event",
        "(event as { toolInput?: Record<string, unknown> })": "event",
        "(event as { arguments?: Record<string, unknown> })": "event",
        "event as Record<string, unknown>": "event",
        " as Record<string, unknown>": "",
        "const guardPayload: Record<string, unknown>": "const guardPayload",
        " as string": "",
    }.items():
        handler = handler.replace(old, new)

    source_path_start = source.index("function sourcePathFromToolInput(")
    source_path_end = source.index("\n\nfunction isVirtualSourcePath(", source_path_start)
    source_path = source[source_path_start:source_path_end].replace(
        "function sourcePathFromToolInput(toolInput: Record<string, unknown>): string | null {",
        "function sourcePathFromToolInput(toolInput) {",
    )
    virtual_start = source.index("function isVirtualSourcePath(")
    virtual_end = source.index("\n\nfunction sourceFileRefForPostToolUse(", virtual_start)
    virtual = source[virtual_start:virtual_end].replace(
        "function isVirtualSourcePath(path: string): boolean {",
        "function isVirtualSourcePath(path) {",
    )
    source_ref_start = source.index("function sourceFileRefForPostToolUse(")
    source_ref_end = source.index("\n\ntype BoundedValue", source_ref_start)
    source_ref = source[source_ref_start:source_ref_end].replace(
        (
            "function sourceFileRefForPostToolUse(\n"
            "  event: Record<string, unknown>,\n"
            "  toolInput: Record<string, unknown>,\n"
            "  digest: OutputDigest,\n"
            "): { version: number; kind: string; path: string; tool_input_path: string; "
            "output_sha256: string; output_chars: number } | null {"
        ),
        """function sourceFileRefForPostToolUse(
  event,
  toolInput,
  digest,
) {""",
    ).replace("(details as Record<string, unknown>)", "details")

    event_json = json.dumps(
        {
            "toolCallId": "fixture-call",
            "toolName": tool_name,
            "input": tool_input or {},
            "content": content,
            "details": details if details is not None else {"source": "fixture"},
            "isError": False,
        }
    )
    response_json = json.dumps(guard_response)
    blocked_reason = "function modelVisibleBlockedReason(reason) { return `blocked: ${reason}`; }"
    if use_generated_blocked_reason:
        reason_start = source.index("function modelVisibleBlockedReason(")
        reason_end = source.index("\n\nfunction blockedToolResult(", reason_start)
        blocked_reason = source[reason_start:reason_end].replace(
            "(reason: string, reasonCode?: string): string", "(reason, reasonCode)"
        )
    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_CONFIG_PATH = "/tmp/omp-hook-contract/settings.json";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_TIMEOUT_MS = {guard_timeout_ms};
const GUARD_DEADLINE_RESERVE_MS = 250;
const GUARD_STRUCTURED_MAX_BYTES = 64 * 1024;
const GUARD_STRUCTURED_MAX_DEPTH = 8;
const GUARD_STRUCTURED_MAX_NODES = 128;
const GUARD_STRUCTURED_MAX_FIELDS = 64;
const GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES = new Set([
  "read", "read_file", "open_file", "view", "view_file", "cat_file", "Read", "View"
]);
{_generated_output_text_keys(source)}
const blockedToolResults = new Map();
const handlers = {{}};
const notifications = [];
let capturedPayload = null;
let capturedSerializedPayload = null;
const guardResponse = JSON.parse({json.dumps(response_json)});
const realDateNow = Date.now;
let forceExpiredDeadline = false;
Date.now = () => forceExpiredDeadline ? realDateNow() + 60_000 : realDateNow();

{_generated_preprocessing_helper(source)}
{_generated_structured_helper(source)}

{source_path}
{virtual}
{source_ref}
// This fixture executes output mediation only, without a session request map.
function cleanupContainedTestRequest() {{}}
function toolCallIdKey(value) {{ return typeof value === "string" && value.trim() ? value.trim() : null; }}
{blocked_reason}
function blockedToolResult(reason, details) {{
  return {{ content: [{{ type: "text", text: reason }}], details, isError: true }};
}}
function reviewedToolResult(content, details, isError) {{
  return isError ? {{ content, details, isError: true }} : {{ content, details }};
}}
function handlerAbortSignal(ctx) {{
  const candidate = ctx?.signal;
  return candidate && typeof candidate === "object" && typeof candidate.aborted === "boolean"
    && typeof candidate.addEventListener === "function" && typeof candidate.removeEventListener === "function"
    ? candidate : undefined;
}}
const handlerController = new AbortController();
if ({str(abort_before_guard).lower()}) handlerController.abort();
const handlerSignal = {"handlerController.signal" if include_signal else "undefined"};
if (
  guardResponse.structured_content_mediation &&
  ({str(abort_during_structured_proof).lower()} || {str(expire_during_structured_proof).lower()})
) {{
  const mediation = guardResponse.structured_content_mediation;
  const contentSha256 = mediation.content_sha256;
  Object.defineProperty(mediation, "content_sha256", {{
    configurable: true,
    get() {{
      if ({str(abort_during_structured_proof).lower()}) handlerController.abort();
      if ({str(expire_during_structured_proof).lower()}) forceExpiredDeadline = true;
      return contentSha256;
    }},
  }});
}}
async function runGuard(payload) {{
  if ({str(abort_during_guard).lower()}) handlerController.abort();
  if (!payloadWithinSerializedBudget(payload, Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS)) {{
    return {{ decision: "deny", reason_code: "hook_payload_unbounded" }};
  }}
  capturedSerializedPayload = JSON.stringify(payload);
  capturedPayload = JSON.parse(JSON.stringify(payload));
  return guardResponse;
}}
const pi = {{ on(name, handler) {{ handlers[name] = handler; }} }};
{handler}

const event = JSON.parse({json.dumps(event_json)});
const ctx = {{ cwd: "/tmp", signal: handlerSignal, ui: {{ notify(message) {{ notifications.push(message); }} }} }};
const result = await handlers.tool_result(event, ctx);
console.log(JSON.stringify({{
  payload: capturedPayload,
  serialized_payload: capturedSerializedPayload,
  result,
  preserved: result === undefined,
}}));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-callback-contract-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = fixture.name
    try:
        completed = subprocess.run(
            ["node", fixture_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(fixture_path).unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _run_generated_source_ref_fixture(
    source: str,
    content: object,
    path: Path,
    *,
    details: object | None = None,
) -> dict[str, object]:
    source_path_start = source.index("function sourcePathFromToolInput(")
    source_path_end = source.index("\n\nfunction isVirtualSourcePath(", source_path_start)
    source_path = source[source_path_start:source_path_end].replace(
        "function sourcePathFromToolInput(toolInput: Record<string, unknown>): string | null {",
        "function sourcePathFromToolInput(toolInput) {",
    )
    virtual_start = source.index("function isVirtualSourcePath(")
    virtual_end = source.index("\n\nfunction sourceFileRefForPostToolUse(", virtual_start)
    virtual = source[virtual_start:virtual_end].replace(
        "function isVirtualSourcePath(path: string): boolean {",
        "function isVirtualSourcePath(path) {",
    )
    source_ref_start = source.index("function sourceFileRefForPostToolUse(")
    source_ref_end = source.index("\n\ntype BoundedValue", source_ref_start)
    source_ref = source[source_ref_start:source_ref_end].replace(
        (
            "function sourceFileRefForPostToolUse(\n"
            "  event: Record<string, unknown>,\n"
            "  toolInput: Record<string, unknown>,\n"
            "  digest: OutputDigest,\n"
            "): { version: number; kind: string; path: string; tool_input_path: string; "
            "output_sha256: string; output_chars: number } | null {"
        ),
        """function sourceFileRefForPostToolUse(
  event,
  toolInput,
  digest,
) {""",
    ).replace("(details as Record<string, unknown>)", "details")
    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_CONFIG_PATH = "/tmp/omp-hook-contract/settings.json";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_STRUCTURED_MAX_BYTES = 64 * 1024;
const GUARD_STRUCTURED_MAX_DEPTH = 8;
const GUARD_STRUCTURED_MAX_NODES = 128;
const GUARD_STRUCTURED_MAX_FIELDS = 64;
const GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES = new Set(["Read"]);
{_generated_output_text_keys(source)}

{_generated_digest_helper(source)}
{_generated_structured_helper(source)}
{source_path}
{virtual}
{source_ref}

const event = {{ toolName: "Read", details: {json.dumps(details)} }};
const toolInput = {{ file_path: {json.dumps(str(path))} }};
const content = JSON.parse({json.dumps(json.dumps(content))});
const digest = digestOutputText(content);
const sourceRef = sourceFileRefForPostToolUse(event, toolInput, digest);
console.log(JSON.stringify({{ digest, sourceRef }}));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-source-ref-contract-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = fixture.name
    try:
        completed = subprocess.run(
            ["node", fixture_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(fixture_path).unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)
