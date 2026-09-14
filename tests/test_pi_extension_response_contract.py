"""Focused runtime contract tests for the generated Pi/OMP hook extension."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.hook_worker_native import _watch_native_post_tool_result
from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    harness_json_from_native_pre_tool,
    observe_lifecycle_fail_safe_response,
)
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_engine import HookReviewEngine
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest, HookSourceFileRef
from codex_plugin_scanner.guard.runtime.hook_source_read import evaluate_source_file_ref, sha256_text
from codex_plugin_scanner.guard.store import GuardStore


def _generated_source(tmp_path: Path) -> str:
    return managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )


def _strip_generated_types(fragment: str) -> str:
    replacements = {
        "function compactHookEventName(value: unknown): string {": "function compactHookEventName(value) {",
        "function normalizeGuardResponse(value: unknown): GuardResponse | null {":
            "function normalizeGuardResponse(value) {",
        """function daemonResponseCanReturn(
  payload: Record<string, unknown>,
  response: GuardResponse,
): boolean {""": """function daemonResponseCanReturn(
  payload,
  response,
) {""",
        "  payload: Record<string, unknown>,": "  payload,",
        "  cwd?: string,": "  cwd,",
        "  options?: { enforceSizeCap?: boolean },": "  options,",
        "  reasonCode: string,": "  reasonCode,",
        "  reason: string,": "  reason,",
        "): GuardResponse {": ") {",
        "): Promise<GuardDaemonAttempt> {": ") {",
        "): Promise<GuardResponse> {": ") {",
        """async function daemonGuardResponse(
  serializedPayload: string,
  cwd?: string,
  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,
  deadlineAt?: number,
): Promise<GuardDaemonAttempt> {""": """async function daemonGuardResponse(
  serializedPayload,
  cwd,
  timeoutMs = GUARD_DAEMON_TIMEOUT_MS,
  deadlineAt,
) {""",
        """async function runGuard(
  payload: Record<string, unknown>,
  cwd?: string,
  options?: { enforceSizeCap?: boolean },
): Promise<GuardResponse> {""": """async function runGuard(
  payload,
  cwd,
  options,
) {""",
        "let result: GuardCliResult | null = null;": "let result = null;",
        " as unknown": "",
        " as Record<string, unknown>": "",
        " as GuardResponse": "",
        " as { decision?: unknown }": "",
        """ as {
          error?: unknown;
        }""": "",
    }
    for old, new in replacements.items():
        fragment = fragment.replace(old, new)
    fragment = fragment.replace("  serializedPayload: string,", "  serializedPayload,")
    fragment = fragment.replace(
        "  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,",
        "  timeoutMs = GUARD_DAEMON_TIMEOUT_MS,",
    )
    fragment = fragment.replace("  deadlineAt?: number,", "  deadlineAt,")
    return fragment


def _run_generated_fixture(source: str) -> dict[str, object]:
    helper_start = source.index("function normalizeGuardResponse(")
    helper_end = source.index("\n\nfunction loadGuardDaemonConnection(", helper_start)
    helper = _strip_generated_types(source[helper_start:helper_end])

    daemon_start = source.index("async function daemonGuardResponse(")
    daemon_end = source.index("\n\nasync function runGuard(", daemon_start)
    daemon = _strip_generated_types(source[daemon_start:daemon_end])

    run_start = source.index("async function runGuard(")
    run_end = source.index("\n\nfunction modelVisibleBlockedReason(", run_start)
    run_guard = _strip_generated_types(source[run_start:run_end])

    javascript = f"""\
const GUARD_DAEMON_TIMEOUT_MS = 3100;
const GUARD_HOME = "/tmp/omp-hook-contract/guard-home";
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = "";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_TIMEOUT_MS = 4250;
const GUARD_DEADLINE_RESERVE_MS = 250;
const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250;
const GUARD_DAEMON_RETRY_TIMEOUT_MS = 150;
const GUARD_CLI_TIMEOUT_MS = 300;
const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = 24000;
const GUARD_ARGS = [];
const GUARD_CLI_WRAPPER_COMMAND = "hol-guard";
const GUARD_CLI_WRAPPER_ARGS = [];
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
let guardCliContainmentFailed = false;
let guardCliEvaluationInFlight = false;
let daemonMode = "transport";
let fetchBodies = [];
let cliResult = {{ status: 0, stdout: "", stderr: "" }};
let daemonCalls = 0;
let recoveryCalls = 0;
let cliCalls = 0;

function loadGuardDaemonConnection() {{
  daemonCalls += 1;
  if (daemonMode === "transport") return null;
  if (daemonMode === "retry-transport" && daemonCalls === 1) return null;
  return {{ port: 1, authToken: "fixture-token" }};
}}

async function recoverGuardDaemon() {{
  recoveryCalls += 1;
  return daemonMode === "retry-transport" || daemonMode === "retry-shape";
}}

async function runGuardCliCommand() {{
  cliCalls += 1;
  return cliResult;
}}

globalThis.fetch = async () => ({{
  ok: true,
  status: 200,
  text: async () => fetchBodies.shift() ?? "",
}});

{helper}

{daemon}

{run_guard}

const result = {{}};
daemonMode = "http";
fetchBodies = ["{{\\"decision\\":\\"allow\\"}}"];
result.daemon_allow = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = [
  "{{\\"decision\\":\\"allow\\",\\"policy_action\\":\\"allow\\",\\"reason_code\\":\\"fixture_lifecycle\\"}}",
];
result.daemon_lifecycle_allow = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
fetchBodies = ["{{\\"decision\\":\\"deny\\",\\"reason\\":\\"fixture block\\"}}"];
result.daemon_deny = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ["", "   "];
result.daemon_empty = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
result.daemon_whitespace = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ["not-json"];
result.daemon_malformed = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"decision":"deny","reason":{{"nested":true}}}}'];
result.daemon_malformed_reason = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"deny","reason":null}}'];
result.daemon_null_reason = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"decision":"deny"}}'];
result.daemon_omitted_reason = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"policy_action":"allow"}}'];
result.daemon_shape = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['[{{"decision":"allow"}}]'];
result.daemon_array = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"maybe"}}'];
result.daemon_unknown = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"block","reason":"fixture block"}}'];
result.daemon_block = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;

daemonMode = "retry-shape";
fetchBodies = ['{{"unknown":"first"}}', '{{"unknown":"second"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
cliResult = {{ status: 0, stdout: "", stderr: "" }};
result.retry_still_malformed = await runGuard({{ hook_event_name: "PreToolUse" }});
result.retry_still_malformed_daemon_calls = daemonCalls;
result.retry_still_malformed_recovery_calls = recoveryCalls;
result.retry_still_malformed_cli_calls = cliCalls;

daemonMode = "retry-shape";
fetchBodies = ['{{"decision":"deny","reason":{{"nested":true}}}}', '{{"decision":"deny","reason":{{"nested":true}}}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
result.retry_malformed_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
result.retry_malformed_reason_daemon_calls = daemonCalls;
result.retry_malformed_reason_recovery_calls = recoveryCalls;
result.retry_malformed_reason_cli_calls = cliCalls;

daemonMode = "retry-transport";
fetchBodies = ['{{"decision":"allow"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
result.retry_valid = await runGuard({{ hook_event_name: "PreToolUse" }});
result.retry_valid_daemon_calls = daemonCalls;
result.retry_valid_recovery_calls = recoveryCalls;
result.retry_valid_cli_calls = cliCalls;

daemonMode = "retry-shape";
fetchBodies = ['{{"decision":"allow"}}', '{{"decision":"allow"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
cliResult = {{
  status: 0,
  stdout: '{{"decision":"allow","model_output_action":"allow_original","reviewed_output_sha256":"cli-digest"}}',
  stderr: "",
}};
result.stale_daemon_cli_success = await runGuard({{ hook_event_name: "PostToolUse" }});
result.stale_daemon_cli_daemon_calls = daemonCalls;
result.stale_daemon_cli_recovery_calls = recoveryCalls;
result.stale_daemon_cli_calls = cliCalls;

daemonMode = "transport";
fetchBodies = [];
cliResult = {{ status: 0, stdout: '{{"policy_action":"allow"}}', stderr: "" }};
result.cli_missing_decision = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: "", stderr: "" }};
result.cli_empty_prompt = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
result.cli_empty_post = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":{{"nested":true}}}}', stderr: "" }};
result.cli_malformed_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":null}}', stderr: "" }};
result.cli_null_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny"}}', stderr: "" }};
result.cli_omitted_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"allow","policy_action":"allow"}}', stderr: "" }};
result.cli_lifecycle_allow = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
cliResult = {{ status: 0, stdout: '{{"decision":"allow"}}', stderr: "" }};
result.cli_allow = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":"fixture block"}}', stderr: "" }};
result.cli_deny = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"block","reason":"fixture block"}}', stderr: "" }};
result.cli_block_prompt = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
result.cli_block_post = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 2, stdout: '{{"decision":"allow"}}', stderr: "cli failed" }};
result.cli_nonzero_allow = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: null, stdout: '{{"decision":"allow"}}', stderr: "" }};
result.cli_signal_allow = await runGuard({{ hook_event_name: "PreToolUse" }});

console.log(JSON.stringify(result));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-hook-contract-", delete=False) as fixture:
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


def _run_generated_tool_result_fixture(source: str) -> dict[str, object]:
    handler_start = source.index('  pi.on("tool_result"')
    handler_end = source.index("\n  });\n}", handler_start) + len("\n  });")
    handler = source[handler_start:handler_end]
    for old, new in {
        "(event as { input?: Record<string, unknown> })": "event",
        "(event as { toolInput?: Record<string, unknown> })": "event",
        "(event as { arguments?: Record<string, unknown> })": "event",
        "event as Record<string, unknown>": "event",
        "const guardPayload: Record<string, unknown>": "const guardPayload",
        " as string": "",
    }.items():
        handler = handler.replace(old, new)

    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_CONFIG_PATH = "/tmp/omp-hook-contract/settings.json";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const blockedToolResults = new Map();
const handlers = {{}};
const notifications = [];
let guardResponse = {{ decision: "allow", model_output_action: "allow_original" }};

function digestOutputText(value) {{
  const text = Array.isArray(value)
    ? value.map((item) => item && item.type === "text" ? item.text : "").join("")
    : "";
  const sha256 = createHash("sha256").update(text, "utf8").digest("hex");
  return {{
    sha256,
    chars: text.length,
    textForExcerpt: text.slice(0, GUARD_TEXT_LIMIT_CHARS),
    excerptTruncated: text.length > GUARD_TEXT_LIMIT_CHARS,
    traversalTruncated: false,
  }};
}}

function boundValue(value) {{
  if (!Array.isArray(value)) return {{ value, truncated: false }};
  let truncated = false;
  const bounded = value.map((item) => {{
    if (item && item.type === "text" && typeof item.text === "string" && item.text.length > GUARD_TEXT_LIMIT_CHARS) {{
      truncated = true;
      return {{ ...item, text: item.text.slice(0, GUARD_TEXT_LIMIT_CHARS) }};
    }}
    return item;
  }});
  return {{ value: bounded, truncated }};
}}

function boundedOutputText(value) {{
  const digest = digestOutputText(value);
  return {{ value: digest.textForExcerpt, truncated: digest.excerptTruncated }};
}}

function sourceFileRefForPostToolUse() {{ return null; }}
function toolCallIdKey(value) {{ return typeof value === "string" && value.trim() ? value.trim() : null; }}
function modelVisibleBlockedReason(reason) {{ return `blocked: ${{reason}}`; }}
function blockedToolResult(reason, details) {{
  return {{ content: [{{ type: "text", text: reason }}], details, isError: true }};
}}
function reviewedToolResult(content, details, isError) {{
  const result = {{ content, details }};
  if (isError) result.isError = true;
  return result;
}}
async function runGuard() {{ return guardResponse; }}
const pi = {{ on(name, handler) {{ handlers[name] = handler; }} }};
{handler}

const event = {{
  toolCallId: "fixture-call",
  toolName: "Bash",
  content: [{{ type: "text", text: "safe inline output" }}],
  details: {{ source: "fixture" }},
  isError: false,
}};
const ctx = {{ cwd: "/tmp", ui: {{ notify(message) {{ notifications.push(message); }} }} }};
const digest = digestOutputText(event.content).sha256;
const result = {{}};

guardResponse = {{ decision: "allow", model_output_action: "allow_original", reviewed_output_sha256: digest }};
result.valid = (await handlers.tool_result(event, ctx)) === undefined;
guardResponse = {{ decision: "allow", reviewed_output_sha256: digest }};
result.missing_directive = await handlers.tool_result(event, ctx);
guardResponse = {{
  decision: "allow",
  model_output_action: "replace_with_reviewed_excerpt",
  reviewed_output_sha256: digest,
}};
result.contradictory_directive = await handlers.tool_result(event, ctx);
guardResponse = {{ decision: "allow", model_output_action: "allow_original" }};
result.missing_digest = await handlers.tool_result(event, ctx);
guardResponse = {{ decision: "allow", model_output_action: "allow_original", reviewed_output_sha256: "0".repeat(64) }};
result.mismatched_digest = await handlers.tool_result(event, ctx);

const longEvent = {{ ...event, content: [{{ type: "text", text: "safe".repeat(13000) }}] }};
guardResponse = {{
  decision: "allow",
  model_output_action: "replace_with_reviewed_excerpt",
  notice: "excerpt",
  reason: "reviewed excerpt",
}};
result.reviewed_excerpt = await handlers.tool_result(longEvent, ctx);

guardResponse = {{ decision: "allow", observe_mode: true }};
result.observe_mode = (await handlers.tool_result(event, ctx)) === undefined;
console.log(JSON.stringify(result));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-tool-result-contract-", delete=False) as fixture:
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


def _generated_digest_helper(source: str) -> str:
    start = source.index("function digestOutputText(")
    end = source.index("\n\nfunction sourcePathFromToolInput(", start)
    helper = _strip_generated_types(source[start:end])
    for old, new in {
        "function digestOutputText(value: unknown): OutputDigest {": "function digestOutputText(value) {",
        "  function update(text: string): void {": "  function update(text) {",
        "  function traverse(val: unknown, depth: number): void {": "  function traverse(val, depth) {",
        "const seen = new WeakSet<object>();": "const seen = new WeakSet();",
        "const obj = val as object;": "const obj = val;",
        "const record = val as Record<string, unknown>;": "const record = val;",
    }.items():
        helper = helper.replace(old, new)
    return helper


def _run_generated_callback_payload(
    source: str,
    content: list[dict[str, object]],
    guard_response: dict[str, object],
) -> dict[str, object]:
    handler_start = source.index('  pi.on("tool_result"')
    handler_end = source.index("\n  });\n}", handler_start) + len("\n  });")
    handler = source[handler_start:handler_end]
    for old, new in {
        "(event as { input?: Record<string, unknown> })": "event",
        "(event as { toolInput?: Record<string, unknown> })": "event",
        "(event as { arguments?: Record<string, unknown> })": "event",
        "event as Record<string, unknown>": "event",
        "const guardPayload: Record<string, unknown>": "const guardPayload",
        " as string": "",
    }.items():
        handler = handler.replace(old, new)

    event_json = json.dumps(
        {
            "toolCallId": "fixture-call",
            "toolName": "Bash",
            "content": content,
            "details": {"source": "fixture"},
            "isError": False,
        }
    )
    response_json = json.dumps(guard_response)
    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_CONFIG_PATH = "/tmp/omp-hook-contract/settings.json";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"];
const blockedToolResults = new Map();
const handlers = {{}};
const notifications = [];
let capturedPayload = null;
let capturedSerializedPayload = null;
const guardResponse = JSON.parse({json.dumps(response_json)});

{_generated_digest_helper(source)}

function boundValue(value) {{ return {{ value, truncated: false }}; }}
function boundedOutputText(value) {{
  const digest = digestOutputText(value);
  return {{ value: digest.textForExcerpt, truncated: digest.excerptTruncated }};
}}
function sourceFileRefForPostToolUse() {{ return null; }}
function toolCallIdKey(value) {{ return typeof value === "string" && value.trim() ? value.trim() : null; }}
function modelVisibleBlockedReason(reason) {{ return `blocked: ${{reason}}`; }}
function blockedToolResult(reason, details) {{
  return {{ content: [{{ type: "text", text: reason }}], details, isError: true }};
}}
function reviewedToolResult(content, details, isError) {{
  return isError ? {{ content, details, isError: true }} : {{ content, details }};
}}
async function runGuard(payload) {{
  capturedSerializedPayload = JSON.stringify(payload);
  capturedPayload = JSON.parse(JSON.stringify(payload));
  return guardResponse;
}}
const pi = {{ on(name, handler) {{ handlers[name] = handler; }} }};
{handler}

const event = JSON.parse({json.dumps(event_json)});
const ctx = {{ cwd: "/tmp", ui: {{ notify(message) {{ notifications.push(message); }} }} }};
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
    content: list[dict[str, object]],
    path: Path,
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
    )
    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_CONFIG_PATH = "/tmp/omp-hook-contract/settings.json";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES = new Set(["Read"]);
const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"];

{_generated_digest_helper(source)}
{source_path}
{virtual}
{source_ref}

const event = {{ toolName: "Read" }};
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


def test_canonical_omp_allow_deny_and_lifecycle_shapes() -> None:
    allow = harness_json_from_native_pre_tool(
        "omp",
        {"decision": "allow", "minimum_action": "allow", "reason_code": "fixture_allow"},
    )
    deny = harness_json_from_native_pre_tool(
        "omp",
        {
            "decision": "deny",
            "minimum_action": "block",
            "reason": "fixture block",
            "reason_code": "fixture_block",
        },
    )
    lifecycle = observe_lifecycle_fail_safe_response(
        "omp",
        event_name="UserPromptSubmit",
        reason_code="fixture_lifecycle",
    )

    assert allow["decision"] == "allow"
    assert deny["decision"] == "deny"
    assert lifecycle == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "fixture_lifecycle",
    }


def test_generated_omp_rejects_ambiguous_success_and_preserves_retry_semantics(tmp_path: Path) -> None:
    result = _run_generated_fixture(_generated_source(tmp_path))

    assert result["daemon_allow"] == {"decision": "allow"}
    assert result["daemon_lifecycle_allow"] == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "fixture_lifecycle",
    }
    assert result["daemon_deny"] == {"decision": "deny", "reason": "fixture block"}
    assert result["daemon_empty"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_whitespace"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_malformed"] == {
        "decision": "deny",
        "reason": "HOL Guard received an invalid response from the authenticated local daemon.",
        "reason_code": "daemon_invalid_response",
    }
    assert result["daemon_malformed_reason"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_null_reason"] == {"decision": "deny", "reason": None}
    assert result["daemon_omitted_reason"] == {"decision": "deny"}
    assert result["daemon_shape"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_array"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_unknown"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_block"] == {"decision": "deny", "reason": "fixture block"}

    assert result["retry_still_malformed"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["retry_still_malformed_daemon_calls"] == 2
    assert result["retry_still_malformed_recovery_calls"] == 1
    assert result["retry_still_malformed_cli_calls"] == 1

    assert result["retry_malformed_reason"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["retry_malformed_reason_daemon_calls"] == 2
    assert result["retry_malformed_reason_recovery_calls"] == 1
    assert result["retry_malformed_reason_cli_calls"] == 1

    assert result["retry_valid"] == {"decision": "allow"}
    assert result["retry_valid_daemon_calls"] == 2
    assert result["retry_valid_recovery_calls"] == 1
    assert result["retry_valid_cli_calls"] == 0
    assert result["stale_daemon_cli_success"] == {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": "cli-digest",
    }
    assert result["stale_daemon_cli_daemon_calls"] == 2
    assert result["stale_daemon_cli_recovery_calls"] == 1
    assert result["stale_daemon_cli_calls"] == 1

    assert result["cli_missing_decision"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_empty_prompt"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_empty_post"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_malformed_reason"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_null_reason"] == {"decision": "deny", "reason": None}
    assert result["cli_omitted_reason"] == {"decision": "deny"}
    assert result["cli_lifecycle_allow"] == {"decision": "allow", "policy_action": "allow"}
    assert result["cli_allow"] == {"decision": "allow"}
    assert result["cli_deny"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_block_prompt"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_block_post"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_nonzero_allow"] == {"decision": "deny", "reason": "cli failed"}
    assert result["cli_signal_allow"] == {"decision": "deny", "reason": "Blocked by HOL Guard."}


def test_generated_omp_tool_result_requires_post_tool_output_proof(tmp_path: Path) -> None:
    result = _run_generated_tool_result_fixture(_generated_source(tmp_path))

    assert result["valid"] is True
    for key in ("missing_directive", "contradictory_directive", "missing_digest", "mismatched_digest"):
        assert result[key]["isError"] is True
    assert result["reviewed_excerpt"]["content"][0]["text"] == "safe" * 3000
    assert result["observe_mode"] is True


def test_generated_omp_payload_matches_real_python_review(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    scanner = ContentScanner()
    cache = HookDecisionCache(store)
    engine = HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=lambda guard_home, workspace: GuardConfig(
            guard_home=guard_home,
            workspace=workspace,
        ),
    )
    cases = (
        ([{"type": "text", "text": "plain output"}], "plain output"),
        (
            [
                {"type": "text", "text": "first"},
                {"type": "image", "data": "ignored"},
                {"type": "text", "text": "second"},
            ],
            "firstsecond",
        ),
        ([], ""),
        ([{"type": "text", "text": "astral 🌋 output"}], "astral 🌋 output"),
        ([{"type": "text", "text": " first\r\nsecond \r\n"}], " first\r\nsecond \r\n"),
    )

    for content, expected_text in cases:
        captured = _run_generated_callback_payload(
            source,
            content,
            {"decision": "deny", "reason": "capture"},
        )
        serialized_payload = captured["serialized_payload"]
        assert isinstance(serialized_payload, str)
        payload = json.loads(serialized_payload)
        assert payload["tool_response"] == content
        assert "stdout" not in payload

        response = engine.review(
            HookReviewRequest(
                harness="omp",
                event_name="PostToolUse",
                payload=payload,
                payload_kind="inline",
                config_path=None,
                cwd=tmp_path,
                home_dir=tmp_path / "home",
                guard_home=tmp_path / "guard-home",
                source_scope="project",
            )
        )
        assert response.decision == "allow"
        assert response.model_output_action == "allow_original"
        assert response.reviewed_output_sha256 == sha256_text(expected_text)

        accepted = _run_generated_callback_payload(source, content, response.to_harness_json())
        assert accepted["preserved"] is True

        recording_only = _watch_native_post_tool_result(
            {
                "decision": "deny",
                "model_output_action": "block",
                "policy_action": "block",
                "reason": "output requires review",
            },
            payload,
        )
        assert recording_only["decision"] == "allow"
        assert recording_only["model_output_action"] == "allow_original"
        assert recording_only["reviewed_output_sha256"] == sha256_text(expected_text)
        assert "observe_mode" not in recording_only
        accepted_recording = _run_generated_callback_payload(source, content, recording_only)
        assert accepted_recording["preserved"] is True


def test_generated_unicode_source_ref_matches_python_fast_path(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    path = source_dir / "fixture.txt"
    text = "first 🌋 line\r\nsecond line\n"
    path.write_bytes(text.encode("utf-8"))
    generated = _run_generated_source_ref_fixture(
        source,
        [{"type": "text", "text": text}],
        Path("src/fixture.txt"),
    )

    digest = generated["digest"]
    source_ref = generated["sourceRef"]
    assert isinstance(digest, dict)
    assert isinstance(source_ref, dict)
    assert digest["chars"] == len(text)
    assert source_ref["output_chars"] == len(text)
    assert source_ref["output_sha256"] == sha256_text(text)

    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/fixture.txt"},
        "tool_response": text,
        "guard_source_ref": source_ref,
    }
    source_ref_model = HookSourceFileRef(
        version=source_ref["version"],
        path=source_ref["path"],
        output_sha256=source_ref["output_sha256"],
        output_chars=source_ref["output_chars"],
        tool_input_path=source_ref["tool_input_path"],
    )
    store = GuardStore(tmp_path / "guard-home")
    scanner = ContentScanner()
    cache = HookDecisionCache(store)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path)
    request = HookReviewRequest(
        harness="omp",
        event_name="PostToolUse",
        payload=payload,
        payload_kind="source_file_ref",
        config_path=None,
        cwd=tmp_path,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        source_scope="project",
        source_ref=source_ref_model,
    )
    envelope = normalize_harness_payload(
        "omp",
        "PostToolUse",
        payload,
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    fast_path = evaluate_source_file_ref(
        request=request,
        envelope=envelope,
        scanner=scanner,
        cache=cache,
        config=config,
        store=store,
        deadline_monotonic=time.monotonic() + 2,
    )
    assert fast_path.status == "allow_original", (
        fast_path.reason_code,
        source_ref,
        envelope.target_paths,
    )
    assert fast_path.proof is not None
    assert fast_path.proof.output_sha256 == sha256_text(text)

    response = HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=lambda guard_home, workspace: config,
    ).review(request)
    assert response.decision == "allow"
    assert response.model_output_action == "allow_original"
    assert response.reviewed_output_sha256 == sha256_text(text)


def test_generated_large_non_source_result_returns_reviewed_excerpt(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    large_text = "x" * (5 * 1024 * 1024 + 1)
    content = [{"type": "text", "text": large_text}]
    captured = _run_generated_callback_payload(
        source,
        content,
        {"decision": "deny", "reason": "capture"},
    )
    serialized_payload = captured["serialized_payload"]
    assert isinstance(serialized_payload, str)
    payload = json.loads(serialized_payload)
    assert payload["tool_response"] == content
    assert "stdout" not in payload

    store = GuardStore(tmp_path / "guard-home")
    scanner = ContentScanner()
    cache = HookDecisionCache(store)
    engine = HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=lambda guard_home, workspace: GuardConfig(
            guard_home=guard_home,
            workspace=workspace,
        ),
    )
    response = engine.review(
        HookReviewRequest(
            harness="omp",
            event_name="PostToolUse",
            payload=payload,
            payload_kind="inline",
            config_path=None,
            cwd=tmp_path,
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            source_scope="project",
        )
    )
    assert response.decision == "allow"
    assert response.model_output_action == "replace_with_reviewed_excerpt"
    assert response.reviewed_excerpt

    callback = _run_generated_callback_payload(source, content, response.to_harness_json())
    assert callback["preserved"] is False
    result = callback["result"]
    assert isinstance(result, dict)
    assert "isError" not in result
    assert result["content"] == [{"type": "text", "text": large_text[:12000]}]
