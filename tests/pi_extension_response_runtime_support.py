from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from tests.pi_extension_response_source_support import (
    _generated_preprocessing_helper,
    _generated_structured_helper,
    _strip_generated_types,
)


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
import {{ createHash }} from "node:crypto";

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
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = 24000;
const GUARD_MAX_SERIALIZED_RESPONSE_CHARS = 12 * GUARD_TEXT_LIMIT_CHARS + GUARD_MAX_SERIALIZED_PAYLOAD_CHARS;
const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"];
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

function responseBody(value) {{
  let used = false;
  return {{
    getReader() {{
      return {{
        async read() {{
          if (used) return {{ done: true, value: undefined }};
          used = true;
          return {{ done: false, value: new TextEncoder().encode(value) }};
        }},
        async cancel() {{ used = true; }},
        releaseLock() {{}},
      }};
    }},
  }};
}}

globalThis.fetch = async () => {{
  const value = fetchBodies.shift() ?? "";
  return {{
    ok: true,
    status: 200,
    body: responseBody(value),
    text: async () => value,
  }};
}};

{helper}

{_generated_preprocessing_helper(source)}

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
fetchBodies = ["x".repeat(GUARD_MAX_SERIALIZED_RESPONSE_CHARS + 1)];
result.daemon_oversized_body = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);

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

daemonMode = "http";
fetchBodies = ['{{"decision":"allow","reason_code":"native_policy_not_ready"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
result.posttool_daemon_allow = await runGuard({{ hook_event_name: "PostToolUse" }});
result.posttool_daemon_allow_daemon_calls = daemonCalls;
result.posttool_daemon_allow_recovery_calls = recoveryCalls;
result.posttool_daemon_allow_cli_calls = cliCalls;

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
    handler_start = source.index('  pi.on("tool_result", async (event, ctx) => {')
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
const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = 24000;
const GUARD_MAX_SERIALIZED_RESPONSE_CHARS = 12 * GUARD_TEXT_LIMIT_CHARS + GUARD_MAX_SERIALIZED_PAYLOAD_CHARS;
const GUARD_TIMEOUT_MS = 4250;
const GUARD_DEADLINE_RESERVE_MS = 250;
const GUARD_STRUCTURED_MAX_BYTES = 64 * 1024;
const GUARD_STRUCTURED_MAX_DEPTH = 8;
const GUARD_STRUCTURED_MAX_NODES = 128;
const GUARD_STRUCTURED_MAX_FIELDS = 64;
const blockedToolResults = new Map();
const handlers = {{}};
const notifications = [];
let guardResponse = {{ decision: "allow", model_output_action: "allow_original" }};

{_generated_preprocessing_helper(source)}
{_generated_structured_helper(source)}

function sourceFileRefForPostToolUse() {{ return null; }}
// Containment lifecycle is exercised separately with its real request map.
function cleanupContainedTestRequest() {{}}
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
function handlerAbortSignal(ctx) {{
  const candidate = ctx?.signal;
  return candidate && typeof candidate === "object" && typeof candidate.aborted === "boolean"
    && typeof candidate.addEventListener === "function" && typeof candidate.removeEventListener === "function"
    ? candidate : undefined;
}}
async function runGuard(payload, cwd, options) {{
  if (options?.enforceSizeCap === true && !payloadWithinSerializedBudget(payload)) {{
    return {{ decision: "deny", reason_code: "hook_payload_unbounded" }};
  }}
  return guardResponse;
}}
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
guardResponse = {{ decision: "allow", reason_code: "native_policy_not_ready" }};
result.missing_directive = (await handlers.tool_result(event, ctx)) === undefined;
guardResponse = {{
  decision: "allow",
  model_output_action: "replace_with_reviewed_excerpt",
  reviewed_excerpt: "reviewed-safe",
}};
result.contradictory_directive = await handlers.tool_result(event, ctx);
guardResponse = {{ decision: "allow", model_output_action: "replace_with_reviewed_excerpt" }};
result.missing_excerpt = await handlers.tool_result(event, ctx);
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
  reviewed_excerpt: "reviewed-long",
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


def _run_generated_preprocessing_fixture(source: str, body: str) -> dict[str, object]:
    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = 24000;
const GUARD_MAX_SERIALIZED_RESPONSE_CHARS = 12 * GUARD_TEXT_LIMIT_CHARS + GUARD_MAX_SERIALIZED_PAYLOAD_CHARS;

{_generated_preprocessing_helper(source)}

{body}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-preprocessing-contract-", delete=False) as fixture:
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
