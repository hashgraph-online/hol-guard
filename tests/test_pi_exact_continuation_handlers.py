"""Generated Pi-family tool-call approval continuation coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from tests.pi_continuation_support import (
    _decode_json_object,
    _handler_fragment,
    _node_executable,
    _run_child,
)


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_generated_tool_call_awaits_exact_approval_without_replanning(
    tmp_path: Path,
    harness: str,
) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to execute the generated handler")

    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name="fixture",
    )
    assert "freezeSnapshot" in source
    assert "handlerAbortSignal(ctx)" in source
    assert "approvalContinuationFailureReason" in source
    assert "scheduleApprovalResume(response, ctx, { kind: 'tool_call'" not in source
    handler = _handler_fragment(source)
    script = f"""
const harness = {json.dumps(harness)};
const GUARD_CONFIG_PATH = '/fixture/settings.json';
const openedApprovalUrls = new Set();
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let activeScenario;
let activeSessionId;
let sentMessages = [];
const handlers = new Map();
const pi = {{
  on: (event, handler) => handlers.set(event, handler),
  sendMessage: (...args) => sentMessages.push(args),
}};

function snapshotToolCall(event, ctx) {{
  const payload = {{
    hook_event_name: 'PreToolUse',
    config_path: GUARD_CONFIG_PATH,
    tool_call_id: event.toolCallId,
    session_id: ctx.sessionManager.getSessionId(),
    tool_name: event.toolName,
    tool_input: JSON.parse(JSON.stringify(event.input)),
  }};
  return {{ payload, canonicalPayload: JSON.stringify(payload), cwd: ctx.cwd }};
}}
function toolCallStillMatches(event, ctx, _configPath, snapshot) {{
  const current = {{
    hook_event_name: 'PreToolUse',
    config_path: GUARD_CONFIG_PATH,
    tool_call_id: event.toolCallId,
    session_id: ctx.sessionManager.getSessionId(),
    tool_name: event.toolName,
    tool_input: event.input,
  }};
  return ctx.cwd === snapshot.cwd && JSON.stringify(current) === snapshot.canonicalPayload;
}}
function handlerAbortSignal(ctx) {{ return ctx.signal; }}
function handlerContinuationActivity(ctx) {{
  return typeof ctx.isIdle === 'function' ? () => ctx.isIdle() === false : undefined;
}}
function continuationIsActive(activity) {{ return !activity || activity(); }}
function approvalContinuationActivity() {{
  return () => !activeScenario.hostAborted;
}}
function approvalRequestId(response) {{ return response.approval_request_id ?? null; }}
function approvalPollPath(response, requestId) {{ return response.resume_poll_path ?? `/v1/requests/${{requestId}}`; }}
function approvalBlockedReason(_response, fallback, _kind, continuation = 'exact') {{
  return continuation === 'replan' ? `unsupported-${{fallback}}` : fallback;
}}
function approvalContinuationFailureReason(_response, result) {{ return `continuation-${{result}}`; }}
function ompInteractiveContext(ctx) {{
  return harness === 'omp' && ctx.mode === 'tui' && typeof ctx.ui?.custom === 'function';
}}
async function runOmpInteractiveContinuation(ctx, operation) {{
  if (!ompInteractiveContext(ctx)) return {{ kind: 'unavailable' }};
  const controller = new AbortController();
  try {{
    const value = await ctx.ui.custom(
      async (_terminal, _theme, _keybindings, done) => {{
        const result = await operation(controller.signal);
        done(result);
        return {{ dispose() {{}} }};
      }},
      {{ signal: controller.signal }},
    );
    return {{ kind: 'completed', value }};
  }} catch (_error) {{
    return {{ kind: 'aborted' }};
  }}
}}
function scheduleApprovalResume(_response, _ctx, _details) {{ activeScenario.scheduleCalls += 1; }}
async function openApprovalUrl() {{}}
async function pollApprovalResolution(_requestId, _pollPath, signal, activity) {{
  activeScenario.pollCalls += 1;
  if (!continuationIsActive(activity)) return 'aborted';
  const response = activeScenario.pollQueue.shift() ?? 'timeout';
  if (response === 'pending') {{
    return new Promise((resolve) => {{
      const timer = setTimeout(() => resolve(
        continuationIsActive(activity) ? (activeScenario.pollQueue.shift() ?? 'timeout') : 'aborted',
      ), 20);
      signal?.addEventListener('abort', () => {{ clearTimeout(timer); resolve('aborted'); }}, {{ once: true }});
    }});
  }}
  return response;
}}
async function runGuard(payload) {{
  activeScenario.guardCalls += 1;
  activeScenario.payloads.push(payload);
  return activeScenario.guardResponses[Math.min(
    activeScenario.guardCalls - 1,
    activeScenario.guardResponses.length - 1,
  )];
}}
async function ensureGuardWorkspaceReady() {{ return {{ ready: true }}; }}
function readinessFailureReason(readiness) {{ return `readiness-${{readiness.reasonCode}}`; }}

{handler}

async function runScenario(name, guardResponses, pollResponses, options = {{}}) {{
  activeScenario = {{
    guardCalls: 0,
    pollCalls: 0,
    scheduleCalls: 0,
    hostAborted: false,
    guardResponses,
    pollQueue: [...pollResponses],
    payloads: [],
  }};
  activeSessionId = `session-${{name}}`;
  const notices = [];
  sentMessages = [];
  const generated = handlers.get('tool_call');
  const abortController = new AbortController();
  const event = {{
    toolCallId: `call-${{name}}`,
    toolName: 'read',
    input: {{ path: 'original.txt', offset: 304, limit: 243 }},
  }};
  const context = {{
    cwd: '/fixture/workspace',
    mode: 'tui',
    sessionManager: {{ getSessionId: () => activeSessionId }},
    isIdle: () => activeScenario.hostAborted,
    ui: {{
      notify: (message) => notices.push(String(message)),
      custom: async (factory) => {{
        let value;
        await factory({{}}, {{}}, {{}}, (result) => {{ value = result; }});
        return value;
      }},
    }},
    ...(harness === 'pi' ? {{ signal: abortController.signal }} : {{}}),
  }};
  const pending = generated(event, context);
  if (options.mutate) {{
    await delay(2);
    event.input.limit = 999;
  }}
  if (options.changeContext) {{
    await delay(2);
    context.cwd = '/fixture/changed-workspace';
    activeSessionId = `changed-${{name}}`;
  }}
  if (options.abort) {{
    await delay(2);
    activeScenario.hostAborted = true;
    abortController.abort();
  }}
  const result = await pending;
  const executed = result === undefined ? [{{ ...event.input }}] : [];
  return {{
    result: result === undefined ? null : result,
    executed,
    guardCalls: activeScenario.guardCalls,
    pollCalls: activeScenario.pollCalls,
    scheduleCalls: activeScenario.scheduleCalls,
    payloads: activeScenario.payloads,
    sentMessages: sentMessages.length,
    notices,
  }};
}}

const approval = {{
  decision: 'deny',
  reason: 'approval pending',
  approval_request_id: 'request-fixture',
  resume_poll_path: '/v1/requests/request-fixture',
}};
const allow = {{ decision: 'allow', reason: 'exact approval consumed' }};
const nativeFailure = {{ decision: 'deny', reason: 'native review failed', reason_code: 'native_failure' }};
const result = {{
  success: await runScenario('success', [approval, allow], ['allow']),
  denial: await runScenario('denial', [approval], ['block']),
  expired: await runScenario('expired', [approval], ['timeout']),
  transport: await runScenario('transport', [approval], ['transport']),
  mutation: await runScenario('mutation', [approval, allow], ['pending', 'allow'], {{ mutate: true }}),
  contextMutation: await runScenario('context', [approval, allow], ['pending', 'allow'], {{ changeContext: true }}),
  nativeFailure: await runScenario('native-failure', [nativeFailure], []),
}};
result.abort = await runScenario('abort', [approval], ['pending'], {{ abort: true }});
console.log(JSON.stringify(result));
"""
    harness_path = tmp_path / f"run-{harness}.mjs"
    harness_path.write_text(script, encoding="utf-8")
    completed = _run_child(
        [node, str(harness_path)],
        timeout=10,
    )
    payload = _decode_json_object(completed.stdout)

    success = payload["success"]
    assert isinstance(success, dict)
    assert success["result"] is None
    assert success["executed"] == [{"path": "original.txt", "offset": 304, "limit": 243}]
    assert success["guardCalls"] == 2
    assert success["pollCalls"] == 1
    assert success["scheduleCalls"] == 0
    assert success["payloads"][0]["tool_input"] == success["payloads"][1]["tool_input"]
    assert success["payloads"][0]["session_id"] == "session-success"
    assert success["sentMessages"] == 0

    for name in ("denial", "expired", "transport", "mutation", "contextMutation", "nativeFailure"):
        scenario = payload[name]
        assert isinstance(scenario, dict)
        assert scenario["result"]["block"] is True
        assert scenario["executed"] == []
        assert scenario["sentMessages"] == 0

    assert payload["mutation"]["guardCalls"] == 1
    assert payload["contextMutation"]["guardCalls"] == 1
    assert payload["nativeFailure"]["pollCalls"] == 0
    abort = payload["abort"]
    assert isinstance(abort, dict)
    assert abort["result"]["block"] is True
    assert "continuation-aborted" in " ".join(abort["notices"])
    assert abort["executed"] == []
    assert abort["guardCalls"] == 1
    assert abort["pollCalls"] == 1
    assert abort["scheduleCalls"] == 0


def test_generated_input_resume_cancels_after_session_change(tmp_path: Path) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to execute the generated input handler")
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="fixture",
    )
    start = source.index("  const blockedToolResults")
    end = source.index('\n  pi.on("tool_call"', start)
    input_source = source[start:end]
    harness_path = tmp_path / "input-resume.ts"
    script = f"""
const GUARD_CONFIG_PATH = '/fixture/settings.json';
function loadGuardDaemonConnection() {{ return {{stateId: 'fixture-daemon'}}; }}
async function daemonWorkspaceReadiness() {{ return {{ready: true, daemonStateId: 'fixture-daemon'}}; }}
const GUARD_TIMEOUT_MS = 4250, GUARD_DEADLINE_RESERVE_MS = 250;
function handlerAbortSignal(ctx) {{ return ctx.signal; }}
let activeScenario;
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function contextCwd(ctx) {{ return ctx.sessionManager.getCwd(); }}
function contextSessionId(ctx) {{ return ctx.sessionManager.getSessionId(); }}
function approvalRequestId(response) {{ return response.approval_request_id ?? null; }}
function approvalPollPath(response, requestId) {{ return response.resume_poll_path ?? `/v1/requests/${{requestId}}`; }}
function approvalBlockedReason(_response, fallback) {{ return fallback; }}
function approvalResumeMessage(details) {{ return details.prompt ?? ''; }}
async function openApprovalUrl() {{}}
async function pollApprovalResolution(_requestId, _pollPath, _signal, activity) {{
  activeScenario.pollCalls += 1;
  if (activeScenario.mode === 'replacement' && activeScenario.pollCalls === 1) {{
    await new Promise((resolve) => {{ activeScenario.releasePollA = resolve; }});
  }} else {{
    await delay(10);
  }}
  return activity && !activity() ? 'aborted' : 'allow';
}}
async function runGuard(payload) {{
  activeScenario.guardCalls += 1;
  const requestId = activeScenario.mode === 'replacement'
    ? 'request-same'
    : (payload.prompt === 'prompt-B' ? 'request-B' : 'request-A');
  return {{
    decision: 'deny',
    reason: 'approval pending',
    approval_request_id: requestId,
    resume_poll_path: `/v1/requests/${{requestId}}`,
  }};
}}

async function runScenario(changeContext) {{
  let sessionId = 'session-input';
  let cwd = '/fixture/workspace';
  activeScenario = {{ guardCalls: 0, pollCalls: 0, sentMessages: [], mode: 'single', releasePollA: null }};
  const handlers = new Map();
  const pi = {{
    on: (event, handler) => handlers.set(event, handler),
    sendMessage: (...args) => activeScenario.sentMessages.push(args),
  }};
  const ctx = {{
    cwd,
    sessionManager: {{ getCwd: () => cwd, getSessionId: () => sessionId }},
    ui: {{ notify: () => {{}} }},
  }};
{input_source}
  const result = await handlers.get('input')({{ source: 'interactive', text: 'read file' }}, ctx);
  if (result?.handled !== true) throw new Error('input was not handled');
  if (changeContext) {{
    sessionId = 'changed-session';
    cwd = '/fixture/changed-workspace';
  }}
  await delay(30);
  return {{ ...activeScenario, result }};
}}

async function runSameSessionReplacement() {{
  let sessionId = 'session-input';
  let cwd = '/fixture/workspace';
  activeScenario = {{ guardCalls: 0, pollCalls: 0, sentMessages: [], mode: 'replacement', releasePollA: null }};
  const handlers = new Map();
  const pi = {{
    on: (event, handler) => handlers.set(event, handler),
    sendMessage: (...args) => activeScenario.sentMessages.push(args),
  }};
  const ctx = {{
    cwd,
    sessionManager: {{ getCwd: () => cwd, getSessionId: () => sessionId }},
    ui: {{ notify: () => {{}} }},
  }};
{input_source}
  const first = handlers.get('input')({{ source: 'interactive', text: 'prompt-A' }}, ctx);
  while (activeScenario.pollCalls < 1) await delay(1);
  const second = handlers.get('input')({{ source: 'interactive', text: 'prompt-B' }}, ctx);
  const secondResult = await second;
  const secondPollStarted = activeScenario.pollCalls === 2;
  activeScenario.releasePollA();
  const firstResult = await first;
  await delay(30);
  return {{ ...activeScenario, firstResult, secondResult, secondPollStarted }};
}}

const sameContext = await runScenario(false);
const changedContext = await runScenario(true);
const sameSessionReplacement = await runSameSessionReplacement();
console.log(JSON.stringify({{ sameContext, changedContext, sameSessionReplacement }}));
"""
    harness_path.write_text(script, encoding="utf-8")
    completed = _run_child(
        [node, "--experimental-strip-types", str(harness_path)],
        timeout=10,
    )
    payload = _decode_json_object(completed.stdout)
    same_context = payload["sameContext"]
    changed_context = payload["changedContext"]
    assert isinstance(same_context, dict)
    assert isinstance(changed_context, dict)
    assert same_context["guardCalls"] == 1
    assert len(same_context["sentMessages"]) == 1
    assert changed_context["guardCalls"] == 1
    assert changed_context["sentMessages"] == []
    replacement = payload["sameSessionReplacement"]
    assert isinstance(replacement, dict)
    assert replacement["guardCalls"] == 2
    assert replacement["pollCalls"] == 2
    assert replacement["secondPollStarted"] is True
    assert replacement["firstResult"]["handled"] is True
    assert replacement["secondResult"]["handled"] is True
    assert len(replacement["sentMessages"]) == 1
    assert replacement["sentMessages"][0][0]["content"] == "prompt-B"
