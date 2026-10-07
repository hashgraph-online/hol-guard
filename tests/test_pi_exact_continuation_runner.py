"""Generated Pi-family tool-call approval continuation coverage."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from tests.pi_continuation_support import (
    _decode_json_object,
    _node_executable,
    _pi_runner_module,
    _run_child,
)


def test_installed_pi_runner_cancels_generated_pending_tool_call(tmp_path: Path) -> None:
    node = _node_executable()
    runner_module = _pi_runner_module()
    if node is None or runner_module is None:
        pytest.skip("Node and the installed Pi SDK are required")

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-state.json").write_text(
        json.dumps(
            {
                "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
                "port": 1,
                "state_id": "fixture-generation",
            }
        ),
        encoding="utf-8",
    )
    (guard_home / "daemon-auth-token").write_text("fixture-token", encoding="utf-8")
    extension_path = tmp_path / "hol-guard-pi.ts"
    extension_path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=tmp_path,
            settings_path=tmp_path / "settings.json",
            harness="pi",
            display_name="fixture",
        ),
        encoding="utf-8",
    )
    harness_path = tmp_path / "installed-pi-runner.mjs"
    script = f"""
import {{ pathToFileURL }} from 'node:url';
import installGuard from {json.dumps(str(extension_path))};
const {{ ExtensionRunner, createExtensionRuntime }} = await import(
  pathToFileURL({json.dumps(str(runner_module))}).href,
);
let guardCalls = 0;
let pollCalls = 0;
globalThis.fetch = async (url) => {{
  if (String(url).includes('/readiness')) {{
    return new Response(JSON.stringify({{ ready: true }}), {{ status: 200 }});
  }}
  if (String(url).includes('/v1/hooks/')) {{
    guardCalls += 1;
    return new Response(JSON.stringify({{
      decision: 'deny',
      reason: 'approval pending',
      approval_request_id: 'request-fixture',
      resume_poll_path: '/v1/requests/request-fixture',
    }}), {{ status: 200 }});
  }}
  pollCalls += 1;
  return new Response(JSON.stringify({{ status: 'pending' }}), {{ status: 200 }});
}};
const handlers = new Map();
const sentMessages = [];
installGuard({{
  on: (event, handler) => handlers.set(event, handler),
  sendMessage: (...args) => sentMessages.push(args),
}});
const handler = handlers.get('tool_call');
const extensionHandlers = new Map();
for (const event of ['session_start', 'agent_start', 'tool_call']) {{
  const registered = handlers.get(event);
  if (registered) extensionHandlers.set(event, [registered]);
}}
const extension = {{
  path: 'fixture',
  resolvedPath: 'fixture',
  sourceInfo: {{}},
  handlers: extensionHandlers,
  tools: new Map(),
  messageRenderers: new Map(),
  commands: new Map(),
  flags: new Map(),
  shortcuts: new Map(),
}};
const runtime = createExtensionRuntime();
const controller = new AbortController();
const runner = new ExtensionRunner([extension], runtime, '/fixture/workspace', {{
  getCwd: () => '/fixture/workspace',
  getSessionId: () => 'session-fixture',
}}, {{}});
runner.bindCore(
  {{
    sendMessage: () => {{}}, sendUserMessage: () => {{}}, appendEntry: () => {{}},
    setSessionName: () => {{}}, getSessionName: () => undefined, setLabel: () => {{}},
    getActiveTools: () => [], getAllTools: () => [], setActiveTools: () => {{}},
    refreshTools: () => {{}}, getCommands: () => [], setModel: async () => false,
    getThinkingLevel: () => 'high', setThinkingLevel: () => {{}},
  }},
  {{
    getModel: () => undefined, isIdle: () => false, isProjectTrusted: () => true,
    getSignal: () => controller.signal, abort: () => controller.abort(),
    hasPendingMessages: () => false, shutdown: () => {{}}, getContextUsage: () => undefined,
    compact: () => {{}}, getSystemPrompt: () => '',
  }},
);
await runner.emit({{ type: 'session_start' }});
const event = {{
  type: 'tool_call', toolCallId: 'call-fixture', toolName: 'read',
  input: {{ path: 'original.txt', offset: 304, limit: 243 }},
}};
const resultPromise = runner.emitToolCall(event);
while (pollCalls === 0) await new Promise((resolve) => setTimeout(resolve, 1));
controller.abort();
const result = await resultPromise;
const invalidEvent = {{
  type: 'tool_call', toolCallId: 'call-invalid', toolName: 'read',
  input: {{ path: 'invalid.txt', unsupported: undefined }},
}};
const invalidResult = await runner.emitToolCall(invalidEvent);
const nonFiniteEvent = {{
  type: 'tool_call', toolCallId: 'call-non-finite', toolName: 'read',
  input: {{ path: 'non-finite.txt', offset: Number.NaN }},
}};
const nonFiniteResult = await runner.emitToolCall(nonFiniteEvent);
const invalidShapeEvent = {{
  type: 'tool_call', toolCallId: 'call-invalid-shape', toolName: 'read',
  input: ['not', 'an', 'object'],
}};
const invalidShapeResult = await runner.emitToolCall(invalidShapeEvent);
console.log(JSON.stringify({{
  blocked: result?.block === true,
  invalidBlocked: invalidResult?.block === true,
  nonFiniteBlocked: nonFiniteResult?.block === true,
  invalidShapeBlocked: invalidShapeResult?.block === true,
  guardCalls,
  pollCalls,
  sentMessages: sentMessages.length,
  input: event.input,
}}));
"""
    harness_path.write_text(script, encoding="utf-8")
    completed = _run_child(
        [node, "--experimental-strip-types", str(harness_path)],
        timeout=15,
    )
    payload = _decode_json_object(completed.stdout)
    assert payload == {
        "blocked": True,
        "invalidBlocked": True,
        "nonFiniteBlocked": True,
        "invalidShapeBlocked": True,
        "guardCalls": 1,
        "pollCalls": 1,
        "sentMessages": 0,
        "input": {"path": "original.txt", "offset": 304, "limit": 243},
    }


def test_actual_pi_runner_survives_five_second_tool_call_handler(tmp_path: Path) -> None:
    node = _node_executable()
    runner_module = _pi_runner_module()
    if node is None or runner_module is None:
        pytest.skip("Node and the installed Pi SDK are required")

    harness_path = tmp_path / "installed-pi-handler-timeout.mjs"
    script = f"""
import {{ pathToFileURL }} from 'node:url';
const {{ ExtensionRunner, createExtensionRuntime }} = await import(
  pathToFileURL({json.dumps(str(runner_module))}).href,
);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const handler = async () => {{
  const deadline = performance.now() + 5_500;
  while (performance.now() < deadline) {{
    await delay(Math.ceil(deadline - performance.now()));
  }}
  return undefined;
}};
const extension = {{
  path: 'fixture',
  resolvedPath: 'fixture',
  sourceInfo: {{}},
  handlers: new Map([['tool_call', [handler]]]),
  tools: new Map(),
  messageRenderers: new Map(),
  commands: new Map(),
  flags: new Map(),
  shortcuts: new Map(),
}};
const runtime = createExtensionRuntime();
const runner = new ExtensionRunner([extension], runtime, '/fixture/workspace', {{
  getCwd: () => '/fixture/workspace',
  getSessionId: () => 'session-fixture',
}}, {{}});
runner.bindCore(
  {{
    sendMessage: () => {{}}, sendUserMessage: () => {{}}, appendEntry: () => {{}},
    setSessionName: () => {{}}, getSessionName: () => undefined, setLabel: () => {{}},
    getActiveTools: () => [], getAllTools: () => [], setActiveTools: () => {{}},
    refreshTools: () => {{}}, getCommands: () => [], setModel: async () => false,
    getThinkingLevel: () => 'high', setThinkingLevel: () => {{}},
  }},
  {{
    getModel: () => undefined, isIdle: () => false, isProjectTrusted: () => true,
    getSignal: () => undefined, abort: () => {{}}, hasPendingMessages: () => false,
    shutdown: () => {{}}, getContextUsage: () => undefined, compact: () => {{}},
    getSystemPrompt: () => '',
  }},
);
const event = {{
  type: 'tool_call', toolCallId: 'call-fixture', toolName: 'read',
  input: {{ path: 'original.txt', offset: 304, limit: 243 }},
}};
const started = performance.now();
const result = await runner.emitToolCall(event);
const elapsedMs = performance.now() - started;
console.log(JSON.stringify({{
  result: result ?? null,
  elapsedMs,
  input: event.input,
}}));
"""
    harness_path.write_text(script, encoding="utf-8")
    completed = _run_child(
        [node, "--experimental-strip-types", str(harness_path)],
        timeout=30,
    )
    payload = _decode_json_object(completed.stdout)
    assert payload["result"] is None
    assert payload["elapsedMs"] >= 5_500
    assert payload["elapsedMs"] < 25_000
    assert payload["input"] == {"path": "original.txt", "offset": 304, "limit": 243}


def test_installed_omp_runner_contract_is_outer_signal_aware() -> None:
    omp_cli = shutil.which("omp")
    if omp_cli is None:
        pytest.skip("The installed OMP SDK is required")
    package = Path(omp_cli).resolve().parents[1]
    runner_path = package / "src" / "extensibility" / "extensions" / "runner.ts"
    types_path = package / "src" / "extensibility" / "extensions" / "types.ts"
    session_path = package / "src" / "session" / "agent-session.ts"
    if not runner_path.is_file() or not types_path.is_file() or not session_path.is_file():
        pytest.skip("Installed OMP source contract is unavailable")
    runner_source = runner_path.read_text(encoding="utf-8")
    types_source = types_path.read_text(encoding="utf-8")
    session_source = session_path.read_text(encoding="utf-8")
    assert "async emitToolCall(event: ToolCallEvent, signal?: AbortSignal)" in runner_source
    assert "EXTENSION_HANDLER_ABORTED" in runner_source
    assert "if (signal?.aborted)" in runner_source
    assert "runner.emitToolCall(" in session_source
    assert "if (callResult?.block)" in session_source
    assert "signal: this.#postPromptTasksAbortController.signal" in session_source
    assert 'on(event: "session_stop"' in types_source
    context_start = types_source.index("export interface ExtensionContext {")
    context_end = types_source.index("\n}\n", context_start)
    context_source = types_source[context_start:context_end]
    assert "\n\tsignal" not in context_source
    assert "\n\tisIdle(): boolean;" in context_source
