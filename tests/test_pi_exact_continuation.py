"""Generated Pi-family tool-call approval continuation coverage."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION


def _node_executable() -> str | None:
    return shutil.which("node")


def _run_child(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if completed.returncode != 0:
        raise AssertionError(
            f"child process failed with exit code {completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


_PI_SDK_ROOT_ENV = "HOL_GUARD_PI_SDK_ROOT"
_PI_SDK_PACKAGE_NAME = "@earendil-works/pi-coding-agent"
_PI_SDK_PACKAGE_VERSION = "0.87.1"


def _pi_runner_module() -> Path | None:
    explicit_root = os.environ.get(_PI_SDK_ROOT_ENV)
    if explicit_root:
        root = Path(explicit_root)
        if not root.is_absolute():
            pytest.fail(f"{_PI_SDK_ROOT_ENV} must be an absolute job-local SDK root")
        try:
            resolved_root = root.resolve(strict=True)
            metadata = json.loads((resolved_root / "package.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            pytest.fail(f"{_PI_SDK_ROOT_ENV} does not point to a readable package: {error}")
        if not isinstance(metadata, dict):
            pytest.fail(f"{_PI_SDK_ROOT_ENV} package metadata is not an object")
        if metadata.get("name") != _PI_SDK_PACKAGE_NAME:
            pytest.fail(f"{_PI_SDK_ROOT_ENV} package identity is not {_PI_SDK_PACKAGE_NAME!r}")
        if metadata.get("version") != _PI_SDK_PACKAGE_VERSION:
            pytest.fail(f"{_PI_SDK_ROOT_ENV} package version is not {_PI_SDK_PACKAGE_VERSION!r}")
        runner_module = resolved_root / "dist" / "index.js"
        try:
            resolved_runner = runner_module.resolve(strict=True)
        except OSError as error:
            pytest.fail(f"{_PI_SDK_ROOT_ENV} package has no dist/index.js: {error}")
        if not resolved_runner.is_relative_to(resolved_root):
            pytest.fail(f"{_PI_SDK_ROOT_ENV} runner resolves outside its package root")
        return resolved_runner

    pi_cli = shutil.which("pi")
    if pi_cli is None:
        return None
    cli_path = Path(pi_cli).resolve()
    if not cli_path.is_file():
        return None
    if cli_path.parent.name == "dist":
        package_root = cli_path.parent.parent
    elif cli_path.parent.name == "bundle" and cli_path.parent.parent.name == "dist":
        package_root = cli_path.parent.parent.parent
    else:
        return None
    try:
        package_root = package_root.resolve(strict=True)
        metadata = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(metadata, dict):
        return None
    if metadata.get("name") != _PI_SDK_PACKAGE_NAME or metadata.get("version") != _PI_SDK_PACKAGE_VERSION:
        return None
    raw_bin = metadata.get("bin")
    if isinstance(raw_bin, str):
        bin_targets = (raw_bin,)
    elif isinstance(raw_bin, dict):
        bin_targets = tuple(value for value in raw_bin.values() if isinstance(value, str))
    else:
        bin_targets = ()
    if not any(
        (package_root / target).resolve() == cli_path and (package_root / target).resolve().is_relative_to(package_root)
        for target in bin_targets
    ):
        return None
    runner_module = package_root / "dist" / "index.js"
    try:
        resolved_runner = runner_module.resolve(strict=True)
    except OSError:
        return None
    return resolved_runner if resolved_runner.is_relative_to(package_root) else None


def _write_pi_package(root: Path, bin_target: str) -> Path:
    root.mkdir(parents=True)
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": _PI_SDK_PACKAGE_NAME,
                "version": _PI_SDK_PACKAGE_VERSION,
                "bin": {"pi": bin_target},
            }
        ),
        encoding="utf-8",
    )
    cli_path = root / bin_target
    cli_path.parent.mkdir(parents=True, exist_ok=True)
    cli_path.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    runner_module = root / "dist" / "index.js"
    runner_module.parent.mkdir(parents=True, exist_ok=True)
    runner_module.write_text("export {};\n", encoding="utf-8")
    return cli_path


def test_pi_runner_module_accepts_published_old_cli_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package_root = tmp_path / "old-layout"
    cli_path = _write_pi_package(package_root, "dist/cli.js")
    monkeypatch.delenv(_PI_SDK_ROOT_ENV, raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: str(cli_path) if name == "pi" else None)

    assert _pi_runner_module() == (package_root / "dist" / "index.js").resolve()


def test_pi_runner_module_accepts_published_nested_cli_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package_root = tmp_path / "nested-layout"
    cli_path = _write_pi_package(package_root, "dist/bundle/cli.js")
    monkeypatch.delenv(_PI_SDK_ROOT_ENV, raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: str(cli_path) if name == "pi" else None)

    assert _pi_runner_module() == (package_root / "dist" / "index.js").resolve()


def test_pi_runner_module_rejects_undeclared_package_wrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package_root = tmp_path / "package"
    _write_pi_package(package_root, "dist/bundle/cli.js")
    monkeypatch.delenv(_PI_SDK_ROOT_ENV, raising=False)
    wrapper_path = package_root / "shim" / "pi"
    wrapper_path.parent.mkdir()
    wrapper_path.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda name: str(wrapper_path) if name == "pi" else None)

    assert _pi_runner_module() is None


def test_generated_input_resume_guard_condition_is_closed(tmp_path: Path) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="pi",
        display_name="fixture",
    )
    assert re.search(
        r"if \(\n"
        r"      !requestId \|\|\n"
        r"      binding === null \|\|\n"
        r"      !inputApprovalResumeBindingIsActive\(ctx, binding\)\n"
        r"    \) return;",
        source,
    )


def _decode_json_object(stdout: str) -> dict[str, object]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    assert lines, stdout
    payload = json.loads(lines[-1])
    assert isinstance(payload, dict)
    return payload


def _handler_fragment(source: str) -> str:
    start = source.index('pi.on("tool_call", async (event, ctx) => {')
    end = source.index('\n  pi.on("message_end"', start)
    return source[start:end]


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_generated_extension_is_typescript_parseable(tmp_path: Path, harness: str) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to parse the generated extension")
    extension_path = tmp_path / f"hol-guard-{harness}.ts"
    extension_path.write_text(
        managed_extension_source(
            guard_home=tmp_path / "guard-home",
            home_dir=tmp_path,
            settings_path=tmp_path / "settings.json",
            harness=harness,
            display_name="fixture",
        ),
        encoding="utf-8",
    )
    _run_child(
        [node, "--experimental-strip-types", "--check", str(extension_path)],
        timeout=10,
    )


def test_generated_snapshot_preserves_proto_data_and_rejects_empty_session(tmp_path: Path) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to execute generated helpers")
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="fixture",
    )
    start = source.index("function canonicalJson")
    end = source.index("function approvalContinuationFailureReason", start)
    helper_source = source[start:end]
    harness_path = tmp_path / "snapshot-helpers.ts"
    script = f"""
{helper_source}
const protoInput = JSON.parse('{{"__proto__":{{"marker":"kept"}},"path":"original.txt"}}');
const protoCanonical = canonicalJson(protoInput);
const protoParsed = JSON.parse(protoCanonical);
const event = {{ toolCallId: 'call-fixture', toolName: 'read', input: {{ path: 'original.txt' }} }};
const emptySession = snapshotToolCall(event, {{
  sessionManager: {{ getCwd: () => '/fixture/workspace', getSessionId: () => '' }},
}}, '/fixture/settings.json');
const validSession = snapshotToolCall(event, {{
  sessionManager: {{ getCwd: () => '/fixture/workspace', getSessionId: () => 'session-fixture' }},
}}, '/fixture/settings.json');
console.log(JSON.stringify({{
  protoOwn: Object.prototype.hasOwnProperty.call(protoParsed, '__proto__'),
  protoCanonical: protoCanonical.includes('"__proto__"'),
  protoMarker: protoParsed.__proto__.marker,
  emptySessionRejected: emptySession === null,
  validSessionAccepted: validSession !== null,
}}));
"""
    harness_path.write_text(script, encoding="utf-8")
    completed = _run_child(
        [node, "--experimental-strip-types", str(harness_path)],
        timeout=10,
    )
    assert _decode_json_object(completed.stdout) == {
        "protoOwn": True,
        "protoCanonical": True,
        "protoMarker": "kept",
        "emptySessionRejected": True,
        "validSessionAccepted": True,
    }


def test_installed_pi_runner_cancels_generated_pending_tool_call(tmp_path: Path) -> None:
    node = _node_executable()
    runner_module = _pi_runner_module()
    if node is None or runner_module is None:
        pytest.skip("Node and the installed Pi SDK are required")

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1}),
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


def test_actual_omp_runner_executes_original_once_and_blocks_late_continuation(tmp_path: Path) -> None:
    bun = shutil.which("bun")
    omp_cli = shutil.which("omp")
    if bun is None or omp_cli is None:
        pytest.skip("Managed Bun and the installed OMP SDK are required")
    package = Path(omp_cli).resolve().parents[1]
    runner_path = package / "src" / "extensibility" / "extensions" / "runner.ts"
    if not runner_path.is_file():
        pytest.skip("Installed OMP runner source is unavailable")

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1}),
        encoding="utf-8",
    )
    (guard_home / "daemon-auth-token").write_text("fixture-token", encoding="utf-8")
    extension_path = tmp_path / "hol-guard-omp.ts"
    extension_path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=tmp_path,
            settings_path=tmp_path / "settings.json",
            harness="omp",
            display_name="fixture",
        ),
        encoding="utf-8",
    )
    harness_path = tmp_path / "installed-omp-runner.ts"
    script = """
import { pathToFileURL } from "node:url";
import installGuard from __EXTENSION_PATH__;
const { ExtensionRunner, testSetExtensionHandlerTimeoutMs } = await import(
  pathToFileURL(__RUNNER_PATH__).href,
);
testSetExtensionHandlerTimeoutMs(5_000);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const originalInput = { path: "original.txt", offset: 304, limit: 243 };

function waitFor(predicate, timeout = 1_000) {
  return (async () => {
    const started = Date.now();
    while (!predicate()) {
      if (Date.now() - started > timeout) throw new Error("timed out waiting for OMP fixture");
      await delay(1);
    }
  })();
}

function makeRunner(scenario) {
  const registered = new Map();
  const sentMessages = [];
  const pi = {
    on: (event, handler) => {
      const handlers = registered.get(event) ?? [];
      handlers.push(handler);
      registered.set(event, handlers);
    },
    sendMessage: (...args) => sentMessages.push(args),
  };
  installGuard(pi);
  const extension = {
    path: "fixture",
    resolvedPath: "fixture",
    sourceInfo: {},
    handlers: new Map(registered),
    tools: new Map(),
    messageRenderers: new Map(),
    commands: new Map(),
    flags: new Map(),
    shortcuts: new Map(),
    fileWriteFallbackHandlers: [],
    fileDeleteFallbackHandlers: [],
  };
  const sessionManager = {
    getCwd: () => scenario.cwd,
    getSessionId: () => scenario.sessionId,
  };
  const modelRegistry = { getAvailable: () => [] };
  const runner = new ExtensionRunner([extension], {}, scenario.cwd, sessionManager, modelRegistry);
  const ui = {
    notify: () => {},
    custom: async (factory, options = {}) => {
      let settled = false;
      let component;
      let resolveResult;
      let rejectResult;
      const result = new Promise((resolve, reject) => {
        resolveResult = resolve;
        rejectResult = reject;
      });
      const abort = () => {
        if (settled) return;
        settled = true;
        component?.dispose?.();
        rejectResult(options.signal?.reason ?? new DOMException("Dialog aborted", "AbortError"));
      };
      const done = (value) => {
        if (settled) return;
        settled = true;
        resolveResult(value);
      };
      if (options.signal?.aborted) {
        abort();
        return result;
      }
      options.signal?.addEventListener("abort", abort, { once: true });
      component = await factory({}, {}, {}, done);
      if (settled) component?.dispose?.();
      return await result.finally(() => options.signal?.removeEventListener("abort", abort));
    },
  };
  runner.initialize(
    {
      sendMessage: () => {},
      sendUserMessage: () => {},
      appendEntry: () => {},
      getActiveTools: () => [],
      getAllTools: () => [],
      setActiveTools: async () => {},
      getCommands: () => [],
      setModel: () => {},
      getThinkingLevel: () => "off",
      setThinkingLevel: () => {},
      getSessionName: () => undefined,
      setSessionName: () => {},
    },
    {
      getModel: () => undefined,
      isIdle: () => false,
      abort: () => {},
      hasPendingMessages: () => false,
      shutdown: async () => {},
      getContextUsage: () => undefined,
      compact: async () => {},
      getSystemPrompt: () => "",
    },
    undefined,
    ui,
    scenario.mode ?? "tui",
  );
  return { runner, sentMessages };
}

async function runScenario(name, config) {
  const scenario = {
    cwd: "/fixture/workspace",
    sessionId: `session-${name}`,
    mode: config.mode,
  };
  let event;
  let guardCalls = 0;
  let pollCalls = 0;
  let activeController;
  globalThis.fetch = async (url) => {
    const text = String(url);
    if (text.includes("/v1/hooks/")) {
      const response = config.guardResponses[Math.min(guardCalls, config.guardResponses.length - 1)];
      guardCalls += 1;
      if (config.abortDuringRevalidation && guardCalls === 2) {
        await delay(20);
        activeController?.abort();
      }
      return new Response(JSON.stringify(response), { status: 200 });
    }
    pollCalls += 1;
    if (config.mutateInput) event.input.limit = 999;
    if (config.mutateContext) {
      scenario.cwd = "/fixture/changed-workspace";
      scenario.sessionId = `changed-${name}`;
    }
    if (config.poll === "pending") {
      const pendingPolls = config.pendingPolls ?? 1;
      if (pollCalls <= pendingPolls) return new Response(JSON.stringify({ status: "pending" }), { status: 200 });
      return new Response(JSON.stringify({ status: "resolved", resolution_action: "allow" }), { status: 200 });
    }
    if (config.poll === "allow") {
      return new Response(JSON.stringify({ status: "resolved", resolution_action: "allow" }), { status: 200 });
    }
    if (config.poll === "block") {
      return new Response(JSON.stringify({ status: "resolved", resolution_action: "block" }), { status: 200 });
    }
    if (config.poll === "expiry") return new Response("", { status: 404 });
    return new Response("", { status: 503 });
  };

  const { runner, sentMessages } = makeRunner(scenario);
  event = {
    type: "tool_call",
    toolCallId: `call-${name}`,
    toolName: "read",
    input: { ...originalInput },
  };
  const controller = new AbortController();
  activeController = controller;
  const started = performance.now();
  const pending = runner.emitToolCall(event, controller.signal);
  if (config.abort) {
    await waitFor(() => pollCalls === 1);
    controller.abort();
  }
  if (config.sessionStop) {
    await waitFor(() => pollCalls === 1);
    await runner.emitSessionStop({ signal: controller.signal });
  }
  const result = await pending;
  const elapsedMs = performance.now() - started;
  if (config.abort || config.sessionStop || config.abortDuringRevalidation) {
    await delay(2_300);
  }
  const executed = result === undefined ? 1 : 0;
  return {
    blocked: result?.block === true,
    reason: result?.reason ?? null,
    executed,
    guardCalls,
    pollCalls,
    sentMessages: sentMessages.length,
    input: event.input,
    cwd: scenario.cwd,
    sessionId: scenario.sessionId,
    elapsedMs,
  };
}

const approval = {
  decision: "deny",
  reason: "approval pending",
  approval_request_id: "request-fixture",
  resume_poll_path: "/v1/requests/request-fixture",
};
const allow = { decision: "allow", reason: "exact approval consumed" };
const nativeFailure = { decision: "deny", reason: "native review failed", reason_code: "native_failure" };
const results = {
  success: await runScenario("success", { guardResponses: [approval, allow], poll: "pending", pendingPolls: 3 }),
  denial: await runScenario("denial", { guardResponses: [approval], poll: "block" }),
  expiry: await runScenario("expiry", { guardResponses: [approval], poll: "expiry" }),
  transport: await runScenario("transport", { guardResponses: [approval], poll: "transport" }),
  nativeFailure: await runScenario("native-failure", { guardResponses: [nativeFailure], poll: "transport" }),
  mutation: await runScenario("mutation", { guardResponses: [approval], poll: "allow", mutateInput: true }),
  contextMutation: await runScenario("context", { guardResponses: [approval], poll: "allow", mutateContext: true }),
  abort: await runScenario("abort", { guardResponses: [approval], poll: "pending", abort: true }),
  sessionStop: await runScenario("session-stop", { guardResponses: [approval], poll: "pending", sessionStop: true }),
  abortDuringRevalidation: await runScenario(
    "abort-during-revalidation",
    { guardResponses: [approval, allow], poll: "allow", abortDuringRevalidation: true },
  ),
  headless: await runScenario("headless", { guardResponses: [approval], poll: "allow", mode: "print" }),
};
console.log(JSON.stringify(results));
""".replace("__EXTENSION_PATH__", json.dumps(str(extension_path))).replace(
        "__RUNNER_PATH__", json.dumps(str(runner_path))
    )
    harness_path.write_text(script, encoding="utf-8")
    completed = _run_child(
        [bun, str(harness_path)],
        timeout=90,
    )
    payload = _decode_json_object(completed.stdout)
    original_input = {"path": "original.txt", "offset": 304, "limit": 243}

    success = payload["success"]
    assert isinstance(success, dict)
    assert success["blocked"] is False
    assert success["executed"] == 1
    assert success["guardCalls"] == 2
    assert success["pollCalls"] == 4
    assert success["elapsedMs"] >= 5_500
    assert success["elapsedMs"] < 25_000
    assert success["sentMessages"] == 0
    assert success["input"] == original_input

    for name in ("denial", "expiry", "transport", "nativeFailure", "mutation", "contextMutation"):
        scenario = payload[name]
        assert isinstance(scenario, dict)
        assert scenario["blocked"] is True
        assert scenario["executed"] == 0
        assert scenario["sentMessages"] == 0
    assert payload["denial"]["pollCalls"] == 1
    assert payload["expiry"]["pollCalls"] == 1
    assert payload["transport"]["pollCalls"] == 1
    assert payload["nativeFailure"]["pollCalls"] == 0
    assert payload["mutation"]["guardCalls"] == 1
    assert payload["contextMutation"]["guardCalls"] == 1

    abort = payload["abort"]
    assert isinstance(abort, dict)
    assert abort["blocked"] is True
    assert abort["executed"] == 0
    assert abort["guardCalls"] == 1
    assert abort["pollCalls"] == 1
    assert abort["sentMessages"] == 0

    for name in ("sessionStop", "abortDuringRevalidation", "headless"):
        scenario = payload[name]
        assert isinstance(scenario, dict)
        assert scenario["blocked"] is True
        assert scenario["executed"] == 0
        assert scenario["sentMessages"] == 0
    assert payload["sessionStop"]["guardCalls"] == 1
    assert payload["sessionStop"]["pollCalls"] == 1
    assert payload["abortDuringRevalidation"]["guardCalls"] == 2
    assert payload["abortDuringRevalidation"]["pollCalls"] == 1
    assert payload["headless"]["guardCalls"] == 1
    assert payload["headless"]["pollCalls"] == 0
    assert "Retry the exact original tool call" in payload["headless"]["reason"]


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
