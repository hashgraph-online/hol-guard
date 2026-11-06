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
    _run_child,
)


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
    if (text.includes("/readiness")) {
      return new Response(JSON.stringify({ ready: true }), { status: 200 });
    }
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
  await runner.emit({ type: "session_start" });
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
