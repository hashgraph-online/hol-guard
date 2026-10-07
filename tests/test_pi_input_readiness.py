"""Prompt readiness through the generated Pi-family input handler."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_input_prepares_cold_workspace_and_retries_failed_setup(tmp_path: Path, harness: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
    )
    cache_start = source.index("  let workspaceReadiness = null;")
    cache_end = source.index("  const approvalContinuationActivity", cache_start)
    input_start = source.index("  async function inputWorkspaceReadiness(")
    input_end = source.index('  pi.on("tool_call",', input_start)
    javascript = (
        """
const callbacks = {}, notices = [], events = [];
const GUARD_CONFIG_PATH = '/fixture/settings.json';
const GUARD_TIMEOUT_MS = 4250, GUARD_DEADLINE_RESERVE_MS = 250;
let inputApprovalResumeGeneration = 0;
const pi = { on(name, callback) { callbacks[name] = callback; } };
let connection = {stateId: 'daemon-a'}, ready = true, setupCalls = 0;
function loadGuardDaemonConnection() { return connection; }
function invalidateInputApprovalResumes() { inputApprovalResumeGeneration++; }
function handlerAbortSignal(ctx) { return ctx.signal; }
function captureInputApprovalResumeBinding() { return null; }
function approvalBlockedReason(_response, reason) { return reason; }
function scheduleApprovalResume() {}
async function daemonWorkspaceReadiness(cwd) {
  setupCalls++;
  events.push('setup:' + cwd);
  await new Promise(resolve => setTimeout(resolve, 30));
  events.push('prepared:' + cwd);
  return {ready, daemonStateId: connection.stateId, reasonCode: 'native_policy_not_ready'};
}
async function runGuard(payload, cwd) {
  events.push('review:' + cwd + ':' + payload.prompt);
  return payload.prompt === 'protected' ? {decision: 'deny', reason: 'protected'} : {decision: 'allow'};
}
"""
        + source[cache_start:cache_end]
        + source[input_start:input_end]
        + """
const ctx = {cwd: '/fixture', ui: {notify(reason) { notices.push(reason); }}};
async function prompt(text, source = 'interactive') {
  return callbacks.input({text, source}, ctx);
}
const coldPending = prompt('cold');
const inFlightTool = await ensureGuardWorkspaceReady(ctx.cwd, false);
const cold = await coldPending;
const warm = await prompt('warm');
const protectedResult = await prompt('protected');
const extension = await prompt('synthetic', 'extension');
const callsAfterWarm = setupCalls;
connection = {stateId: 'daemon-b'};
ready = false;
const failed = await prompt('failed');
const beforeTool = setupCalls;
const tool = await ensureGuardWorkspaceReady(ctx.cwd, false);
const callsAfterTool = setupCalls;
ready = true;
const retry = await prompt('retry');
ctx.cwd = '/other';
const other = await prompt('other');
console.log(JSON.stringify({cold, inFlightTool, warm, protectedResult, extension, callsAfterWarm, failed,
  beforeTool, tool, callsAfterTool, retry, other, setupCalls, events, notices}));
"""
    )
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the generated input handler")
    completed = subprocess.run(
        [node, "--input-type=module", "-e", javascript],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    result = json.loads(completed.stdout)
    for key in ("cold", "warm", "extension", "retry", "other"):
        assert result[key] == {"action": "continue"}
    for key in ("failed", "protectedResult"):
        assert result[key] == {"action": "handled", "handled": True}
    assert result["callsAfterWarm"] == 1
    assert result["inFlightTool"]["ready"] is True
    assert result["setupCalls"] == 4
    assert result["tool"]["ready"] is False
    assert result["beforeTool"] == result["callsAfterTool"] == 2
    assert result["events"] == [
        "setup:/fixture",
        "prepared:/fixture",
        "review:/fixture:cold",
        "review:/fixture:warm",
        "review:/fixture:protected",
        "setup:/fixture",
        "prepared:/fixture",
        "setup:/fixture",
        "prepared:/fixture",
        "review:/fixture:retry",
        "setup:/other",
        "prepared:/other",
        "review:/other:other",
    ]
    assert result["notices"] == [
        "protected",
        "HOL Guard could not prepare protection for this prompt. "
        "Retry the prompt to reconnect (native_policy_not_ready).",
    ]


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize("change", ["deadline", "cwd", "prompt", "abort", "generation"])
@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required to execute the generated input handler")
def test_pending_input_returns_in_time_and_rejects_changed_context(tmp_path: Path, harness: str, change: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
    )
    start = source.index("  let workspaceReadiness = null;")
    end = source.index("  const approvalContinuationActivity", start)
    input_start = source.index("  async function inputWorkspaceReadiness(")
    input_end = source.index('  pi.on("tool_call",', input_start)
    script = (
        """
const GUARD_CONFIG_PATH = '/fixture/settings.json', GUARD_TIMEOUT_MS = 30, GUARD_DEADLINE_RESERVE_MS = 10;
const callbacks = {}, notices = [];
let inputApprovalResumeGeneration = 0, setupCalls = 0, reviews = 0, finished = false;
const pi = {on(name, callback) {callbacks[name] = callback;}};
function loadGuardDaemonConnection() {return {stateId: 'fixture'};}
function invalidateInputApprovalResumes() {inputApprovalResumeGeneration++;}
function captureInputApprovalResumeBinding() {return null;}
function handlerAbortSignal(ctx) {return ctx.signal;}
async function daemonWorkspaceReadiness() {
  setupCalls++;
  await new Promise(resolve => setTimeout(resolve, 80));
  finished = true;
  return {ready: true, daemonStateId: 'fixture'};
}
async function runGuard(_payload, _cwd, options) {
  if (options.deadlineAt <= Date.now()) throw Error('review started after deadline');
  reviews++;
  return {decision: 'allow'};
}
"""
        + source[start:end]
        + source[input_start:input_end]
        + """
const controller = new AbortController();
const event = {text: 'hello', source: 'interactive'};
const ctx = {cwd: '/fixture', signal: controller.signal, ui: {notify(reason) {notices.push(reason);}}};
setTimeout(() => {
  if (CHANGE === 'cwd') ctx.cwd = '/changed';
  if (CHANGE === 'prompt') event.text = 'changed';
  if (CHANGE === 'abort') controller.abort();
  if (CHANGE === 'generation') inputApprovalResumeGeneration++;
}, 5);
const first = await callbacks.input(event, ctx);
const early = {finished, reviews};
await new Promise(resolve => setTimeout(resolve, 100));
ctx.cwd = '/fixture'; ctx.signal = undefined; event.text = 'hello';
const retry = await callbacks.input(event, ctx);
console.log(JSON.stringify({first, early, retry, setupCalls, reviews, notices}));
""".replace("CHANGE", json.dumps(change))
    )
    completed = subprocess.run(
        [shutil.which("node") or "node", "--input-type=module", "-e", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    result = json.loads(completed.stdout)
    assert result["first"] == {"action": "handled", "handled": True}
    assert result["early"] == {"finished": False, "reviews": 0}
    assert result["retry"] == {"action": "continue"}
    assert result["setupCalls"] == result["reviews"] == 1
    assert len(result["notices"]) == (1 if change == "deadline" else 0)
