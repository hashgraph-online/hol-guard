"""CIGAR project context through the generated Pi-family prompt handlers."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

FOUND = "HOL Guard CIGAR found code in this project that matches this request."

PRELUDE = """
const callbacks = {}, payloads = [], FOUND = FOUND_TEXT;
const GUARD_CONFIG_PATH = '/fixture/settings.json';
const GUARD_TIMEOUT_MS = TIMEOUT_VALUE, GUARD_DEADLINE_RESERVE_MS = 10;
let inputApprovalResumeGeneration = 0, setupDelayMs = 0;
const pi = {
  on(name, callback) { callbacks[name] = callback; },
  sendUserMessage(text) { resumed.push(text); },
};
const resumed = [];
function loadGuardDaemonConnection() { return {stateId: 'fixture'}; }
function invalidateInputApprovalResumes() { inputApprovalResumeGeneration++; }
function invalidateToolApprovalResumes() {}
function handlerAbortSignal(ctx) { return ctx.signal; }
function captureInputApprovalResumeBinding(ctx) {
  return {generation: inputApprovalResumeGeneration, cwd: ctx.cwd};
}
function inputApprovalResumeBindingIsActive(ctx, binding) {
  return binding.generation === inputApprovalResumeGeneration && binding.cwd === ctx.cwd;
}
function approvalBlockedReason(_response, reason) { return reason; }
function scheduleApprovalResume() {}
async function daemonWorkspaceReadiness() {
  await new Promise(resolve => setTimeout(resolve, setupDelayMs));
  return {ready: true, daemonStateId: 'fixture'};
}
async function runGuard(payload) {
  payloads.push(payload);
  if (payload.prompt === 'protected') return {decision: 'deny', reason: 'protected'};
  if (payload.prompt === 'no match') {
    return {decision: 'allow', hookSpecificOutput: {hookEventName: 'UserPromptSubmit'}};
  }
  return {decision: 'allow', hookSpecificOutput: {hookEventName: 'UserPromptSubmit',
    additionalContext: FOUND + ' ' + payload.prompt}};
}
const ctx = {cwd: '/fixture', ui: {notify() {}}};
const start = (prompt) => callbacks.before_agent_start({type: 'before_agent_start', prompt}, ctx);
const turn = async (text, source = 'interactive') => ({
  input: await callbacks.input({text, source}, ctx),
  start: await start(text),
});
"""


def run_handlers(tmp_path: Path, harness: str, steps: str, timeout_ms: int = 4250) -> dict[str, object]:
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
    script = (
        PRELUDE.replace("FOUND_TEXT", json.dumps(FOUND)).replace("TIMEOUT_VALUE", str(timeout_ms))
        + source[cache_start:cache_end]
        + source[input_start:input_end]
        + steps
    )
    completed = subprocess.run(
        [shutil.which("node") or "node", "--input-type=module", "-e", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return json.loads(completed.stdout)


def context_message(prompt: str) -> dict[str, object]:
    return {"message": {"customType": "hol-guard-project-context", "content": f"{FOUND} {prompt}", "display": False}}


node_required = pytest.mark.skipif(
    shutil.which("node") is None, reason="Node is required to execute the generated input handler"
)


@pytest.mark.parametrize("harness", ["pi", "omp"])
@node_required
def test_allowed_prompt_hands_cigar_context_to_the_model_once(tmp_path: Path, harness: str) -> None:
    result = run_handlers(
        tmp_path,
        harness,
        """
const matched = await turn('fix the cart total');
const again = await start('fix the cart total');
const empty = await turn('no match');
const blocked = await turn('protected');
// A prompt sent while the agent is busy is queued and starts no turn of its
// own; its files must not reach the next turn, which runs another prompt.
await callbacks.input({text: 'fix the theme', source: 'interactive'}, ctx);
const later = await turn('summarize the release notes', 'extension');
console.log(JSON.stringify({matched, again, empty, blocked, later, payloads}));
""",
    )
    assert result["matched"] == {"input": {"action": "continue"}, "start": context_message("fix the cart total")}
    assert "again" not in result, "context is handed on once"
    assert result["empty"] == {"input": {"action": "continue"}}
    assert result["blocked"] == {"input": {"action": "handled", "handled": True}}
    assert result["later"] == {"input": {"action": "continue"}}
    reviewed = [payload for payload in result["payloads"] if payload["hook_event_name"] == "UserPromptSubmit"]
    assert reviewed and all(payload["guard_prompt_context"] is True for payload in reviewed)


@pytest.mark.parametrize("harness", ["pi", "omp"])
@node_required
def test_prompt_resumed_after_workspace_setup_keeps_its_context(tmp_path: Path, harness: str) -> None:
    result = run_handlers(
        tmp_path,
        harness,
        """
setupDelayMs = 80;
const input = await callbacks.input({text: 'fix the cart total', source: 'interactive'}, ctx);
const early = await start('fix the cart total');
for (let waited = 0; resumed.length === 0 && waited < 2000; waited += 10) {
  await new Promise(resolve => setTimeout(resolve, 10));
}
// Pi runs the queued prompt as a new turn from the extension.
const resumedTurn = await turn(resumed[0], 'extension');
const again = await start(resumed[0]);
console.log(JSON.stringify({input, early, resumed, resumedTurn, again}));
""",
        timeout_ms=40,
    )
    assert result["input"] == {"action": "handled", "handled": True}
    assert "early" not in result, "nothing is handed on before the review finishes"
    assert result["resumed"] == ["fix the cart total"]
    assert result["resumedTurn"] == {"input": {"action": "continue"}, "start": context_message("fix the cart total")}
    assert "again" not in result
