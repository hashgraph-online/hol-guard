"""CIGAR project context through the generated Pi-family prompt handlers."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

FOUND = "HOL Guard CIGAR found code in this project that matches this request."


def prompt_context_script(source: str) -> str:
    cache_start = source.index("  let workspaceReadiness = null;")
    cache_end = source.index("  const approvalContinuationActivity", cache_start)
    input_start = source.index("  async function inputWorkspaceReadiness(")
    input_end = source.index('  pi.on("tool_call",', input_start)
    return (
        """
const callbacks = {}, payloads = [], FOUND = FOUND_TEXT;
const GUARD_CONFIG_PATH = '/fixture/settings.json';
const GUARD_TIMEOUT_MS = 4250, GUARD_DEADLINE_RESERVE_MS = 250;
let inputApprovalResumeGeneration = 0;
const pi = { on(name, callback) { callbacks[name] = callback; } };
function loadGuardDaemonConnection() { return {stateId: 'fixture'}; }
function invalidateInputApprovalResumes() { inputApprovalResumeGeneration++; }
function invalidateToolApprovalResumes() {}
function handlerAbortSignal(ctx) { return ctx.signal; }
function captureInputApprovalResumeBinding() { return null; }
function approvalBlockedReason(_response, reason) { return reason; }
function scheduleApprovalResume() {}
async function daemonWorkspaceReadiness() { return {ready: true, daemonStateId: 'fixture'}; }
async function runGuard(payload) {
  payloads.push(payload);
  if (payload.prompt === 'protected') return {decision: 'deny', reason: 'protected'};
  if (payload.prompt === 'no match') {
    return {decision: 'allow', hookSpecificOutput: {hookEventName: 'UserPromptSubmit'}};
  }
  return {decision: 'allow', hookSpecificOutput: {hookEventName: 'UserPromptSubmit',
    additionalContext: FOUND + ' ' + payload.prompt}};
}
"""
        + source[cache_start:cache_end]
        + source[input_start:input_end]
        + """
const ctx = {cwd: '/fixture', ui: {notify() {}}};
const turn = async (text, source = 'interactive') => ({
  input: await callbacks.input({text, source}, ctx),
  start: await callbacks.before_agent_start({prompt: text}, ctx),
});
const matched = await turn('fix the cart total');
const again = await callbacks.before_agent_start({prompt: 'fix the cart total'}, ctx);
const empty = await turn('no match');
await callbacks.input({text: 'fix the theme', source: 'interactive'}, ctx);
const blocked = await turn('protected');
await callbacks.input({text: 'fix the theme', source: 'interactive'}, ctx);
const extension = await turn('resumed', 'extension');
console.log(JSON.stringify({matched, again, empty, blocked, extension, payloads}));
"""
    ).replace("FOUND_TEXT", json.dumps(FOUND))


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required to execute the generated input handler")
def test_allowed_prompt_hands_cigar_context_to_the_model_once(tmp_path: Path, harness: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
    )
    completed = subprocess.run(
        [shutil.which("node") or "node", "--input-type=module", "-e", prompt_context_script(source)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    result = json.loads(completed.stdout)
    assert result["matched"] == {
        "input": {"action": "continue"},
        "start": {
            "message": {
                "customType": "hol-guard-project-context",
                "content": f"{FOUND} fix the cart total",
                "display": False,
            }
        },
    }
    assert "again" not in result, "context is handed on once"
    assert result["empty"] == {"input": {"action": "continue"}}
    assert result["blocked"] == {"input": {"action": "handled", "handled": True}}
    # A prompt Guard resumes arrives from the extension itself and keeps the
    # context its approved review found.
    assert result["extension"] == {
        "input": {"action": "continue"},
        "start": {
            "message": {
                "customType": "hol-guard-project-context",
                "content": f"{FOUND} fix the theme",
                "display": False,
            }
        },
    }
    reviewed = [payload for payload in result["payloads"] if payload["hook_event_name"] == "UserPromptSubmit"]
    assert reviewed and all(payload["guard_prompt_context"] is True for payload in reviewed)
