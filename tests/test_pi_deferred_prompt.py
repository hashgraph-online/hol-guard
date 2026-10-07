"""Cold prompt continuation must retain review and session ownership."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize(
    "change", ["none", "cwd", "session", "prompt", "abort", "generation", "unavailable", "deny", "unknown"]
)
def test_cold_prompt_resumes_only_after_bound_successful_review(
    tmp_path: Path, harness: str, change: str
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the generated input handler")
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
        """
const CHANGE = __CHANGE__;
const GUARD_CONFIG_PATH = '/fixture/settings.json';
const GUARD_TIMEOUT_MS = 30, GUARD_DEADLINE_RESERVE_MS = 10;
const callbacks = {}, notices = [], queued = [], reviewed = [];
let inputApprovalResumeGeneration = 0, approvalResumes = 0;
const pi = {
  on(name, callback) { callbacks[name] = callback; },
  sendUserMessage(prompt, options) { queued.push({prompt, options}); },
};
function loadGuardDaemonConnection() { return {stateId: 'daemon-a'}; }
function invalidateInputApprovalResumes() { inputApprovalResumeGeneration++; }
function handlerAbortSignal(ctx) { return ctx.signal; }
function captureInputApprovalResumeBinding(ctx) {
  return {generation: inputApprovalResumeGeneration, cwd: ctx.cwd, sessionId: ctx.sessionId};
}
function inputApprovalResumeBindingIsActive(ctx, binding) {
  return binding.generation === inputApprovalResumeGeneration && binding.cwd === ctx.cwd &&
    binding.sessionId === ctx.sessionId;
}
function approvalBlockedReason(_response, reason) { return reason; }
function scheduleApprovalResume() { approvalResumes++; }
async function daemonWorkspaceReadiness() {
  await new Promise(resolve => setTimeout(resolve, 80));
  return {ready: CHANGE !== 'unavailable', daemonStateId: 'daemon-a', reasonCode: 'native_not_ready'};
}
async function runGuard(payload, cwd, options) {
  reviewed.push({payload, cwd, freshDeadline: options.deadlineAt > Date.now()});
  if (CHANGE === 'unknown') return {};
  return {decision: CHANGE === 'deny' ? 'deny' : 'allow', reason: 'reviewed'};
}
""".replace("__CHANGE__", json.dumps(change))
        + source[cache_start:cache_end]
        + source[input_start:input_end]
        + """
const controller = new AbortController();
const event = {text: 'original prompt', source: 'interactive'};
const ctx = {cwd: '/fixture', sessionId: 'session-a', signal: controller.signal,
  ui: {notify(reason, level) {notices.push({reason, level});}}};
const result = await callbacks.input(event, ctx);
const beforeReady = {queued: queued.length, reviewed: reviewed.length};
if (CHANGE === 'cwd') ctx.cwd = '/other';
if (CHANGE === 'session') ctx.sessionId = 'session-b';
if (CHANGE === 'prompt') event.text = 'changed prompt';
if (CHANGE === 'abort') controller.abort();
if (CHANGE === 'generation') inputApprovalResumeGeneration++;
await new Promise(resolve => setTimeout(resolve, 120));
console.log(JSON.stringify({result, beforeReady, queued, reviewed, notices, approvalResumes}));
"""
    )
    completed = subprocess.run(
        [node, "--input-type=module", "-e", script],
        check=True, capture_output=True, text=True, timeout=10,
    )
    result = json.loads(completed.stdout)
    assert result["result"] == {"action": "handled", "handled": True}
    assert result["beforeReady"] == {"queued": 0, "reviewed": 0}
    if change == "none":
        assert result["queued"] == [{"prompt": "original prompt", "options": {"deliverAs": "followUp"}}]
    else:
        assert result["queued"] == []
    if change in {"none", "deny", "unknown"}:
        assert len(result["reviewed"]) == 1
        assert result["reviewed"][0]["freshDeadline"] is True
        assert result["reviewed"][0]["payload"]["prompt"] == "original prompt"
    else:
        assert result["reviewed"] == []
    assert result["approvalResumes"] == (1 if change in {"deny", "unknown"} else 0)
    assert result["notices"][0]["level"] == "info"
