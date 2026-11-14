"""CIGAR project context through the generated Pi-family prompt handlers."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.pi_continuation_support import WATCH_POSTURE_STUB
from tests.pi_extension_support import managed_extension_source

FOUND = "HOL Guard CIGAR found code in this project that matches this request."

PRELUDE = """
const callbacks = {}, payloads = [], FOUND = FOUND_TEXT;
const GUARD_CONFIG_PATH = '/fixture/settings.json';
const GUARD_TIMEOUT_MS = TIMEOUT_VALUE, GUARD_DEADLINE_RESERVE_MS = 10;
let inputApprovalResumeGeneration = 0, setupDelayMs = 0, idle = true;
const pi = {
  on(name, callback) { callbacks[name] = callback; },
  sendUserMessage(text, options) { resumed.push(text); sent.push(options); },
};
const resumed = [], sent = [];
function loadGuardDaemonConnection() { return {stateId: 'fixture'}; }
function invalidateInputApprovalResumes() { inputApprovalResumeGeneration++; }
function invalidateToolApprovalResumes() {}
function handlerAbortSignal(ctx) { return ctx.signal; }
function contextSessionId(ctx) { return ctx.sessionId ?? null; }
function captureInputApprovalResumeBinding(ctx) {
  return {generation: inputApprovalResumeGeneration, cwd: ctx.cwd};
}
function inputApprovalResumeBindingIsActive(ctx, binding) {
  return binding.generation === inputApprovalResumeGeneration && binding.cwd === ctx.cwd;
}
function approvalBlockedReason(_response, reason) { return reason; }
function approvalUrlFromResponse(response) { return response.approval_url ?? null; }
function scheduleApprovalResume() {}
async function daemonWorkspaceReadiness() {
  await new Promise(resolve => setTimeout(resolve, setupDelayMs));
  return {ready: true, daemonStateId: 'fixture'};
}
async function runGuard(payload) {
  payloads.push(payload);
  if (payload.prompt === 'protected') return {decision: 'deny', reason: 'protected'};
  if (payload.prompt === 'needs approval') {
    return {decision: 'deny', reason: 'held', approval_url: 'https://guard.example/approve/1'};
  }
  if (payload.prompt === 'no match') {
    return {decision: 'allow', hookSpecificOutput: {hookEventName: 'UserPromptSubmit'}};
  }
  return {decision: 'allow', hookSpecificOutput: {hookEventName: 'UserPromptSubmit',
    additionalContext: FOUND + ' ' + payload.prompt}};
}
const ctx = {cwd: '/fixture', sessionId: 'session-a', hasUI: true, ui: {notify() {}}, isIdle: () => idle};
const start = (prompt) => callbacks.before_agent_start({type: 'before_agent_start', prompt}, ctx);
const turn = async (text, source = 'interactive', expanded = text) => ({
  input: await callbacks.input({text, source}, ctx),
  start: await start(expanded),
});
"""


def run_handlers(
    tmp_path: Path, harness: str, steps: str, timeout_ms: int = 4250, exit_code: int = 0
) -> dict[str, object]:
    completed = run_node(handler_script(tmp_path, harness, steps, timeout_ms))
    assert completed.stdout.strip(), completed.stderr
    # A stopped headless prompt ends the run nonzero and says why on stderr.
    assert completed.returncode == exit_code, completed.stderr
    result = json.loads(completed.stdout)
    result["stderr"] = completed.stderr.splitlines()
    return result


def run_node(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [shutil.which("node") or "node", "--input-type=module", "-e", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def handler_script(tmp_path: Path, harness: str, steps: str, timeout_ms: int = 4250) -> str:
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
    return (
        PRELUDE.replace("FOUND_TEXT", json.dumps(FOUND)).replace("TIMEOUT_VALUE", str(timeout_ms))
        + WATCH_POSTURE_STUB
        + source[cache_start:cache_end]
        + source[input_start:input_end]
        + steps
    )


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
// Pi expands a skill command or prompt template before the turn starts.
const skill = await turn('/skill:review fix the cart', 'interactive', 'Review carefully. fix the cart');
const template = await turn('/cart-fix', 'interactive', 'Fix the cart total rounding.');
// A turn that runs a different prompt gets nothing.
await callbacks.input({text: 'fix the theme', source: 'interactive'}, ctx);
const other = await turn('summarize the release notes', 'extension');
// A prompt sent while the agent is busy is queued and starts no turn of its
// own; its files must not reach the next turn, which runs another prompt.
idle = false;
await callbacks.input({text: '/skill:review fix the theme', source: 'interactive'}, ctx);
idle = true;
const later = await turn('summarize the release notes', 'extension');
console.log(JSON.stringify({matched, again, empty, blocked, skill, template, other, later, payloads}));
""",
    )
    assert result["matched"] == {"input": {"action": "continue"}, "start": context_message("fix the cart total")}
    assert "again" not in result, "context is handed on once"
    assert result["empty"] == {"input": {"action": "continue"}}
    assert result["blocked"] == {"input": {"action": "handled", "handled": True}}
    assert result["skill"] == {"input": {"action": "continue"}, "start": context_message("/skill:review fix the cart")}
    assert result["template"] == {"input": {"action": "continue"}, "start": context_message("/cart-fix")}
    assert result["other"] == {"input": {"action": "continue"}}
    assert result["later"] == {"input": {"action": "continue"}}
    reviewed = [payload for payload in result["payloads"] if payload["hook_event_name"] == "UserPromptSubmit"]
    assert reviewed and all(payload["guard_prompt_context"] is True for payload in reviewed)
    assert all(payload["session_id"] == "session-a" for payload in reviewed)


RESUME_STEPS = """
setupDelayMs = 80;
idle = RESUME_IDLE;
const input = await callbacks.input({text: 'fix the cart total', source: 'interactive'}, ctx);
for (let waited = 0; resumed.length === 0 && waited < 2000; waited += 10) {
  await new Promise(resolve => setTimeout(resolve, 10));
}
idle = true;
// Pi runs the resumed prompt as a new turn from the extension.
const resumedTurn = await turn(resumed[0], 'extension');
const again = await start(resumed[0]);
console.log(JSON.stringify({input, resumed, sent, resumedTurn, again, payloads}));
"""


@pytest.mark.parametrize("harness", ["pi", "omp"])
@node_required
def test_prompt_resumed_after_workspace_setup_keeps_its_context(tmp_path: Path, harness: str) -> None:
    result = run_handlers(tmp_path, harness, RESUME_STEPS.replace("RESUME_IDLE", "true"), timeout_ms=40)
    assert result["input"] == {"action": "handled", "handled": True}
    reviewed = [payload["prompt"] for payload in result["payloads"] if payload["hook_event_name"] == "UserPromptSubmit"]
    assert reviewed == ["fix the cart total"], "the resumed turn is not reviewed again"
    assert result["resumed"] == ["fix the cart total"]
    # Starting the turn directly lets Pi expand a skill command or prompt template.
    assert result["sent"] == [{"expandPromptTemplates": True}]
    assert result["resumedTurn"] == {"input": {"action": "continue"}, "start": context_message("fix the cart total")}
    assert "again" not in result


@pytest.mark.parametrize("harness", ["pi", "omp"])
@node_required
def test_prompt_resumed_while_the_agent_is_busy_is_queued_without_context(tmp_path: Path, harness: str) -> None:
    result = run_handlers(tmp_path, harness, RESUME_STEPS.replace("RESUME_IDLE", "false"), timeout_ms=40)
    assert result["resumed"] == ["fix the cart total"]
    # A queued follow-up starts no turn of its own, so its files are not kept.
    assert result["sent"] == [{"deliverAs": "followUp"}]
    assert result["resumedTurn"] == {"input": {"action": "continue"}}


HEADLESS_STEPS = """
const aborted = [], notes = [];
const headless = {...ctx, hasUI: false, abort: () => aborted.push(true), ui: {notify: (text) => notes.push(text)}};
// Print mode and the SDK start a turn without an "input" event.
const begin = (prompt, reason = 'prompt') =>
  callbacks.before_agent_start({type: 'before_agent_start', reason, prompt}, headless);
const matched = await begin('fix the cart total');
const empty = await begin('no match');
const blocked = await begin('protected');
const held = await begin('needs approval');
const stopped = aborted.length;
const revived = await begin('fix the cart total', 'revive');
// A typed prompt is reviewed by the input handler, and only its own turn.
const typed = await turn('fix the theme');
// An SDK session that emitted "input" can still call prompt() directly.
const later = await begin('fix the cart total');
const repeat = await begin('fix the theme');
// A prompt the input handler held owns no turn, so prompt() reviews it again.
await callbacks.input({text: 'protected', source: 'interactive'}, ctx);
const retried = await begin('protected');
console.log(JSON.stringify({
  matched, empty, blocked, held, stopped, notes, revived, typed, later, repeat, retried, payloads,
  aborted: aborted.length,
}));
"""


@pytest.mark.parametrize("harness", ["pi", "omp"])
@node_required
def test_headless_prompt_is_reviewed_when_its_turn_starts(tmp_path: Path, harness: str) -> None:
    result = run_handlers(tmp_path, harness, HEADLESS_STEPS, exit_code=1)
    assert result["matched"] == context_message("fix the cart total")
    assert "empty" not in result
    assert "blocked" not in result
    assert "held" not in result
    assert result["stopped"] == 2, "a denied headless prompt stops its turn"
    # A prompt cannot be approved, so the note gives the reason and no approval link.
    assert result["notes"] == ["protected", "held", "protected"]
    assert "revived" not in result
    assert result["typed"] == {"input": {"action": "continue"}, "start": context_message("fix the theme")}
    assert result["later"] == context_message("fix the cart total")
    assert "repeat" not in result, "a turn rerunning the typed prompt is not reviewed twice"
    assert "retried" not in result
    assert result["aborted"] == 3
    assert result["stderr"] == ["protected", "held", "protected"]
    reviewed = [payload["prompt"] for payload in result["payloads"] if payload["hook_event_name"] == "UserPromptSubmit"]
    assert reviewed == [
        "fix the cart total",
        "no match",
        "protected",
        "needs approval",
        "fix the theme",
        "fix the cart total",
        "protected",
        "protected",
    ]
    assert all(payload["guard_prompt_context"] is True for payload in result["payloads"])
    assert all(payload["session_id"] == "session-a" for payload in result["payloads"])


PRINT_MODE_STEPS = """
const printMode = {...ctx, hasUI: HAS_UI, abort() {}, ui: {notify() {}}};
const begin = (prompt) => callbacks.before_agent_start({type: 'before_agent_start', prompt}, printMode);
await begin('protected');
await begin('needs approval');
await begin('fix the cart total');
console.log(JSON.stringify({done: true}));
HOST_EXIT
"""

# Print mode ends with the host's own process.exit(0); a run may also just drain.
HOST_EXITS = pytest.mark.parametrize("host_exit", ["", "process.exit(0);"], ids=["drain", "host-exit"])


def print_mode_script(tmp_path: Path, harness: str, has_ui: str, host_exit: str) -> str:
    steps = PRINT_MODE_STEPS.replace("HAS_UI", has_ui).replace("HOST_EXIT", host_exit)
    return handler_script(tmp_path, harness, steps)


@pytest.mark.parametrize("harness", ["pi", "omp"])
@HOST_EXITS
@node_required
def test_stopped_print_mode_prompt_says_why_and_exits_nonzero(tmp_path: Path, harness: str, host_exit: str) -> None:
    # Print and JSON modes have no UI, so a notice alone reaches no one and the
    # run used to exit 0 as if the prompt had finished.
    completed = run_node(print_mode_script(tmp_path, harness, "false", host_exit))
    assert json.loads(completed.stdout) == {"done": True}
    assert completed.stderr.splitlines() == ["protected", "held"]
    assert completed.returncode == 1


@pytest.mark.parametrize("harness", ["pi", "omp"])
@HOST_EXITS
@node_required
def test_stopped_prompt_with_a_ui_leaves_the_exit_status_alone(tmp_path: Path, harness: str, host_exit: str) -> None:
    completed = run_node(print_mode_script(tmp_path, harness, "true", host_exit))
    assert json.loads(completed.stdout) == {"done": True}
    assert completed.stderr == ""
    assert completed.returncode == 0
