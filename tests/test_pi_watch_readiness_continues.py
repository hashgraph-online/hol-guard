"""Watch posture lets prompts and tool calls continue past readiness failures."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from tests.pi_continuation_support import WATCH_POSTURE_STUB


def _slices(source: str) -> tuple[str, str, str]:
    cache_start = source.index("  let workspaceReadiness = null;")
    cache_end = source.index("  const approvalContinuationActivity", cache_start)
    input_start = source.index("  async function inputWorkspaceReadiness(")
    input_end = source.index('  pi.on("tool_call",', input_start)
    tool_start = source.index('  pi.on("tool_call", async (event, ctx) => {')
    tool_end = source.index("\n  });\n}", tool_start) + len("\n  });")
    return (
        source[cache_start:cache_end] + source[input_start:input_end],
        source[tool_start:tool_end],
        source,
    )


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize("watch", [False, True])
@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required to execute the generated handlers")
def test_readiness_failure_continues_only_in_watch(tmp_path: Path, harness: str, watch: bool) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
    )
    input_slice, tool_slice, _ = _slices(source)
    posture = "function guardWatchPostureActive() { return true; }\n" if watch else WATCH_POSTURE_STUB
    guard_calls = "let guardCalls = 0;"
    input_ctx_js = (
        "const inputCtx = { cwd: '/fixture', sessionId: 's',"
        " ui: { notify: (m) => notices.push(String(m)) }, isIdle: () => true };"
    )
    headless_ctx_js = "{ ...inputCtx, abort: () => {} }"
    tool_ctx_js = (
        "const toolCtx = { cwd: '/fixture', sessionId: 's', mode: 'tui',"
        " sessionManager: { getSessionId: () => 's' }, signal: undefined,"
        " ui: { notify: (m) => notices.push(String(m)),"
        " custom: async () => ({ kind: 'unavailable' }) } };"
    )
    script = f"""
const GUARD_CONFIG_PATH = '/fixture/settings.json';
const GUARD_TIMEOUT_MS = 4250, GUARD_DEADLINE_RESERVE_MS = 250;
let inputApprovalResumeGeneration = 0, approvalContinuationGeneration = 0;
const callbacks = new Map(), notices = [];
const pi = {{ on: (name, cb) => callbacks.set(name, cb) }};
function loadGuardDaemonConnection() {{ return {{ stateId: 'daemon-a' }}; }}
function invalidateInputApprovalResumes() {{ inputApprovalResumeGeneration++; }}
function invalidateToolApprovalResumes() {{}}
function invalidateApprovalContinuations() {{}}
function handlerAbortSignal(ctx) {{ return ctx.signal; }}
function contextCwd(ctx) {{ return ctx.cwd; }}
function contextSessionId(ctx) {{ return ctx.sessionId ?? null; }}
function captureInputApprovalResumeBinding() {{ return null; }}
function approvalContinuationFailureReason(_response, result) {{ return 'continuation-' + result; }}
function scheduleApprovalResume() {{}}
function continuationIsActive() {{ return true; }}
// Fail the daemon seam; the extracted ensureGuardWorkspaceReady cache stays authoritative.
async function daemonWorkspaceReadiness() {{
  return {{ ready: false, reasonCode: 'daemon_readiness_transport_failure', daemonStateId: 'daemon-a' }};
}}
async function runGuard() {{ guardCalls++; return {{ decision: 'allow' }}; }}
{guard_calls}
{posture}
{input_slice}
function snapshotToolCall(event, ctx) {{
  return {{ payload: {{ hook_event_name: 'PreToolUse', tool_name: event.toolName }}, cwd: ctx.cwd }};
}}
function toolCallStillMatches() {{ return true; }}
{tool_slice}
{input_ctx_js}
const inputResult = await callbacks.get('input')({{ text: 'hello', source: 'interactive' }}, inputCtx);
// A different prompt owns no input turn, so its turn-start review exercises the headless gate.
const headlessResult = await callbacks.get('before_agent_start')({{ prompt: 'other' }}, {headless_ctx_js});
{tool_ctx_js}
const toolResult = await callbacks.get('tool_call')({{ toolCallId: 'c', toolName: 'read', input: {{}} }}, toolCtx);
console.log(JSON.stringify({{ inputResult, headlessResult, toolResult, guardCalls, notices }}));
"""
    harness_path = tmp_path / f"watch-readiness-{harness}-{'on' if watch else 'off'}.mts"
    harness_path.write_text(script, encoding="utf-8")
    completed = subprocess.run(
        [shutil.which("node") or "node", "--experimental-strip-types", str(harness_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    result = json.loads(completed.stdout)
    if watch:
        assert result["inputResult"] == {"action": "continue"}
        assert "headlessResult" not in result, "the headless turn continues (undefined)"
        assert "toolResult" not in result, "the tool runs (undefined)"
        assert result["guardCalls"] == 0, "nothing is reviewed while readiness is down"
        assert any("daemon_readiness_transport_failure" in notice for notice in result["notices"])
    else:
        assert result["inputResult"] == {"action": "handled", "handled": True}
        assert "headlessResult" not in result
        assert result["toolResult"]["block"] is True
        assert "daemon_readiness_transport_failure" in result["toolResult"]["reason"]
        assert result["guardCalls"] == 0
