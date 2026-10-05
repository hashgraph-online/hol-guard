"""Run the generated tool-call boundary, not a hand-built hook payload."""

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_generated_pre_tool_payload_binds_sdk_session(tmp_path: Path, harness: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name="fixture",
    )
    start = source.index('pi.on("tool_call", async (event, ctx) => {')
    # Execute the actual payload-construction slice; downstream delivery is covered separately.
    end = source.index('    if (response.decision === "deny")', start)
    fragment = source[start:end] + "\n});"
    javascript = (
        """
const GUARD_CONFIG_PATH = '/fixture/settings.json';
let handler;
let captured;
const pi = { on: (_, callback) => { handler = callback; } };
function snapshotToolCall(event, ctx) {
  return {
    payload: {
      hook_event_name: 'PreToolUse',
      config_path: GUARD_CONFIG_PATH,
      tool_call_id: event.toolCallId,
      session_id: ctx.sessionManager?.getSessionId?.(),
      tool_name: event.toolName,
      tool_input: event.input,
    },
    canonicalPayload: 'fixture',
    cwd: ctx.cwd,
  };
}
function toolCallStillMatches() { return true; }
function handlerAbortSignal(ctx) { return ctx.signal; }
function approvalContinuationActivity() { return undefined; }
function continuationIsActive(activity) { return !activity || activity(); }
function approvalContinuationFailureReason(_response, result) { return `continuation-${result}`; }
async function ensureGuardWorkspaceReady() { return { ready: true }; }
function readinessFailureReason(readiness) { return `readiness-${readiness.reasonCode}`; }
async function runGuard(payload) { captured = payload; return {}; }
"""
        + fragment
        + """
await handler({ toolCallId: 'call-one', toolName: 'read', input: {path: 'src/example.py'} },
  {cwd: '/fixture', sessionManager: { getSessionId: () => 'session-one' }});
console.log(JSON.stringify(captured));
"""
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", javascript],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    assert payload["session_id"] == "session-one"
    assert payload["tool_call_id"] == "call-one"
    assert payload["tool_input"] == {"path": "src/example.py"}
