from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.native_daemon_route import native_route_facts
from tests.pi_continuation_support import WATCH_POSTURE_STUB


def test_pi_source_prepares_workspace_before_timed_tool_review(
    tmp_path: Path, native_approval_reuse_runtime: Path
) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    agent_start = source.index('pi.on("agent_start", async (_event, ctx) => {')
    session_start = source.index('pi.on("session_start", async (_event, ctx) => {')
    tool_call = source.index('pi.on("tool_call", async (event, ctx) => {')
    readiness_request = source.index("/v1/hooks/omp/readiness")
    tool_readiness = source.index("toolWorkspaceReadiness(snapshot.cwd, hookDeadlineAt)", tool_call)
    semantic_review = source.index("const response = await runGuard(", tool_call)

    assert readiness_request < agent_start
    assert agent_start < session_start
    assert session_start < tool_call
    assert tool_readiness < semantic_review
    assert "native_route !== 'native_resident'" in source
    assert "if (connection === null || connection.stateId === null)" in source
    assert '"authenticated-control-plane-failure"' in source
    assert native_route_facts(
        "POST", "/v1/hooks/omp/readiness", guard_home=native_approval_reuse_runtime
    ).requires_header_token
    assert "'X-Guard-Token': connection.authToken" in source[readiness_request : readiness_request + 700]
    assert "prepareGuardWorkspaceForTurn(contextCwd(ctx) ?? process.cwd())" in source
    assert 'pi.on("session_start", async (_event, ctx) => {' in source
    assert 'pi.on("agent_start", async (_event, ctx) => {' in source
    assert "daemon_restarted_requires_session_setup" in source


def test_pi_readiness_cache_requires_session_setup_after_failure_or_restart(tmp_path: Path) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    cache_start = source.index("  let workspaceReadiness = null;")
    cache_end = source.index("  const approvalContinuationActivity", cache_start)
    cache_source = source[cache_start:cache_end]
    agent_start = source.index('  pi.on("agent_start", async (_event, ctx) => {')
    agent_end = source.index('  pi.on("agent_end"', agent_start)
    agent_start_source = source[agent_start:agent_end]
    javascript = (
        """
let connection = { stateId: 'daemon-a' };
let mode = 'failed';
let readinessCalls = 0;
const callbacks = {};
const pi = { on(name, callback) { callbacks[name] = callback; } };
function contextCwd(ctx) { return ctx?.cwd ?? null; }
function invalidateApprovalContinuations() {}
function loadGuardDaemonConnection() { return connection; }
function daemonWorkspaceReadiness(_cwd) {
  readinessCalls += 1;
  return Promise.resolve(mode === 'ready'
    ? { ready: true, daemonStateId: connection.stateId }
    : { ready: false, reasonCode: 'native_policy_not_ready', daemonStateId: connection.stateId });
}
"""
        + WATCH_POSTURE_STUB
        + cache_source
        + agent_start_source
        + """
async function runAgentStart(cwd) {
  await callbacks.agent_start({}, { cwd, ui: { notify() {} } });
}
connection = { stateId: null };
mode = 'ready';
const inFlight = ensureGuardWorkspaceReady('/inflight', true);
const inFlightTool = await ensureGuardWorkspaceReady('/inflight', false);
await inFlight;
connection = { stateId: 'daemon-a' };
mode = 'failed';
await runAgentStart('/fixture');
const first = await ensureGuardWorkspaceReady('/fixture', false);
mode = 'ready';
const sameSession = await ensureGuardWorkspaceReady('/fixture', false);
const callsAfterFailure = readinessCalls;
await runAgentStart('/fixture');
const recovered = await ensureGuardWorkspaceReady('/fixture', false);
connection = { stateId: 'daemon-b' };
await runAgentStart('/fixture');
const afterRestartSetup = await ensureGuardWorkspaceReady('/fixture', false);
const afterRestartTool = await ensureGuardWorkspaceReady('/fixture', false);
await runAgentStart('/other-fixture');
const contextChangedSetup = await ensureGuardWorkspaceReady('/other-fixture', false);
const contextChangedTool = await ensureGuardWorkspaceReady('/other-fixture', false);
console.log(JSON.stringify({
  first,
  sameSession,
  recovered,
  afterRestartSetup,
  afterRestartTool,
  contextChangedSetup,
  contextChangedTool,
  inFlightTool,
  callsAfterFailure,
  readinessCalls,
}));
"""
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", javascript],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = json.loads(result.stdout)
    assert output["first"]["ready"] is False
    assert output["sameSession"]["ready"] is False
    assert output["sameSession"]["reasonCode"] == "native_policy_not_ready"
    assert output["callsAfterFailure"] == 2
    assert output["recovered"]["ready"] is True
    assert output["afterRestartSetup"]["ready"] is True
    assert output["afterRestartTool"]["ready"] is True
    assert output["contextChangedSetup"]["ready"] is True
    assert output["contextChangedTool"]["ready"] is True
    assert output["inFlightTool"]["ready"] is False
    assert output["inFlightTool"]["reasonCode"] == "daemon_changed_during_workspace_setup"
    assert output["readinessCalls"] == 5


@pytest.mark.parametrize(
    ("statuses", "recovery_delay", "recovery_success", "ready", "attempts", "requests", "cancel_calls"),
    [
        ([404, 200], 0, True, True, 1, 2, 1),
        ([404, 404], 0, True, False, 1, 2, 1),
        ([404], 0, False, False, 1, 1, 1),
        ([404, 200], 26_000, True, False, 1, 1, 1),
        ([503], 0, True, False, 0, 1, 0),
        ([401], 0, True, False, 0, 1, 0),
        ([200], 0, True, True, 0, 1, 0),
    ],
)
def test_pi_readiness_recovers_missing_endpoint_once_within_setup_budget(
    tmp_path: Path,
    statuses: list[int],
    recovery_delay: int,
    recovery_success: bool,
    ready: bool,
    attempts: int,
    requests: int,
    cancel_calls: int,
) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    start = source.index("const GUARD_DAEMON_READINESS_TIMEOUT_MS")
    end = source.index("async function runGuard(", start)
    readiness = source[start:end].replace(" as unknown", "").replace(" as Record<string, unknown>", "")
    readiness = readiness.replace("cwd: string,", "cwd,")
    readiness = readiness.replace("options: { deadlineAt?: number; allowRecovery?: boolean }", "options")
    javascript = (
        f"const statuses = {json.dumps(statuses)}; const recoveryDelay = {recovery_delay};\n"
        + f"const recoverySuccess = {json.dumps(recovery_success)};\n"
        + """
const GUARD_HOME = '/fixture', GUARD_HOME_DIR = '/home/fixture';
const GUARD_HOME_DIR_IS_DEFAULT = false, GUARD_TEXT_LIMIT_CHARS = 32768;
let clock = 1000, recoveryAttempts = 0, fetches = 0, cancelCalls = 0;
Date.now = () => clock;
let connection = {port: 12345, authToken: 'fixture-token', stateId: 'old'};
function loadGuardDaemonConnection() { return connection; }
async function recoverGuardDaemon(timeout, kind) {
  if (timeout > 26000 || timeout <= 0 || kind !== 'authenticated-control-plane-failure') throw Error('budget');
  recoveryAttempts++;
  clock += recoveryDelay;
  connection = {...connection, stateId: 'new'};
  return recoverySuccess;
}
async function boundedResponseText(response) { return JSON.stringify(response.value); }
globalThis.fetch = async (url, options) => {
  if (options.headers['X-Guard-Token'] !== 'fixture-token') throw Error('authentication');
  const status = statuses[fetches++];
  if (status === undefined) throw Error('unbounded retry');
  return {status, ok: status === 200, body: {cancel() { cancelCalls++; return new Promise(() => {}); }},
    value: {ready: status === 200, native_required: true, native_route: 'native_resident',
      workspace_acknowledged: true, worker_ready: true}};
};
"""
        + readiness
        + "const result = await daemonWorkspaceReadiness('/fixture');\n"
        + "console.log(JSON.stringify({result, recoveryAttempts, fetches, cancelCalls}));\n"
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", javascript],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = json.loads(result.stdout)
    assert output["result"]["ready"] is ready
    assert output["recoveryAttempts"] == attempts
    assert output["fetches"] == requests
    assert output["cancelCalls"] == cancel_calls
    if attempts and ready:
        assert output["result"]["daemonStateId"] == "new"


def test_pi_readiness_does_not_recover_again_when_retry_loses_identity(tmp_path: Path) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    start = source.index("const GUARD_DAEMON_READINESS_TIMEOUT_MS")
    end = source.index("async function runGuard(", start)
    readiness = source[start:end].replace(" as unknown", "").replace(" as Record<string, unknown>", "")
    readiness = readiness.replace("cwd: string,", "cwd,")
    readiness = readiness.replace("options: { deadlineAt?: number; allowRecovery?: boolean }", "options")
    javascript = (
        """
const GUARD_HOME = '/fixture', GUARD_HOME_DIR = '/home/fixture';
const GUARD_HOME_DIR_IS_DEFAULT = false, GUARD_TEXT_LIMIT_CHARS = 32768;
let connection = {port: 12345, authToken: 'fixture-token', stateId: 'old'};
let recoveryAttempts = 0;
function loadGuardDaemonConnection() { return connection; }
async function recoverGuardDaemon() {
  recoveryAttempts++;
  connection = null;
  return true;
}
globalThis.fetch = async () => ({status: 404, ok: false, body: {cancel() { return Promise.resolve(); }}});
"""
        + readiness
        + "const result = await daemonWorkspaceReadiness('/fixture');\n"
        + "console.log(JSON.stringify({result, recoveryAttempts}));\n"
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", javascript],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = json.loads(result.stdout)
    assert output["result"]["ready"] is False
    assert output["result"]["reasonCode"] == "daemon_readiness_transport_failure"
    assert output["recoveryAttempts"] == 1
