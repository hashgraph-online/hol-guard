"""Exercise the generated tool readiness barrier across daemon replacement."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


@pytest.mark.parametrize(
    "mode", ["ready", "unready", "replaced", "cancelled", "mutated", "same-unready", "missing", "slow"]
)
def test_tool_call_reprepares_replaced_daemon_without_replaying_authority(tmp_path: Path, mode: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    cache = source[
        source.index("  let workspaceReadiness = null;") : source.index("  const approvalContinuationActivity")
    ]
    tool_start = source.index('  pi.on("tool_call",')
    tool = source[tool_start : source.index("    const signal = handlerAbortSignal(ctx);", tool_start)]
    javascript = (
        """
let connection = {stateId: 'a'};
let calls = 0, invalidations = 0, reviews = 0, approvalContinuationGeneration = 0;
const GUARD_TIMEOUT_MS = 80, GUARD_DEADLINE_RESERVE_MS = 10;
const GUARD_DAEMON_READINESS_RESPONSE_RESERVE_MS = 10;
const callbacks = {}, pi = {on(name, fn) {callbacks[name] = fn;}};
const GUARD_CONFIG_PATH = '/fixture/config';
function loadGuardDaemonConnection() {return connection;}
function invalidateApprovalContinuations() {invalidations++; approvalContinuationGeneration++;}
function snapshotToolCall(event, ctx) {return {cwd: ctx.cwd, payload: {...event}};}
function toolCallStillMatches(event, ctx, config, snapshot) {
  return ctx.cwd === snapshot.cwd && event.arguments === snapshot.payload.arguments;
}
function handlerAbortSignal() {return undefined;}
let mode = 'ready';
let event;
async function daemonWorkspaceReadiness() {
  calls++;
  const stateId = connection.stateId;
  await Promise.resolve();
  if (mode === 'slow') await new Promise(resolve => setTimeout(resolve, 120));
  if (mode === 'replaced') connection = {stateId: 'replacement-' + calls};
  if (mode === 'cancelled') invalidateApprovalContinuations();
  if (mode === 'mutated') event.arguments += 'changed';
  return {ready: !['unready', 'same-unready', 'missing'].includes(mode),
    reasonCode: 'native_policy_not_ready', daemonStateId: stateId};
}
"""
        + cache
        + tool
        + """
    reviews++;
    return {reviewed: true};
  });
await prepareGuardWorkspaceForTurn('/fixture');
connection = {stateId: 'b'};
"""
        + f"mode = {json.dumps(mode)};\n"
        + """
event = {arguments: 'byte-exact original'};
const ctx = {cwd: '/fixture', ui: {notify() {}}};
const first = await callbacks.tool_call(event, ctx);
if (mode === 'slow') await new Promise(resolve => setTimeout(resolve, 150));
if (mode === 'same-unready' || mode === 'missing') {
  connection = {stateId: mode === 'missing' ? null : 'b'};
  await prepareGuardWorkspaceForTurn('/fixture');
  invalidations = 0;
}
const second = ['ready', 'unready', 'replaced', 'same-unready', 'missing', 'slow'].includes(mode)
  ? await callbacks.tool_call(event, ctx) : first;
if (mode === 'same-unready' || mode === 'missing') {
  await ensureGuardWorkspaceReady('/fixture', true, true);
}
console.log(JSON.stringify({first, second, calls, invalidations, reviews}));
"""
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", javascript], capture_output=True, text=True, check=True, timeout=30
    )
    output = json.loads(result.stdout)
    if mode == "slow":
        assert output["first"]["block"] is True
        assert "workspace_setup_pending" in output["first"]["reason"]
        assert output["second"] == {"reviewed": True}
        assert output["reviews"] == 1
        assert output["calls"] == 2
    elif mode == "ready":
        assert output["reviews"] == 2
        assert output["first"] == {"reviewed": True}
        assert output["calls"] == 2
        assert output["invalidations"] >= 1
    else:
        assert output["reviews"] == 0
        assert output["first"]["block"] is True
        assert output["second"]["block"] is True
        assert output["calls"] <= (4 if mode in {"same-unready", "missing"} else 3)
    if mode in {"same-unready", "missing"}:
        assert output["invalidations"] == 0
