from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.daemon import server as daemon_server_module


class _FakeHandler:
    _handle_hook_readiness = daemon_server_module._GuardDaemonHandler._handle_hook_readiness
    _normalized_hook_workspace_string = staticmethod(
        daemon_server_module._GuardDaemonHandler._normalized_hook_workspace_string
    )

    def __init__(self, daemon_server: object) -> None:
        self._fake_daemon_server = daemon_server
        self.responses: list[tuple[dict[str, object], int]] = []
        self.path_rejections: list[tuple[str, str]] = []

    def _daemon_server(self) -> object:
        return self._fake_daemon_server

    @staticmethod
    def _optional_string(value: object) -> str | None:
        return value if isinstance(value, str) else None

    @staticmethod
    def _validated_hook_guard_home(value: str | None) -> str | None:
        return value

    @staticmethod
    def _validated_hook_directory_string(
        _parameter: str,
        value: str | None,
        *,
        roots: tuple[Path, ...],
    ) -> str | None:
        del roots
        return value

    @staticmethod
    def _hook_safe_roots() -> tuple[Path, ...]:
        return ()

    def _record_hook_path_rejection(self, *, parameter: str, reason: str) -> None:
        self.path_rejections.append((parameter, reason))

    def _write_json(
        self,
        payload: dict[str, object],
        *,
        status: int = 200,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        del extra_headers
        self.responses.append((payload, status))


def _daemon(*, prepared: dict[str, object] | None) -> SimpleNamespace:
    class Worker:
        def prepare_workspace_policy(self, workspace: Path, *, deadline: float) -> dict[str, object] | None:
            assert workspace.is_absolute()
            assert deadline - time.monotonic() > 20
            time.sleep(0.02)
            return prepared

    class Runner:
        def __init__(self) -> None:
            self.calls: list[float] = []

        def wait_for_capacity(self, *, minimum_workers: int, timeout_seconds: float) -> bool:
            assert minimum_workers == 1
            self.calls.append(timeout_seconds)
            return prepared is not None

    return SimpleNamespace(
        hook_worker=Worker(),
        hook_process_runner=Runner(),
        diagnostics=SimpleNamespace(record_exception=lambda _code: None),
    )


def test_workspace_readiness_waits_for_delayed_native_ack(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(daemon_server_module, "_native_mode_requires_rust", lambda: True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = _daemon(prepared={"snapshot_generation": 1})
    handler = _FakeHandler(daemon)

    handler._handle_hook_readiness(
        {},
        f"workspace={workspace}&guard-home={tmp_path / 'guard-home'}",
        default_harness="omp",
    )

    assert handler.responses == [
        (
            {
                "ready": True,
                "native_required": True,
                "native_route": "native_resident",
                "workspace_acknowledged": True,
                "worker_ready": True,
            },
            200,
        )
    ]
    assert daemon.hook_process_runner.calls
    assert daemon.hook_process_runner.calls[0] < 25


def test_workspace_readiness_stays_fail_closed_when_native_ack_is_unready(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(daemon_server_module, "_native_mode_requires_rust", lambda: True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = _daemon(prepared=None)
    handler = _FakeHandler(daemon)

    handler._handle_hook_readiness(
        {},
        f"workspace={workspace}&guard-home={tmp_path / 'guard-home'}",
        default_harness="omp",
    )

    assert handler.responses == [({"ready": False, "reason_code": "native_policy_not_ready"}, 503)]
    assert daemon.hook_process_runner.calls == []


def test_pi_source_prepares_workspace_before_timed_tool_review(tmp_path: Path) -> None:
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
    tool_readiness = source.index("ensureGuardWorkspaceReady(snapshot.cwd, false)", tool_call)
    semantic_review = source.index("const response = await runGuard(", tool_call)

    assert readiness_request < agent_start
    assert agent_start < session_start
    assert session_start < tool_call
    assert tool_readiness < semantic_review
    assert "native_route !== 'native_resident'" in source
    assert "if (connection === null || connection.stateId === null)" in source
    assert '"authenticated-control-plane-failure"' in source
    assert daemon_server_module._GuardDaemonHandler._requires_header_token(
        "/v1/hooks/omp/readiness",
        ["v1", "hooks", "omp", "readiness"],
    )
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
    assert output["inFlightTool"]["ready"] is True
    assert output["readinessCalls"] == 5
