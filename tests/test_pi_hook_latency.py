from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.client import HTTPResponse
from pathlib import Path
from typing import Protocol, cast

import pytest

from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview, HookProcessRunner
from codex_plugin_scanner.guard.daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


class _DaemonInternals(Protocol):
    auth_token: str
    hook_process_runner: HookProcessRunner


def _daemon_internals(daemon: GuardDaemonServer) -> _DaemonInternals:
    return cast(_DaemonInternals, vars(daemon)["_server"])


def _decode_json_object(payload: str | bytes) -> dict[str, object]:
    loaded = cast(object, json.loads(payload))
    assert isinstance(loaded, dict)
    return cast(dict[str, object], loaded)


def _read_json_object(response: HTTPResponse) -> dict[str, object]:
    return _decode_json_object(response.read())


def _bun_executable() -> str | None:
    path_without_guard_shims = os.pathsep.join(
        entry for entry in os.environ.get("PATH", "").split(os.pathsep) if "package-shims" not in entry
    )
    unwrapped = shutil.which("bun", path=path_without_guard_shims)
    if unwrapped is not None:
        return unwrapped
    user_install = Path.home() / ".bun" / "bin" / "bun"
    if user_install.is_file():
        return str(user_install)
    return shutil.which("bun")


def _pi_hook_request(*, daemon: GuardDaemonServer, guard_home: str, call_id: str) -> urllib.request.Request:
    query = urllib.parse.urlencode({"guard-home": guard_home, "home": guard_home})
    return urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}",
        data=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_call_id": call_id,
                "tool_name": "read",
                "tool_input": {"path": "README.md"},
            }
        ).encode(),
        headers={"Content-Type": "application/json", "X-Guard-Token": _daemon_internals(daemon).auth_token},
        method="POST",
    )


def test_review_required_pi_hook_returns_before_worker_deadline(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    (guard_home / "config.toml").write_text(
        'security_level = "custom"\n[risk_actions]\ndestructive_shell = "review"\n',
        encoding="utf-8",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    query = urllib.parse.urlencode(
        {
            "guard-home": str(guard_home),
            "home": str(tmp_path),
            "workspace": str(tmp_path),
        }
    )
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}",
        data=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf build"},
            }
        ).encode(),
        headers={"Content-Type": "application/json", "X-Guard-Token": _daemon_internals(daemon).auth_token},
        method="POST",
    )
    try:
        started = time.monotonic()
        with urllib.request.urlopen(request, timeout=2) as response:
            result = _read_json_object(response)
        elapsed = time.monotonic() - started
    finally:
        daemon.stop()

    assert result["decision"] == "deny"
    assert store.count_pending_requests(harness="pi") == 1
    assert elapsed < 1.45


def test_pi_hook_is_not_queued_behind_unrelated_overlay_free_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_started = threading.Event()
    release_first = threading.Event()

    def fake_review(**kwargs: object) -> HookProcessReview:
        payload = kwargs["payload"]
        assert isinstance(payload, dict)
        if payload["tool_call_id"] == "first":
            first_started.set()
            assert release_first.wait(timeout=2)
        return HookProcessReview({"decision": "allow"}, None)

    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    monkeypatch.setattr(_daemon_internals(daemon).hook_process_runner, "review", fake_review)
    daemon.start()
    first_result: list[dict[str, object]] = []

    def run_first() -> None:
        request = _pi_hook_request(daemon=daemon, guard_home=str(store.guard_home), call_id="first")
        with cast(HTTPResponse, urllib.request.urlopen(request, timeout=3)) as response:
            first_result.append(_read_json_object(response))

    first_thread = threading.Thread(target=run_first)
    first_thread.start()
    try:
        assert first_started.wait(timeout=1)
        request = _pi_hook_request(daemon=daemon, guard_home=str(store.guard_home), call_id="second")
        with cast(HTTPResponse, urllib.request.urlopen(request, timeout=1)) as response:
            second_result = _read_json_object(response)
    finally:
        release_first.set()
        first_thread.join(timeout=3)
        daemon.stop()

    assert second_result == {"decision": "allow"}
    assert first_result == [{"decision": "allow"}]


def test_pi_daemon_keeps_health_responsive_at_active_process_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_condition = threading.Condition()
    release_hooks = threading.Event()
    started_count = 0

    def fake_review(**kwargs: object) -> HookProcessReview:
        nonlocal started_count
        del kwargs
        with started_condition:
            started_count += 1
            started_condition.notify_all()
        assert release_hooks.wait(timeout=5)
        return HookProcessReview({"decision": "allow"}, None)

    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    monkeypatch.setattr(_daemon_internals(daemon).hook_process_runner, "review", fake_review)
    daemon.start()
    process_capacity = _daemon_internals(daemon).hook_process_runner.stats()["ready"]
    assert process_capacity >= 1
    results: list[dict[str, object]] = []
    failures: list[Exception] = []

    def run_hook(index: int) -> None:
        try:
            request = _pi_hook_request(
                daemon=daemon,
                guard_home=str(store.guard_home),
                call_id=f"load-{index}",
            )
            with urllib.request.urlopen(request, timeout=6) as response:
                results.append(json.loads(response.read()))
        except Exception as error:
            failures.append(error)

    threads = [threading.Thread(target=run_hook, args=(index,)) for index in range(process_capacity)]
    for thread in threads:
        thread.start()
    try:
        with started_condition:
            assert started_condition.wait_for(lambda: started_count == process_capacity, timeout=5)
        health_started_at = time.monotonic()
        with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=1) as response:
            health = json.loads(response.read())
        health_elapsed = time.monotonic() - health_started_at
        detailed_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/healthz/details",
            headers={"X-Guard-Token": daemon._server.auth_token},
        )
        with urllib.request.urlopen(detailed_request, timeout=2) as response:
            detailed_health = json.loads(response.read())
    finally:
        release_hooks.set()
        for thread in threads:
            thread.join(timeout=7)
        daemon.stop()

    assert health == {"ok": True, "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION}
    assert health_elapsed < 0.5
    assert detailed_health["hook_capacity"]["active"] == process_capacity
    assert detailed_health["hook_capacity"]["limit"] == 32
    assert detailed_health["hook_capacity"]["rejected"] == 0
    assert detailed_health["hook_capacity"]["per_harness_active"]["pi"] == process_capacity
    assert detailed_health["hook_process_capacity"]["active"] == process_capacity
    assert detailed_health["hook_process_capacity"]["active_limit"] == process_capacity
    assert detailed_health["hook_process_capacity"]["queued"] == 0
    assert detailed_health["request_capacity"]["limit"] == 32
    assert failures == []
    assert results == [{"decision": "allow"}] * process_capacity


def test_pi_extension_keeps_fallbacks_inside_outer_hook_deadline(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
    )

    assert "const GUARD_TIMEOUT_MS = 4250;" in source
    assert "const GUARD_DEADLINE_RESERVE_MS = 250;" in source
    assert "const GUARD_DAEMON_TIMEOUT_MS = 1700;" in source
    assert "const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250;" in source
    assert "const GUARD_DAEMON_RETRY_TIMEOUT_MS = 150;" in source
    assert "const GUARD_CLI_TIMEOUT_MS = 1400;" in source
    assert 'const GUARD_ARGS = ["hook", "--json"' in source
    assert "compatibility_version !== GUARD_COMPATIBILITY_VERSION" in source
    assert "error.name === 'AbortError'" in source
    assert source.index("error.name === 'AbortError'") > source.index("await fetch")
    timeout_branch = source[source.index("error.name === 'AbortError'") :]
    assert "return { response: null, recoveryKind: null }" in timeout_branch
    assert "response.status === 401 || response.status === 403" in source
    assert 'recoveryKind: "authenticated-control-plane-failure"' in source
    assert "schedule_guard_daemon_recovery" in source
    assert "failure_kind=sys.argv[1]" in source
    assert source.count("assign_current_process_to_windows_hook_job") == 4
    assert "_windows_job=assign_current_process_to_windows_hook_job()" in source
    assert "allow_breakaway=True" in source
    assert "HOL_GUARD_WINDOWS_JOB_CONTAINED" in source
    assert "if (!response.ok) {" in source
    assert "reason_code: reasonCode" in source
    assert "const deadlineAt = Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS" in source
    assert "Math.max(deadlineAt - Date.now(), 1)" in source
    assert "spawnSync" not in source
    assert "guardCliEvaluationInFlight" in source
    assert "guardDaemonRecoveryInFlight" in source
    assert "result = await runGuardCliCommand(" in source
    assert "GUARD_CLI_WRAPPER_COMMAND" in source
    assert "[...GUARD_CLI_WRAPPER_ARGS, JSON.stringify(args)]" in source
    assert 'reason_code: "guard_cli_recovery_busy"' in source
    assert 'reason_code: "guard_cli_recovery_timeout"' in source


def test_pi_hook_deadline_stays_inside_host_timeout() -> None:
    pi_hook_host_timeout_ms = 4_500

    from codex_plugin_scanner.guard.adapters.pi_extension_source import (
        GUARD_CLI_HOOK_TIMEOUT_MS,
        GUARD_DAEMON_HOOK_TIMEOUT_MS,
        GUARD_DAEMON_RECOVERY_TIMEOUT_MS,
        GUARD_DAEMON_RETRY_TIMEOUT_MS,
        GUARD_HOOK_DEADLINE_RESERVE_MS,
        GUARD_HOOK_TIMEOUT_MS,
    )

    assert pi_hook_host_timeout_ms > GUARD_HOOK_TIMEOUT_MS
    assert GUARD_CLI_HOOK_TIMEOUT_MS > 750
    assert (
        GUARD_DAEMON_HOOK_TIMEOUT_MS
        + GUARD_DAEMON_RECOVERY_TIMEOUT_MS
        + GUARD_DAEMON_RETRY_TIMEOUT_MS
        + GUARD_CLI_HOOK_TIMEOUT_MS
        + GUARD_HOOK_DEADLINE_RESERVE_MS
        < GUARD_HOOK_TIMEOUT_MS
    )


@pytest.mark.skipif(_bun_executable() is None, reason="Bun is required to execute Pi cleanup helpers")
def test_pi_cli_detects_split_windows_job_marker(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_cli_runtime_source import CLI_RUNTIME_HELPERS_SOURCE

    bun = _bun_executable()
    assert bun is not None
    script_path = tmp_path / "pi-split-marker.ts"
    _ = script_path.write_text(
        CLI_RUNTIME_HELPERS_SOURCE
        + """
const state: GuardStderrMarkerState = { pending: '', contained: false };
const first = consumeGuardStderrChunk(state, 'HOL_GUARD_WINDOWS_JOB_CONT', false);
const second = consumeGuardStderrChunk(state, 'AINED\\nvisible', false);
const final = consumeGuardStderrChunk(state, '', true);
console.log(JSON.stringify({
  contained: state.contained,
  stderr: first + second + final,
}));
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(script_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert _decode_json_object(completed.stdout) == {
        "contained": True,
        "stderr": "visible",
    }


@pytest.mark.skipif(_bun_executable() is None, reason="Bun is required to execute Pi cleanup helpers")
def test_pi_cli_cleanup_failure_settles_and_latches(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_cli_runtime_source import CLI_RUNTIME_HELPERS_SOURCE

    bun = _bun_executable()
    assert bun is not None
    script_path = tmp_path / "pi-cleanup-failure.ts"
    source = CLI_RUNTIME_HELPERS_SOURCE.replace("process.platform", "guardPlatform")
    _ = script_path.write_text(
        """
const guardPlatform = "win32";
const GUARD_TASKKILL_PATH: string | null = null;
const GUARD_TEXT_LIMIT_CHARS = 1_000;
const child = {
  pid: 123,
  exitCode: null,
  signalCode: null,
  stdout: undefined,
  stderr: undefined,
  stdin: { once: () => {}, end: () => {} },
  once: () => {},
  kill: () => { throw new Error("kill refused"); },
};
const spawn = () => child;
"""
        + source
        + """
const startedAt = performance.now();
const first = await runGuardCliCommand("guard", [], "", 1);
const recoveryAllowed = await recoverGuardDaemon(1, "transport-failure");
console.log(JSON.stringify({
  elapsedMs: performance.now() - startedAt,
  code: first.error?.code,
  recoveryAllowed,
}));
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(script_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    payload = _decode_json_object(completed.stdout)

    assert payload["code"] == "ECONTAINMENT"
    assert payload["recoveryAllowed"] is False
    elapsed_ms = payload["elapsedMs"]
    assert isinstance(elapsed_ms, int | float)
    assert float(elapsed_ms) < 1_000


@pytest.mark.skipif(_bun_executable() is None, reason="Bun is required to execute Pi cleanup helpers")
def test_pi_exited_windows_parent_without_job_proof_latches(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_cli_runtime_source import CLI_RUNTIME_HELPERS_SOURCE

    bun = _bun_executable()
    assert bun is not None
    script_path = tmp_path / "pi-exited-parent.ts"
    source = CLI_RUNTIME_HELPERS_SOURCE.replace("process.platform", "guardPlatform")
    _ = script_path.write_text(
        """
const guardPlatform = "win32";
const GUARD_TASKKILL_PATH: string | null = "taskkill.exe";
const GUARD_TEXT_LIMIT_CHARS = 1_000;
const GUARD_DAEMON_RECOVERY_COMMAND = "guard";
const GUARD_DAEMON_RECOVERY_ARGS: string[] = [];
let spawnCalls = 0;
const child = {
  pid: 123,
  exitCode: 0,
  signalCode: null,
  stdout: undefined,
  stderr: undefined,
  stdin: { once: () => {}, end: () => {} },
  once: () => {},
  kill: () => true,
};
const spawn = () => {
  spawnCalls += 1;
  return child;
};
"""
        + source
        + """
const first = await runGuardCliCommand("guard", [], "", 1);
const recoveryAllowed = await recoverGuardDaemon(1, "transport-failure");
console.log(JSON.stringify({
  code: first.error?.code,
  recoveryAllowed,
  spawnCalls,
}));
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(script_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    payload = _decode_json_object(completed.stdout)

    assert payload == {
        "code": "ECONTAINMENT",
        "recoveryAllowed": False,
        "spawnCalls": 3,
    }


@pytest.mark.skipif(
    _bun_executable() is None or os.name != "posix",
    reason="Bun and POSIX process groups are required for fallback termination testing",
)
def test_pi_cleanup_kills_descendants_after_direct_parent_exits(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_cli_runtime_source import CLI_RUNTIME_HELPERS_SOURCE

    bun = _bun_executable()
    assert bun is not None
    marker = tmp_path / "pi-exited-parent-descendant-ran"
    descendant = f"import time;time.sleep(0.6);open({str(marker)!r},'w',encoding='utf-8').write('ran')"
    parent = f"import subprocess,sys;subprocess.Popen([sys.executable,'-c',{descendant!r}])"
    script_path = tmp_path / "pi-exited-parent-posix.ts"
    _ = script_path.write_text(
        """
import { spawn } from "node:child_process";
const GUARD_TASKKILL_PATH: string | null = null;
const GUARD_TEXT_LIMIT_CHARS = 1_000;
const GUARD_DAEMON_RECOVERY_COMMAND = "guard";
const GUARD_DAEMON_RECOVERY_ARGS: string[] = [];
"""
        + CLI_RUNTIME_HELPERS_SOURCE
        + f"""
const result = await runGuardCliCommand(
  {json.dumps(str(Path(sys.executable).absolute()))},
  ["-c", {json.dumps(parent)}],
  "",
  100,
);
await new Promise((resolve) => setTimeout(resolve, 800));
console.log(JSON.stringify({{ code: result.error?.code }}));
""",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [bun, str(script_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert _decode_json_object(completed.stdout) == {"code": "ETIMEDOUT"}
    assert not marker.exists()


@pytest.mark.skipif(_bun_executable() is None, reason="Bun is required to execute the managed Pi extension")
def test_pi_extension_treats_authenticated_daemon_overload_as_terminal(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    bun = _bun_executable()
    assert bun is not None
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _ = (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1}),
        encoding="utf-8",
    )
    _ = (guard_home / "daemon-auth-token").write_text("test-token", encoding="utf-8")
    extension_path = tmp_path / "hol-guard.ts"
    compiled_path = tmp_path / "hol-guard.mjs"
    harness_path = tmp_path / "load.mjs"
    _ = extension_path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=tmp_path,
            settings_path=tmp_path / "settings.json",
        ),
        encoding="utf-8",
    )
    _ = subprocess.run(
        [
            bun,
            "build",
            str(extension_path),
            "--target=bun",
            "--format=esm",
            f"--outfile={compiled_path}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    _ = harness_path.write_text(
        f"""
import installGuard from {json.dumps(str(compiled_path))};
let fetchCount = 0;
globalThis.fetch = async () => {{
  fetchCount += 1;
  return new Response(
    JSON.stringify({{
      reason_code: "transient_overload",
      retry_after_ms: 25,
      estimated_service_ms: 100,
    }}),
    {{ status: 503, headers: {{ "Content-Type": "application/json" }} }},
  );
}};
const handlers = new Map();
installGuard({{ on: (event, handler) => handlers.set(event, handler), sendMessage: () => {{}} }});
const handler = handlers.get("tool_call");
const notices = [];
const results = await Promise.all(Array.from({{ length: 20 }}, (_, index) => handler(
  {{ toolCallId: `call-${{index}}`, toolName: "read", input: {{ path: "README.md" }} }},
  {{ cwd: {json.dumps(str(tmp_path))}, ui: {{ notify: (reason) => notices.push(reason) }} }},
)));
console.log(JSON.stringify({{
  fetchCount,
  blocked: results.filter((result) => result?.block === true).length,
  overloadReasons: notices.filter((reason) => reason.includes("temporarily saturated")).length,
}}));
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(harness_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    payload = _decode_json_object(completed.stdout)

    assert payload == {"fetchCount": 40, "blocked": 20, "overloadReasons": 20}


@pytest.mark.skipif(
    _bun_executable() is None or os.name != "posix",
    reason="Bun and POSIX process groups are required for fallback termination testing",
)
def test_pi_extension_allows_only_one_cli_fallback_during_daemon_outage(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    bun = _bun_executable()
    assert bun is not None
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _ = (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1}),
        encoding="utf-8",
    )
    _ = (guard_home / "daemon-auth-token").write_text("test-token", encoding="utf-8")
    extension_path = tmp_path / "hol-guard.ts"
    compiled_path = tmp_path / "hol-guard.mjs"
    harness_path = tmp_path / "load.mjs"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fallback_count_path = tmp_path / "fallback-count"
    fake_cli = fake_bin / "plugin-guard"
    _ = fake_cli.write_text(
        ('#!/bin/sh\nprintf "1\\n" >> "$FALLBACK_COUNT_PATH"\nsleep 0.5\nprintf \'{"decision":"allow"}\\n\'\n'),
        encoding="utf-8",
    )
    _ = fake_cli.chmod(0o755)
    source = managed_extension_source(
        guard_home=guard_home,
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
    )
    recovery_command = f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(Path(sys.executable).absolute()))};"
    source = source.replace(
        recovery_command,
        'const GUARD_DAEMON_RECOVERY_COMMAND = "missing-guard-recovery-command";',
    )
    source = source.replace(
        f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(Path(sys.executable).absolute()))};",
        f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(fake_cli))};",
    )
    source = source.replace(
        source[
            source.index("const GUARD_CLI_WRAPPER_ARGS = ") : source.index(
                ";\n", source.index("const GUARD_CLI_WRAPPER_ARGS = ")
            )
            + 2
        ],
        "const GUARD_CLI_WRAPPER_ARGS = [];\n",
    )
    assert "missing-guard-recovery-command" in source
    _ = extension_path.write_text(source, encoding="utf-8")
    _ = subprocess.run(
        [
            bun,
            "build",
            str(extension_path),
            "--target=bun",
            "--format=esm",
            f"--outfile={compiled_path}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    _ = harness_path.write_text(
        f"""
import installGuard from {json.dumps(str(compiled_path))};
globalThis.fetch = async () => {{ throw new Error("daemon unavailable"); }};
const handlers = new Map();
installGuard({{ on: (event, handler) => handlers.set(event, handler), sendMessage: () => {{}} }});
const handler = handlers.get("tool_call");
const notices = [];
const startedAt = performance.now();
const results = await Promise.all(Array.from({{ length: 20 }}, (_, index) => handler(
  {{ toolCallId: `call-${{index}}`, toolName: "read", input: {{ path: "README.md" }} }},
  {{ cwd: {json.dumps(str(tmp_path))}, ui: {{ notify: (reason) => notices.push(reason) }} }},
)));
console.log(JSON.stringify({{
  elapsedMs: performance.now() - startedAt,
  allowed: results.filter((result) => result === undefined).length,
  blocked: results.filter((result) => result?.block === true).length,
  recoveryBusy: notices.filter((reason) => reason.includes("recovery is already reviewing")).length,
  recoveryTimeout: notices.filter((reason) => reason.includes("could not complete fallback review")).length,
}}));
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(harness_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
        env={
            **os.environ,
            "FALLBACK_COUNT_PATH": str(fallback_count_path),
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        },
    )
    payload = _decode_json_object(completed.stdout)

    assert fallback_count_path.read_text(encoding="utf-8").splitlines() == ["1"]
    assert payload["allowed"] == 1
    assert payload["blocked"] == 19
    assert payload["recoveryBusy"] == 19
    assert payload["recoveryTimeout"] == 0
    elapsed_ms = payload["elapsedMs"]
    assert isinstance(elapsed_ms, (int, float))
    assert elapsed_ms < 2_000
