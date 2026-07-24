from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from argparse import Namespace
from pathlib import Path
from typing import TextIO

import pytest

from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


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
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )


def test_pi_hook_is_not_queued_behind_unrelated_overlay_free_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_started = threading.Event()
    release_first = threading.Event()

    def fake_run_guard_command(args: Namespace, *, input_text: str, output_stream: TextIO) -> int:
        del args
        payload = json.loads(input_text)
        if payload["tool_call_id"] == "first":
            first_started.set()
            assert release_first.wait(timeout=2)
        output_stream.write('{"decision":"allow"}')
        return 0

    monkeypatch.setattr(guard_commands_module, "run_guard_command", fake_run_guard_command)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    first_result: list[dict[str, object]] = []

    def run_first() -> None:
        request = _pi_hook_request(daemon=daemon, guard_home=str(store.guard_home), call_id="first")
        with urllib.request.urlopen(request, timeout=3) as response:
            first_result.append(json.loads(response.read()))

    first_thread = threading.Thread(target=run_first)
    first_thread.start()
    try:
        assert first_started.wait(timeout=1)
        request = _pi_hook_request(daemon=daemon, guard_home=str(store.guard_home), call_id="second")
        with urllib.request.urlopen(request, timeout=1) as response:
            second_result = json.loads(response.read())
    finally:
        release_first.set()
        first_thread.join(timeout=3)
        daemon.stop()

    assert second_result == {"decision": "allow"}
    assert first_result == [{"decision": "allow"}]


def test_pi_daemon_keeps_health_responsive_during_twenty_active_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_condition = threading.Condition()
    release_hooks = threading.Event()
    started_count = 0

    def fake_run_guard_command(args: Namespace, *, input_text: str, output_stream: TextIO) -> int:
        nonlocal started_count
        del args, input_text
        with started_condition:
            started_count += 1
            started_condition.notify_all()
        assert release_hooks.wait(timeout=5)
        output_stream.write('{"decision":"allow"}')
        return 0

    monkeypatch.setattr(guard_commands_module, "run_guard_command", fake_run_guard_command)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
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

    threads = [threading.Thread(target=run_hook, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    try:
        with started_condition:
            assert started_condition.wait_for(lambda: started_count == 20, timeout=5)
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
    assert detailed_health["hook_capacity"]["active"] == 20
    assert detailed_health["hook_capacity"]["limit"] == 32
    assert detailed_health["hook_capacity"]["rejected"] == 0
    assert detailed_health["hook_capacity"]["per_harness_active"]["pi"] == 20
    assert detailed_health["request_capacity"]["limit"] == 64
    assert failures == []
    assert results == [{"decision": "allow"}] * 20


def test_pi_extension_keeps_fallbacks_inside_outer_hook_deadline(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
    )

    assert "const GUARD_TIMEOUT_MS = 4000;" in source
    assert "const GUARD_DEADLINE_RESERVE_MS = 250;" in source
    assert "const GUARD_DAEMON_TIMEOUT_MS = 1250;" in source
    assert "const GUARD_CLI_TIMEOUT_MS = 2250;" in source
    assert 'const GUARD_ARGS = ["hook", "--json"' in source
    assert "compatibility_version !== GUARD_COMPATIBILITY_VERSION" in source
    assert "error.name === 'AbortError'" in source
    assert source.index("error.name === 'AbortError'") > source.index("await fetch")
    assert "an unresponsive daemon cannot stall or bypass Guard enforcement" in source
    timeout_branch = source[source.index("error.name === 'AbortError'") :]
    assert "return null;" in timeout_branch
    assert "if (!response.ok) {" in source
    assert "response.status === 401 || response.status === 403" in source
    assert 'decision: "deny"' in source
    assert "reason_code: reasonCode" in source
    assert "const deadlineAt = Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS" in source
    assert "Math.max(deadlineAt - Date.now(), 1)" in source
    assert "spawnSync" not in source
    assert "guardCliEvaluationInFlight" in source
    assert "await runGuardCliCommand(command, args, serializedPayload, cliTimeoutMs)" in source
    assert 'reason_code: "guard_cli_recovery_busy"' in source
    assert 'reason_code: "guard_cli_recovery_timeout"' in source


def test_pi_hook_deadline_stays_inside_host_timeout() -> None:
    pi_hook_host_timeout_ms = 4_500

    from codex_plugin_scanner.guard.adapters.pi_extension_source import (
        GUARD_CLI_HOOK_TIMEOUT_MS,
        GUARD_DAEMON_HOOK_TIMEOUT_MS,
        GUARD_HOOK_DEADLINE_RESERVE_MS,
        GUARD_HOOK_TIMEOUT_MS,
    )

    assert pi_hook_host_timeout_ms > GUARD_HOOK_TIMEOUT_MS
    assert (
        GUARD_DAEMON_HOOK_TIMEOUT_MS + GUARD_CLI_HOOK_TIMEOUT_MS + GUARD_HOOK_DEADLINE_RESERVE_MS
        < GUARD_HOOK_TIMEOUT_MS
    )


@pytest.mark.skipif(_bun_executable() is None, reason="Bun is required to execute the managed Pi extension")
def test_pi_extension_treats_authenticated_daemon_rejection_as_terminal(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    bun = _bun_executable()
    assert bun is not None
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1}),
        encoding="utf-8",
    )
    (guard_home / "daemon-auth-token").write_text("test-token", encoding="utf-8")
    extension_path = tmp_path / "hol-guard.ts"
    compiled_path = tmp_path / "hol-guard.mjs"
    harness_path = tmp_path / "load.mjs"
    extension_path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=tmp_path,
            settings_path=tmp_path / "settings.json",
        ),
        encoding="utf-8",
    )
    subprocess.run(
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
    harness_path.write_text(
        f"""
import installGuard from {json.dumps(str(compiled_path))};
globalThis.fetch = async () => new Response(
  JSON.stringify({{ error: "invalid_hook_workspace_path" }}),
  {{ status: 400, headers: {{ "Content-Type": "application/json" }} }},
);
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
  blocked: results.filter((result) => result?.block === true).length,
  terminalReasons: notices.filter((reason) => reason.includes("invalid_hook_workspace_path")).length,
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
    payload = json.loads(completed.stdout)

    assert payload["blocked"] == 20
    assert payload["terminalReasons"] == 20
    assert payload["elapsedMs"] < 1_000


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
    (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1}),
        encoding="utf-8",
    )
    (guard_home / "daemon-auth-token").write_text("test-token", encoding="utf-8")
    extension_path = tmp_path / "hol-guard.ts"
    compiled_path = tmp_path / "hol-guard.mjs"
    harness_path = tmp_path / "load.mjs"
    extension_path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=tmp_path,
            settings_path=tmp_path / "settings.json",
        ),
        encoding="utf-8",
    )
    subprocess.run(
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
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fallback_count_path = tmp_path / "fallback-count"
    fake_cli = fake_bin / "plugin-guard"
    fake_cli.write_text(
        (
            '#!/bin/sh\ntrap "" TERM\nprintf "1\\n" >> "$FALLBACK_COUNT_PATH"\n'
            'sleep 5\nprintf \'{"decision":"allow"}\\n\'\n'
        ),
        encoding="utf-8",
    )
    fake_cli.chmod(0o755)
    harness_path.write_text(
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
    payload = json.loads(completed.stdout)

    assert fallback_count_path.read_text(encoding="utf-8").splitlines() == ["1"]
    assert payload["allowed"] == 0
    assert payload["blocked"] == 20
    assert payload["recoveryBusy"] == 19
    assert payload["recoveryTimeout"] == 1
    assert payload["elapsedMs"] < 3_000
