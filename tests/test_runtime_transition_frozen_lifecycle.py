"""Opt-in frozen daemon lifecycle and configured hook protection.

Protection cases require a real approved connection through the frozen CLI.
An initial noninteractive connection may refuse with interactive approval
required, even in a generated home; this test preserves that refusal. It does
not qualify Desktop transitions, releases or installed migration.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.daemon.live_identity import DaemonArtifactBinding, verified_live_guard_daemon_identity
from codex_plugin_scanner.guard.live_process_identity import process_start_token
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity
from codex_plugin_scanner.guard.runtime_transition_codex_observer import observe_configured_codex_hook
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("dynamic_port", [False, True])
@pytest.mark.parametrize("protected", [False, True])
def test_real_frozen_daemon_identity_and_exact_retirement(tmp_path, monkeypatch, dynamic_port, protected):
    selected = os.environ.get("HOL_GUARD_FROZEN_QUALIFICATION_CORE")
    if selected is None:
        pytest.skip("requires an explicitly selected frozen qualification artifact")
    executable = Path(selected).resolve(strict=True)
    native = None
    launches = []
    real_launch = observer.run_isolated_hook_process

    def observed_launch(*args, **kwargs):
        result = real_launch(*args, **kwargs)
        output = json.loads(result.stdout) if result.stdout else {}
        decision = output.get("hookSpecificOutput", {}).get("permissionDecision")
        launches.append(
            {
                "returncode": result.returncode,
                "decision": decision,
                "stdout_bytes": len(result.stdout),
                "stderr_bytes": len(result.stderr),
            }
        )
        return result

    monkeypatch.setattr(observer, "run_isolated_hook_process", observed_launch)
    if protected:
        native_selected = os.environ.get("HOL_GUARD_FROZEN_QUALIFICATION_NATIVE")
        if native_selected is None:
            pytest.skip("requires an explicitly selected comparison native artifact")
        native_path = Path(native_selected).resolve(strict=True)
        metadata = native_path.stat()
        native = NativeRuntimeIdentity(
            native_path, metadata.st_size, metadata.st_mtime_ns, hashlib.sha256(native_path.read_bytes()).hexdigest()
        )
    home = tmp_path / "isolated-frozen-home"
    home.mkdir(mode=0o700)
    guard = home / ".hol-guard"
    guard.mkdir(mode=0o700)
    store = None
    workspace = home / "workspace"
    if protected:
        workspace.mkdir(mode=0o700)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    if dynamic_port:
        port = 0
    binding = DaemonArtifactBinding(executable, hashlib.sha256(executable.read_bytes()).hexdigest(), __version__)
    environment = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "HOL_GUARD_HOME": str(guard)}
    for name in (
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_APPROVAL_PASSWORD",
        "HOL_GUARD_APPROVAL_TOTP_CODE",
        "HOL_GUARD_TEST_KEYRING_FILE",
        "PYTEST_CURRENT_TEST",
    ):
        environment.pop(name, None)
    with (tmp_path / "frozen-daemon-stderr.txt").open("wb") as stderr:
        deadline = time.monotonic() + 20
        child = subprocess.Popen(
            [
                str(executable),
                "daemon",
                "--serve",
                "--home",
                str(home),
                "--guard-home",
                str(guard),
                "--port",
                str(port),
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            identity = None
            while time.monotonic() < deadline and child.poll() is None:
                identity = verified_live_guard_daemon_identity(
                    guard,
                    expected_artifact=binding,
                    deadline_monotonic=deadline,
                )
                if identity is not None:
                    break
                time.sleep(0.05)
            assert identity is not None, f"frozen daemon identity unverified; exit={child.poll()}"
            daemon_pid = identity["pid"]
            assert isinstance(daemon_pid, int) and daemon_pid > 0
            assert daemon_pid == child.pid or (os.name == "posix" and os.getpgid(daemon_pid) == child.pid)
            token = process_start_token(daemon_pid, deadline_monotonic=deadline)
            assert token is not None
            if protected:
                connected = real_launch(
                    [
                        str(executable),
                        "apps",
                        "connect",
                        "codex",
                        "--surface",
                        "hooks",
                        "--home",
                        str(home),
                        "--guard-home",
                        str(guard),
                        "--json",
                    ],
                    input_text="",
                    cwd=home,
                    environment=environment,
                    output_limit=64 * 1024,
                    deadline_monotonic=deadline,
                )
                assert connected.returncode == 0, f"frozen connection refused; exit={connected.returncode}"
                assert not (connected.timed_out or connected.containment_failed or connected.output_limit_exceeded)
                store = GuardStore(guard)
                assert native is not None
                config = home / ".codex/config.toml"
                try:
                    with codex_install_transaction(guard, config, actor="frozen-qualification", deadline=deadline):
                        proof = observe_configured_codex_hook(
                            operation_id=str(uuid.uuid4()),
                            artifact_generation=binding.executable_sha256,
                            expected_runtime=native,
                            guard_home=guard,
                            config_path=config,
                            workspace=workspace,
                            deadline_monotonic=deadline,
                            artifact_binding=binding,
                            receipt_store=store,
                        )
                except Exception as error:
                    pytest.fail(f"frozen protection refused: {type(error).__name__}; launches={launches}")
                assert proof.allow_receipt["authority"] == proof.deny_receipt["authority"] == "rust"
                assert proof.allow_receipt["decision"] == "allow"
                assert proof.deny_receipt["decision"] == "deny"
                observed_identity = verified_live_guard_daemon_identity(
                    guard,
                    expected_artifact=binding,
                    deadline_monotonic=deadline,
                )
                assert observed_identity is not None and observed_identity["pid"] == daemon_pid
            assert manager._retire_guard_daemon_pid(
                daemon_pid,
                expected_guard_home=guard,
                expected_start_token=token,
                deadline_monotonic=deadline,
            )
            child.wait(timeout=5)
            assert manager._guard_daemon_pid_is_proven_dead(daemon_pid)
            assert verified_live_guard_daemon_identity(guard, expected_artifact=binding) is None
        finally:
            if child.poll() is None:
                if os.name == "posix":
                    os.killpg(child.pid, signal.SIGTERM)
                else:
                    child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if os.name == "posix":
                        os.killpg(child.pid, signal.SIGKILL)
                    else:
                        child.kill()
                    child.wait(timeout=5)
