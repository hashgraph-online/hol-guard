"""Tests for guarded Codex remote-control launches."""

from __future__ import annotations

import socket
import stat
import subprocess
from pathlib import Path

from codex_plugin_scanner.guard.adapters import codex_remote_control


def test_guarded_codex_launch_starts_remote_control_and_connects_tui(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []
    home_dir = tmp_path / "home"
    socket_path = home_dir / ".codex" / "app-server-control" / "app-server-control.sock"

    def fake_run(command, **kwargs):
        calls.append((list(command), dict(kwargs["env"])))
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    monkeypatch.setattr(codex_remote_control.subprocess, "run", fake_run)
    monkeypatch.setattr(codex_remote_control, "_wait_for_socket", lambda _path: True)

    command = codex_remote_control.guarded_codex_launch_command(
        executable="/usr/local/bin/codex",
        home_dir=home_dir,
        passthrough_args=["Fix the failing test."],
        environ={"PATH": "/usr/bin"},
    )

    assert calls[0][0] == ["/usr/local/bin/codex", "remote-control", "start", "--json"]
    assert calls[0][1]["HOME"] == str(home_dir)
    assert calls[0][1]["CODEX_HOME"] == str(home_dir / ".codex")
    assert (home_dir / ".codex").is_dir()
    assert command == [
        "/usr/local/bin/codex",
        "--remote",
        f"unix://{socket_path}",
        "Fix the failing test.",
    ]


def test_guarded_codex_launch_falls_back_when_remote_control_is_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        codex_remote_control.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr="unsupported"),
    )
    monkeypatch.setattr(codex_remote_control, "_start_direct_app_server", lambda **kwargs: False)

    command = codex_remote_control.guarded_codex_launch_command(
        executable="codex",
        home_dir=tmp_path / "home",
        passthrough_args=["Fix the failing test."],
        environ={},
    )

    assert command == ["codex", "Fix the failing test."]


def test_guarded_codex_launch_starts_portable_app_server_when_managed_daemon_is_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    starts: list[dict[str, object]] = []
    home_dir = tmp_path / "home"

    monkeypatch.setattr(
        codex_remote_control.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr="unsupported"),
    )

    def fake_start(**kwargs):
        starts.append(kwargs)
        return True

    monkeypatch.setattr(codex_remote_control, "_start_direct_app_server", fake_start)

    command = codex_remote_control.guarded_codex_launch_command(
        executable="/usr/local/bin/codex",
        home_dir=home_dir,
        passthrough_args=[],
        environ={},
    )

    socket_path = home_dir / ".codex" / "app-server-control" / "app-server-control.sock"
    assert starts[0]["executable"] == "/usr/local/bin/codex"
    assert starts[0]["socket_path"] == socket_path
    assert command == ["/usr/local/bin/codex", "--remote", f"unix://{socket_path}"]


def test_guarded_codex_launch_does_not_wrap_unsupported_subcommands(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("remote control must not start for codex exec")

    monkeypatch.setattr(codex_remote_control.subprocess, "run", fail_run)

    command = codex_remote_control.guarded_codex_launch_command(
        executable="codex",
        home_dir=tmp_path / "home",
        passthrough_args=["exec", "Run tests."],
        environ={},
    )

    assert command == ["codex", "exec", "Run tests."]


def test_guarded_codex_launch_does_not_wrap_unsupported_subcommand_after_global_flags(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("remote control must not start for codex exec")

    monkeypatch.setattr(codex_remote_control.subprocess, "run", fail_run)

    command = codex_remote_control.guarded_codex_launch_command(
        executable="codex",
        home_dir=tmp_path / "home",
        passthrough_args=["--config", "model_reasoning_effort=high", "exec", "Run tests."],
        environ={},
    )

    assert command == [
        "codex",
        "--config",
        "model_reasoning_effort=high",
        "exec",
        "Run tests.",
    ]


def test_guarded_codex_launch_preserves_explicit_remote_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("remote control must not replace an explicit remote")

    monkeypatch.setattr(codex_remote_control.subprocess, "run", fail_run)

    command = codex_remote_control.guarded_codex_launch_command(
        executable="codex",
        home_dir=tmp_path / "home",
        passthrough_args=["--remote", "unix:///custom/codex.sock"],
        environ={},
    )

    assert command == ["codex", "--remote", "unix:///custom/codex.sock"]


def test_wait_for_socket_rejects_trusted_stale_socket(
    tmp_path: Path,
    monkeypatch,
) -> None:
    socket_path = tmp_path / "app-server.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.close()
    monkeypatch.setattr(codex_remote_control, "_REMOTE_CONTROL_READY_TIMEOUT_SECONDS", 0.01)

    assert codex_remote_control._socket_is_trusted(socket_path) is True
    assert codex_remote_control._wait_for_socket(socket_path) is False


def test_wait_for_socket_accepts_trusted_live_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / "app-server.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    try:
        assert codex_remote_control._wait_for_socket(socket_path) is True
    finally:
        listener.close()


def test_wait_for_socket_retries_transient_os_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def fake_trust_check(_socket_path: Path) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("socket is being created")
        return True

    monkeypatch.setattr(codex_remote_control, "_socket_is_trusted", fake_trust_check)
    monkeypatch.setattr(codex_remote_control, "_socket_is_live", lambda _path: True)
    monkeypatch.setattr(codex_remote_control, "_REMOTE_CONTROL_READY_TIMEOUT_SECONDS", 0.2)

    assert codex_remote_control._wait_for_socket(tmp_path / "app-server.sock") is True
    assert calls == 2


def test_direct_app_server_uses_private_control_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    socket_path = tmp_path / "home" / ".codex" / "app-server-control" / "app-server-control.sock"

    class FakeProcess:
        pid = 4321

    wait_calls = 0

    def fake_wait(path: Path) -> bool:
        nonlocal wait_calls
        wait_calls += 1
        return wait_calls > 1 and path.parent.exists()

    monkeypatch.setattr(codex_remote_control, "_wait_for_socket", fake_wait)
    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", lambda command, **kwargs: FakeProcess())

    started = codex_remote_control._start_direct_app_server(
        executable="codex",
        socket_path=socket_path,
        environment={},
    )

    directory_mode = stat.S_IMODE(socket_path.parent.stat().st_mode)
    pid_mode = stat.S_IMODE((socket_path.parent / "hol-guard-app-server.pid").stat().st_mode)
    assert started is True
    assert directory_mode == 0o700
    assert pid_mode == 0o600


def test_direct_app_server_recovers_when_pid_marker_is_stale(
    tmp_path: Path,
    monkeypatch,
) -> None:
    socket_path = tmp_path / "home" / ".codex" / "app-server-control" / "app-server-control.sock"
    socket_path.parent.mkdir(parents=True)
    (socket_path.parent / "hol-guard-app-server.pid").write_text("4321", encoding="utf-8")

    wait_calls = 0
    launches = 0

    def fake_wait(_path: Path) -> bool:
        nonlocal wait_calls
        wait_calls += 1
        return wait_calls > 2

    class FakeProcess:
        pid = 9876

    def fake_popen(*args, **kwargs):
        nonlocal launches
        launches += 1
        return FakeProcess()

    monkeypatch.setattr(codex_remote_control, "_wait_for_socket", fake_wait)
    monkeypatch.setattr(codex_remote_control.os, "kill", lambda _pid, _signal: None)
    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", fake_popen)

    started = codex_remote_control._start_direct_app_server(
        executable="codex",
        socket_path=socket_path,
        environment={},
    )

    assert started is True
    assert launches == 1
    assert (socket_path.parent / "hol-guard-app-server.pid").read_text(encoding="utf-8") == "9876"
