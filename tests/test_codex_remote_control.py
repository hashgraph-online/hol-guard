"""Tests for guarded Codex remote-control launches."""

from __future__ import annotations

import socket
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_context
from codex_plugin_scanner.guard.adapters import codex_remote_control


@pytest.fixture(autouse=True)
def _native_runtime_probed_before_fakes(_ambient_context_digest_home: None) -> None:
    """Probe the native runtime before a test replaces ``subprocess``.

    ``codex_remote_control.subprocess`` is the shared module, so a fake
    ``Popen`` also catches the runtime's one-time capability probe. That
    probe only runs when this file is the first in its worker to need the
    runtime, which depends on how tests are split across shards.
    """
    native_context._native_runtime_status_memo()  # pyright: ignore[reportPrivateUsage]


def test_guarded_codex_launch_candidates_are_side_effect_free(tmp_path, monkeypatch):
    def fail_subprocess(*_args, **_kwargs):
        pytest.fail("launch preview must not start remote-control setup")

    monkeypatch.setattr(codex_remote_control.subprocess, "run", fail_subprocess)
    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", fail_subprocess)

    candidates = codex_remote_control.guarded_codex_launch_command_candidates(
        executable="/usr/bin/codex",
        home_dir=tmp_path / "home",
        passthrough_args=["Fix it."],
    )

    socket_path = codex_remote_control.default_codex_control_socket(tmp_path / "home")
    assert candidates == (
        ["/usr/bin/codex", "--remote", f"unix://{socket_path}", "Fix it."],
        ["/usr/bin/codex", "Fix it."],
    )


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
    assert starts[0]["executable_prefix"] == ["/usr/local/bin/codex"]
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
    monkeypatch,
) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-codex-", dir="/tmp") as directory:
        socket_path = Path(directory) / "app-server.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.close()
        monkeypatch.setattr(codex_remote_control, "_REMOTE_CONTROL_READY_TIMEOUT_SECONDS", 0.01)

        assert codex_remote_control._wait_for_socket(socket_path) is False


def test_wait_for_socket_accepts_trusted_live_socket() -> None:
    with tempfile.TemporaryDirectory(prefix="guard-codex-", dir="/tmp") as directory:
        socket_path = Path(directory) / "app-server.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)
        try:
            assert codex_remote_control._wait_for_socket(socket_path) is True
        finally:
            listener.close()


def _answer_reclaim(monkeypatch, answer: dict[str, object]) -> list[tuple[str, dict[str, object], float | None]]:
    requests: list[tuple[str, dict[str, object], float | None]] = []

    def fake_ask(op: str, fields: dict[str, object], budget: float | None = None) -> dict[str, object]:
        requests.append((op, dict(fields), budget))
        return answer

    monkeypatch.setattr(codex_remote_control, "_ask", fake_ask)
    return requests


def test_direct_app_server_uses_private_control_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    socket_path = tmp_path / "home" / ".codex" / "app-server-control" / "app-server-control.sock"

    class FakeProcess:
        pid = 4321

    wait_calls = 0
    launch_commands: list[list[str]] = []

    def fake_wait(path: Path) -> bool:
        nonlocal wait_calls
        wait_calls += 1
        return wait_calls > 1 and path.parent.exists()

    def fake_popen(command, **_kwargs):
        launch_commands.append(list(command))
        return FakeProcess()

    monkeypatch.setattr(codex_remote_control, "_wait_for_socket", fake_wait)
    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", fake_popen)
    requests = _answer_reclaim(monkeypatch, {"state": "free"})

    started = codex_remote_control._start_direct_app_server(
        executable_prefix=("/usr/bin/env", "codex"),
        socket_path=socket_path,
        environment={},
    )

    directory_mode = stat.S_IMODE(socket_path.parent.stat().st_mode)
    pid_path = socket_path.parent / "hol-guard-app-server.pid"
    assert started is True
    assert requests == [("reclaim", {"socket": str(socket_path), "seconds": 3.0}, 7.0)]
    assert launch_commands == [["/usr/bin/env", "codex", "app-server", "--listen", f"unix://{socket_path}"]]
    assert directory_mode == 0o700
    assert stat.S_IMODE(pid_path.stat().st_mode) == 0o600
    assert pid_path.read_text(encoding="utf-8") == "4321"


def test_direct_app_server_replaces_a_stale_pid_marker_the_resident_frees(
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
        return wait_calls > 1

    class FakeProcess:
        pid = 9876

    def fake_popen(*args, **kwargs):
        nonlocal launches
        launches += 1
        return FakeProcess()

    monkeypatch.setattr(codex_remote_control, "_wait_for_socket", fake_wait)
    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", fake_popen)
    _answer_reclaim(monkeypatch, {"state": "free"})

    started = codex_remote_control._start_direct_app_server(
        executable_prefix=("codex",),
        socket_path=socket_path,
        environment={},
    )

    assert started is True
    assert launches == 1
    assert (socket_path.parent / "hol-guard-app-server.pid").read_text(encoding="utf-8") == "9876"


@pytest.mark.parametrize("answer", [{}, {"state": "busy"}, {"state": None}, {"state": "other"}])
def test_direct_app_server_keeps_tracking_unless_the_resident_frees_it(
    tmp_path: Path,
    monkeypatch,
    answer: dict[str, object],
) -> None:
    socket_path = tmp_path / "home" / ".codex" / "app-server-control" / "app-server-control.sock"
    socket_path.parent.mkdir(parents=True)
    pid_path = socket_path.parent / "hol-guard-app-server.pid"
    pid_path.write_text("4321", encoding="utf-8")

    def fail_popen(*_args, **_kwargs):
        raise AssertionError("a tracked server the resident did not free must not be replaced")

    monkeypatch.setattr(codex_remote_control, "_wait_for_socket", lambda _path: False)
    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", fail_popen)
    _answer_reclaim(monkeypatch, answer)

    started = codex_remote_control._start_direct_app_server(
        executable_prefix=("codex",),
        socket_path=socket_path,
        environment={},
    )

    assert started is False
    assert pid_path.read_text(encoding="utf-8") == "4321"


def test_direct_app_server_reuses_a_tracked_server_that_listens(
    tmp_path: Path,
    monkeypatch,
) -> None:
    socket_path = tmp_path / "home" / ".codex" / "app-server-control" / "app-server-control.sock"

    def fail_popen(*_args, **_kwargs):
        raise AssertionError("a listening tracked server must be reused")

    monkeypatch.setattr(codex_remote_control, "_wait_for_socket", lambda _path: False)
    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", fail_popen)
    _answer_reclaim(monkeypatch, {"state": "ready"})

    assert (
        codex_remote_control._start_direct_app_server(
            executable_prefix=("codex",),
            socket_path=socket_path,
            environment={},
        )
        is True
    )


def test_launch_preparation_selects_only_among_previewed_argv(tmp_path: Path, monkeypatch) -> None:
    answers = iter([{}, {"tails": [["--remote", "unix:///x.sock", "fix"], ["fix"]]}])
    monkeypatch.setattr(codex_remote_control, "_ask", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr(codex_remote_control, "_start_direct_app_server", lambda **_kwargs: True)
    home = tmp_path / "home"

    previewed = codex_remote_control.guarded_codex_launch_command_candidates(
        executable="codex", home_dir=home, passthrough_args=["fix"]
    )
    prepared = codex_remote_control.guarded_codex_launch_command(
        executable="codex", home_dir=home, passthrough_args=["fix"]
    )

    assert previewed == (["codex", "fix"],)
    assert prepared == ["codex", "fix"]
