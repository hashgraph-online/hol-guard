"""Tests for guarded Codex remote-control launches."""

from __future__ import annotations

import os
import socket
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_remote_client as codex_remote_control
from codex_plugin_scanner.guard import native_context


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

    socket_path = _socket(tmp_path / "home")
    assert candidates == (
        ["/usr/bin/codex", "--remote", f"unix://{socket_path}", "Fix it."],
        ["/usr/bin/codex", "Fix it."],
    )


def _script(monkeypatch, answers: list[dict[str, object] | None]) -> list[dict[str, object]]:
    """Answer each ``prepare`` step from ``answers``; ``None`` asks the resident."""

    requests: list[dict[str, object]] = []
    ask = codex_remote_control._ask
    pending = iter(answers)

    def scripted(op: str, fields: dict[str, object], budget: float | None = None) -> dict[str, object]:
        if op != "prepare":
            return ask(op, fields, budget)
        requests.append(dict(fields))
        answer = next(pending)
        return ask(op, fields, budget) if answer is None else answer

    monkeypatch.setattr(codex_remote_control, "_ask", scripted)
    return requests


def _socket(home_dir: Path) -> Path:
    return home_dir / ".codex" / "app-server-control" / "app-server-control.sock"


def test_guarded_codex_launch_starts_remote_control_and_connects_tui(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []
    home_dir = tmp_path / "home"

    def fake_run(command, **kwargs):
        calls.append((list(command), dict(kwargs["env"])))
        return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

    monkeypatch.setattr(codex_remote_control.subprocess, "run", fake_run)
    requests = _script(monkeypatch, [None, {"launch": "remote"}])

    command = codex_remote_control.guarded_codex_launch_command(
        executable="/usr/local/bin/codex",
        home_dir=home_dir,
        passthrough_args=["Fix the failing test."],
        environ={"PATH": "/usr/bin"},
    )

    assert calls[0][0] == ["/usr/local/bin/codex", "remote-control", "start", "--json"]
    assert calls[0][1] == {"PATH": "/usr/bin", "HOME": str(home_dir), "CODEX_HOME": str(home_dir / ".codex")}
    assert (home_dir / ".codex").is_dir()
    assert requests[1]["stage"] == "started" and requests[1]["exit"] == 0
    assert command == [
        "/usr/local/bin/codex",
        "--remote",
        f"unix://{_socket(home_dir)}",
        "Fix the failing test.",
    ]


@pytest.mark.parametrize(
    "answer", [{"launch": "plain"}, {}, {"stage": "spawned", "spawn": []}, {"stage": "started", "run": ["x"]}]
)
def test_guarded_codex_launch_falls_back_when_remote_control_is_unavailable(
    tmp_path: Path,
    monkeypatch,
    answer: dict[str, object],
) -> None:
    monkeypatch.setattr(
        codex_remote_control.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr="unsupported"),
    )

    def fail_popen(*_args, **_kwargs):
        raise AssertionError("an app-server the resident did not name must not start")

    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", fail_popen)
    requests = _script(monkeypatch, [None, answer])

    command = codex_remote_control.guarded_codex_launch_command(
        executable="codex",
        home_dir=tmp_path / "home",
        passthrough_args=["Fix the failing test."],
        environ={},
    )

    assert requests[1]["exit"] == 1
    assert command == ["codex", "Fix the failing test."]


@pytest.mark.skipif(os.name == "nt", reason="Unix control socket")
def test_guarded_codex_launch_starts_a_private_app_server_when_managed_daemon_is_unavailable(
    monkeypatch,
) -> None:
    launches: list[list[str]] = []

    class FakeProcess:
        pid = 9876

    def fake_popen(command, **kwargs):
        assert kwargs["start_new_session"] is True
        launches.append(list(command))
        return FakeProcess()

    monkeypatch.setattr(
        codex_remote_control.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr="unsupported"),
    )
    monkeypatch.setattr(codex_remote_control.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(codex_remote_control, "_REMOTE_CONTROL_READY_TIMEOUT_SECONDS", 0.05)
    with tempfile.TemporaryDirectory(prefix="guard-codex-", dir="/tmp") as directory:
        home_dir = Path(directory)
        socket_path = _socket(home_dir)
        socket_path.parent.mkdir(parents=True)
        # A stale marker naming another process is replaced.
        (socket_path.parent / "hol-guard-app-server.pid").write_text("1", encoding="utf-8")

        command = codex_remote_control.guarded_codex_launch_command(
            executable="/usr/local/bin/codex", home_dir=home_dir, passthrough_args=[], environ={}
        )

        pid_path = socket_path.parent / "hol-guard-app-server.pid"
        assert launches == [["/usr/local/bin/codex", "app-server", "--listen", f"unix://{socket_path}"]]
        assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(pid_path.stat().st_mode) == 0o600
        assert pid_path.read_text(encoding="utf-8") == "9876"
        # Nothing listens on the socket, so the launch stays ordinary.
        assert command == ["/usr/local/bin/codex"]


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


def _started(socket_path: Path) -> dict[str, object]:
    fields = {"home_dir": str(socket_path.parent), "socket": str(socket_path), "seconds": 0.2}
    return codex_remote_control._ask("prepare", {**fields, "stage": "started", "exit": 0}, 5.0)


@pytest.mark.skipif(os.name == "nt", reason="Unix control socket")
def test_a_trusted_stale_socket_is_not_ready() -> None:
    with tempfile.TemporaryDirectory(prefix="guard-codex-", dir="/tmp") as directory:
        socket_path = Path(directory) / "app-server.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.close()

        assert _started(socket_path).get("launch") != "remote"


@pytest.mark.skipif(os.name == "nt", reason="Unix control socket")
def test_a_trusted_live_socket_is_ready() -> None:
    with tempfile.TemporaryDirectory(prefix="guard-codex-", dir="/tmp") as directory:
        socket_path = Path(directory) / "app-server.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)
        try:
            assert _started(socket_path) == {"launch": "remote"}
        finally:
            listener.close()


def test_launch_preparation_selects_only_among_previewed_argv(tmp_path: Path, monkeypatch) -> None:
    remote = {
        "prepare": True,
        "prefix": ["codex"],
        "socket": "/x.sock",
        "plain": ["codex", "fix"],
        "remote": ["codex", "--remote", "unix:///x.sock", "fix"],
        "candidates": [["codex", "--remote", "unix:///x.sock", "fix"], ["codex", "fix"]],
    }
    answers = iter([{}, remote])
    monkeypatch.setattr(codex_remote_control, "_ask", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr(codex_remote_control, "_prepare_remote", lambda *_args, **_kwargs: True)
    home = tmp_path / "home"

    previewed = codex_remote_control.guarded_codex_launch_command_candidates(
        executable="codex", home_dir=home, passthrough_args=["fix"]
    )
    prepared = codex_remote_control.guarded_codex_launch_command(
        executable="codex", home_dir=home, passthrough_args=["fix"]
    )

    assert previewed == (["codex", "fix"],)
    assert prepared == ["codex", "fix"]


def test_a_refused_launch_plan_raises_the_resident_refusal(tmp_path: Path, monkeypatch) -> None:
    refusal = "Codex launch preparation requires a canonical executable prefix."
    monkeypatch.setattr(codex_remote_control, "_ask", lambda *_args, **_kwargs: {"refusal": refusal})

    with pytest.raises(ValueError, match="canonical executable prefix"):
        codex_remote_control.guarded_codex_launch_command(executable="", home_dir=tmp_path, passthrough_args=[])
