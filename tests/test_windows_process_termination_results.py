"""The daemon state records the owner of the process it adopted."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


def test_state_writer_uses_selected_pid_owner_for_adopted_daemon(monkeypatch, tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    adopted_pid = 73_002
    observed_pids: list[int] = []

    def owner_marker(pid: int) -> str:
        observed_pids.append(pid)
        return "sid:S-1-5-21-adopted"

    monkeypatch.setattr(daemon_manager_module, "process_start_token", lambda _pid: "windows:123")
    monkeypatch.setattr(daemon_manager_module, "process_owner_marker", owner_marker)

    daemon_manager_module.write_guard_daemon_state(
        guard_home,
        4781,
        "auth-token",
        pid=adopted_pid,
    )

    state = daemon_manager_module.load_authenticated_daemon_state(guard_home)
    assert observed_pids == [adopted_pid]
    assert state is not None
    assert state["pid"] == adopted_pid
    assert state["user"] == "sid:S-1-5-21-adopted"
