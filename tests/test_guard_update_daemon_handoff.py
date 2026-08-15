"""Cross-version daemon refresh handoff contracts."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.daemon import manager


def test_refresh_script_adapts_to_new_manager_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    _ = guard_home.mkdir(parents=True)
    _ = (guard_home / "daemon-state.json").write_text('{"port":8123}', encoding="utf-8")
    observed: dict[str, object] = {}

    def retire(_guard_home: Path) -> list[int]:
        return [17]

    def no_op(_guard_home: Path) -> None:
        return None

    def retirement_complete(_guard_home: Path) -> bool:
        return True

    monkeypatch.setattr(manager, "retire_all_guard_daemons_for_home", retire)
    monkeypatch.setattr(manager, "guard_daemon_retirement_is_complete", retirement_complete)
    monkeypatch.setattr(manager, "clear_guard_daemon_state", no_op)
    monkeypatch.setattr(manager, "repair_approval_center_locator", no_op)

    def require_new_parameters(
        received_guard_home: Path,
        *,
        home_dir: Path,
        preferred_port: int | None = None,
        allow_windows_job_breakaway: bool = False,
    ) -> str:
        observed.update(
            guard_home=received_guard_home,
            home_dir=home_dir,
            preferred_port=preferred_port,
            allow_windows_job_breakaway=allow_windows_job_breakaway,
        )
        return "http://127.0.0.1:8123"

    def process_home(_path_type: type[Path]) -> Path:
        return home_dir

    monkeypatch.setattr(manager, "ensure_guard_daemon_after_update", require_new_parameters)
    monkeypatch.setattr(manager, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:8123")
    monkeypatch.setattr(Path, "home", classmethod(process_home))
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"guard_home": str(guard_home)})),
    )

    refresh_script = cast(str, update_commands.__dict__["_DAEMON_REFRESH_SCRIPT"])
    with pytest.raises(SystemExit) as exit_info:
        exec(refresh_script, {})

    assert exit_info.value.code == 0

    assert observed == {
        "guard_home": guard_home.resolve(),
        "home_dir": home_dir.resolve(),
        "preferred_port": 8123,
        "allow_windows_job_breakaway": True,
    }
    assert json.loads(capsys.readouterr().out) == {
        "status": "restarted",
        "retired": [17],
        "daemon_url": "http://127.0.0.1:8123",
        "runtime_verified": True,
        "attempts": 1,
    }


def test_refresh_script_converges_when_supervisor_respawns_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    _ = guard_home.mkdir(parents=True)
    _ = (guard_home / "daemon-state.json").write_text('{"port":8125}', encoding="utf-8")
    retirement_checks = 0
    retirement_calls = 0

    def retire(_guard_home: Path) -> list[int]:
        nonlocal retirement_calls
        retirement_calls += 1
        return [20 + retirement_calls]

    def retirement_complete(_guard_home: Path) -> bool:
        nonlocal retirement_checks
        retirement_checks += 1
        return retirement_checks >= 3

    monkeypatch.setattr(manager, "retire_all_guard_daemons_for_home", retire)
    monkeypatch.setattr(manager, "guard_daemon_retirement_is_complete", retirement_complete)
    monkeypatch.setattr(manager, "clear_guard_daemon_state", lambda _guard_home: None)
    monkeypatch.setattr(manager, "repair_approval_center_locator", lambda _guard_home: None)
    monkeypatch.setattr(
        manager,
        "ensure_guard_daemon_after_update",
        lambda _guard_home, **_kwargs: "http://127.0.0.1:8125",
    )
    monkeypatch.setattr(manager, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:8125")
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"guard_home": str(guard_home), "home_dir": str(home_dir)})),
    )

    refresh_script = cast(str, update_commands.__dict__["_DAEMON_REFRESH_SCRIPT"])
    with pytest.raises(SystemExit) as exit_info:
        exec(refresh_script, {})

    assert exit_info.value.code == 0

    assert retirement_calls == 3
    assert json.loads(capsys.readouterr().out) == {
        "status": "restarted",
        "retired": [21, 22, 23],
        "daemon_url": "http://127.0.0.1:8125",
        "runtime_verified": True,
        "attempts": 1,
    }


def test_refresh_script_preserves_legacy_manager_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    _ = guard_home.mkdir(parents=True)
    _ = (guard_home / "daemon-state.json").write_text('{"port":8124}', encoding="utf-8")
    observed: dict[str, object] = {}

    def retire(_guard_home: Path) -> list[int]:
        return [18]

    def no_op(_guard_home: Path) -> None:
        return None

    def retirement_complete(_guard_home: Path) -> bool:
        return True

    def legacy_parameters(received_guard_home: Path, *, preferred_port: int | None = None) -> str:
        observed.update(guard_home=received_guard_home, preferred_port=preferred_port)
        return "http://127.0.0.1:8124"

    monkeypatch.setattr(manager, "retire_all_guard_daemons_for_home", retire)
    monkeypatch.setattr(manager, "guard_daemon_retirement_is_complete", retirement_complete)
    monkeypatch.setattr(manager, "clear_guard_daemon_state", no_op)
    monkeypatch.setattr(manager, "repair_approval_center_locator", no_op)
    monkeypatch.setattr(manager, "ensure_guard_daemon_after_update", legacy_parameters)
    monkeypatch.setattr(manager, "load_guard_daemon_url", lambda _home: "http://127.0.0.1:8124")
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"guard_home": str(guard_home), "home_dir": str(home_dir)})),
    )

    refresh_script = cast(str, update_commands.__dict__["_DAEMON_REFRESH_SCRIPT"])
    with pytest.raises(SystemExit) as exit_info:
        exec(refresh_script, {})

    assert exit_info.value.code == 0

    assert observed == {"guard_home": guard_home.resolve(), "preferred_port": 8124}
    assert json.loads(capsys.readouterr().out) == {
        "status": "restarted",
        "retired": [18],
        "daemon_url": "http://127.0.0.1:8124",
        "runtime_verified": True,
        "attempts": 1,
    }


def test_refresh_script_retries_when_runtime_changes_during_stability_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    guard_home.mkdir(parents=True)
    (guard_home / "daemon-state.json").write_text('{"port":8126}', encoding="utf-8")
    verification = iter(
        [
            "http://127.0.0.1:8126",
            None,
            "http://127.0.0.1:8126",
            "http://127.0.0.1:8126",
            "http://127.0.0.1:8126",
        ]
    )
    retire_calls = 0

    def retire(_guard_home: Path) -> list[int]:
        nonlocal retire_calls
        retire_calls += 1
        return [30 + retire_calls]

    monkeypatch.setattr(manager, "retire_all_guard_daemons_for_home", retire)
    monkeypatch.setattr(manager, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(manager, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(manager, "repair_approval_center_locator", lambda _home: None)
    monkeypatch.setattr(
        manager,
        "ensure_guard_daemon_after_update",
        lambda _guard_home, **_kwargs: "http://127.0.0.1:8126",
    )
    monkeypatch.setattr(manager, "load_guard_daemon_url", lambda _home: next(verification))
    monkeypatch.setattr(update_commands.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"guard_home": str(guard_home), "home_dir": str(home_dir)})),
    )

    with pytest.raises(SystemExit) as exit_info:
        exec(cast(str, update_commands.__dict__["_DAEMON_REFRESH_SCRIPT"]), {})

    assert exit_info.value.code == 0
    assert retire_calls == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "restarted",
        "retired": [31, 32],
        "daemon_url": "http://127.0.0.1:8126",
        "runtime_verified": True,
        "attempts": 2,
    }
