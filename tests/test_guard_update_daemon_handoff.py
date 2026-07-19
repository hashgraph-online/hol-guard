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

    monkeypatch.setattr(manager, "retire_all_guard_daemons_for_home", retire)
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
    monkeypatch.setattr(Path, "home", classmethod(process_home))
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"guard_home": str(guard_home)})),
    )

    refresh_script = cast(str, update_commands.__dict__["_DAEMON_REFRESH_SCRIPT"])
    exec(refresh_script, {})

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

    def legacy_parameters(received_guard_home: Path, *, preferred_port: int | None = None) -> str:
        observed.update(guard_home=received_guard_home, preferred_port=preferred_port)
        return "http://127.0.0.1:8124"

    monkeypatch.setattr(manager, "retire_all_guard_daemons_for_home", retire)
    monkeypatch.setattr(manager, "clear_guard_daemon_state", no_op)
    monkeypatch.setattr(manager, "repair_approval_center_locator", no_op)
    monkeypatch.setattr(manager, "ensure_guard_daemon_after_update", legacy_parameters)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"guard_home": str(guard_home), "home_dir": str(home_dir)})),
    )

    refresh_script = cast(str, update_commands.__dict__["_DAEMON_REFRESH_SCRIPT"])
    exec(refresh_script, {})

    assert observed == {"guard_home": guard_home.resolve(), "preferred_port": 8124}
    assert json.loads(capsys.readouterr().out) == {
        "status": "restarted",
        "retired": [18],
        "daemon_url": "http://127.0.0.1:8124",
    }
