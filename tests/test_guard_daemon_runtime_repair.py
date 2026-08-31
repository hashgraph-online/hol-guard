from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import runtime_repair


def test_repair_restarts_authenticated_older_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    retired: list[Path] = []
    events: list[str] = []

    @contextmanager
    def lifecycle_lock(_home: Path):
        events.append("lock-enter")
        yield
        events.append("lock-exit")

    monkeypatch.setattr(
        runtime_repair,
        "load_authenticated_daemon_state",
        lambda _home: {"package_version": "3.0.18"},
    )
    monkeypatch.setattr(runtime_repair, "_guard_daemon_start_lock", lifecycle_lock)
    monkeypatch.setattr(runtime_repair, "_verified_live_runtime", lambda _home, _state: None)
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(
        runtime_repair,
        "retire_all_guard_daemons_for_home",
        lambda home: retired.append(home) or [321],
    )
    monkeypatch.setattr(runtime_repair, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(runtime_repair, "clear_guard_daemon_state", lambda _home: None)
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.34")
    monkeypatch.setattr(
        runtime_repair,
        "ensure_guard_daemon_after_update",
        lambda _home, *, home_dir: events.append("ensure") or "http://127.0.0.1:5474",
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home, home_dir=home_dir)

    assert result["runtime_status"] == "restarted"
    assert result["daemon_version"] == "3.0.18"
    assert result["cli_version"] == "3.0.34"
    assert result["retired"] == [321]
    assert retired == [guard_home]
    assert events == ["lock-enter", "lock-exit", "ensure"]


def test_repair_retains_authenticated_newer_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(
        runtime_repair,
        "load_authenticated_daemon_state",
        lambda _home: {"package_version": "3.0.35"},
    )
    monkeypatch.setattr(
        runtime_repair,
        "_verified_live_runtime",
        lambda _home, _state: (runtime_repair.Version("3.0.35"), "3.0.35"),
    )
    monkeypatch.setattr(
        runtime_repair,
        "repair_approval_center_locator",
        lambda _home: {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(runtime_repair, "__version__", "3.0.34")
    monkeypatch.setattr(
        runtime_repair,
        "retire_all_guard_daemons_for_home",
        lambda _home: (_ for _ in ()).throw(AssertionError("newer runtime must remain active")),
    )

    result = runtime_repair.repair_guard_daemon_runtime(guard_home)

    assert result["runtime_status"] == "retained_newer_runtime"
    assert result["daemon_version"] == "3.0.35"


def test_repair_validates_home_before_retiring_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_home = tmp_path / "missing-home"
    monkeypatch.setattr(
        runtime_repair,
        "retire_all_guard_daemons_for_home",
        lambda _home: (_ for _ in ()).throw(AssertionError("invalid home must fail before retirement")),
    )

    with pytest.raises(FileNotFoundError):
        runtime_repair.repair_guard_daemon_runtime(tmp_path / "guard-home", home_dir=missing_home)
