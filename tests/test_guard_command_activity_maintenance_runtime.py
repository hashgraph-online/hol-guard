"""Daemon scheduling and config ownership for command activity maintenance."""

# pyright: reportAny=false, reportMissingImports=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon import server as daemon_server


class _SequencedEvent:
    calls: int

    def __init__(self) -> None:
        self.calls = 0

    def wait(self, timeout: float) -> bool:
        assert timeout == 3_600
        self.calls += 1
        return self.calls > 2

    def is_set(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class _LoadedConfig:
    evidence_retain_days: int


class _FakeStore:
    guard_home: Path = Path("/global-home")

    def maintain_command_activity(self, **_kwargs: object) -> None:
        return None

    def record_command_activity_persistence_failure(self, **_kwargs: object) -> None:
        return None


@dataclass(frozen=True, slots=True)
class _FakeServer:
    store: _FakeStore


class _ThreadStillStopping:
    joined: bool = False

    def join(self, timeout: float | None = None) -> None:
        assert timeout == 5
        self.joined = True

    def is_alive(self) -> bool:
        return True


def test_long_lived_daemon_rechecks_daily_and_uses_global_retention(monkeypatch: pytest.MonkeyPatch) -> None:
    service = object.__new__(daemon_server.GuardDaemonServer)
    service._shutdown_started = cast(threading.Event, cast(object, _SequencedEvent()))
    maintenance_calls: list[int] = []
    service._maintain_command_activity_best_effort = lambda: maintenance_calls.append(1)
    service._maintain_storage_best_effort = lambda: True
    service._command_activity_maintenance_loop()
    assert len(maintenance_calls) == 3

    loaded: list[tuple[Path, Path | None]] = []
    object.__setattr__(service, "_server", _FakeServer(_FakeStore()))
    service._aibom_workspace_dir = Path("/workspace")

    def load(home: Path, workspace: Path | None = None) -> _LoadedConfig:
        loaded.append((home, workspace))
        return _LoadedConfig(evidence_retain_days=90)

    monkeypatch.setattr(daemon_server, "load_guard_config", load)
    daemon_server.GuardDaemonServer._maintain_command_activity_best_effort(service)
    assert loaded == [(Path("/global-home"), None)]


def test_daemon_shutdown_skips_initial_command_activity_maintenance() -> None:
    service = object.__new__(daemon_server.GuardDaemonServer)
    service._shutdown_started = threading.Event()
    service._shutdown_started.set()
    maintenance_calls: list[int] = []
    service._maintain_command_activity_best_effort = lambda: maintenance_calls.append(1)

    service._command_activity_maintenance_loop()

    assert maintenance_calls == []


def test_daemon_restart_rejects_a_still_stopping_maintenance_worker() -> None:
    service = object.__new__(daemon_server.GuardDaemonServer)
    worker = _ThreadStillStopping()
    service._command_activity_maintenance_thread = cast(threading.Thread, cast(object, worker))
    service._join_command_activity_maintenance()
    assert worker.joined is True
    assert service._command_activity_maintenance_thread is not None
    with pytest.raises(RuntimeError, match="still stopping"):
        service._require_command_activity_maintenance_stopped()


def test_global_evidence_retention_setting_is_bounded(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    config_path = guard_home / "config.toml"
    config_path.write_text("evidence_retain_days = 45\n", encoding="utf-8")
    assert load_guard_config(guard_home).evidence_retain_days == 45
    config_path.write_text("evidence_retain_days = 0\n", encoding="utf-8")
    assert load_guard_config(guard_home).evidence_retain_days == 90


def test_retention_row_limits_are_opt_in(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    config_path = guard_home / "config.toml"
    config_path.write_text("", encoding="utf-8")
    config = load_guard_config(guard_home)
    assert config.receipt_detail_limit is None
    assert config.guard_event_limit is None
    config_path.write_text("receipt_detail_limit = 50000\nguard_event_limit = 25000\n", encoding="utf-8")
    config = load_guard_config(guard_home)
    assert config.receipt_detail_limit == 50000
    assert config.guard_event_limit == 25000


def test_retention_row_limits_reject_invalid_values(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    config_path = guard_home / "config.toml"
    for invalid in ("0", "-5", "1000001", "\"lots\"", "true"):
        config_path.write_text(f"receipt_detail_limit = {invalid}\n", encoding="utf-8")
        assert load_guard_config(guard_home).receipt_detail_limit is None, invalid
        config_path.write_text(f"guard_event_limit = {invalid}\n", encoding="utf-8")
        assert load_guard_config(guard_home).guard_event_limit is None, invalid
