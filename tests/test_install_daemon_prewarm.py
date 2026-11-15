"""An install warms Guard for the first hook of a harness with no session-start hook."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import native_daemon_manage
from codex_plugin_scanner.guard.cli import install_daemon_prewarm


def _record_prewarm(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Path, Path | None]]:
    calls: list[tuple[Path, Path | None]] = []

    def record(guard_home: Path, *, home_dir: Path | None = None) -> None:
        calls.append((guard_home, home_dir))

    monkeypatch.setattr(install_daemon_prewarm, "prewarm_after_install", record)
    return calls


@pytest.mark.usefixtures("native_prompt_runtime")
def test_a_successful_install_reserves_a_prewarm_for_its_guard_home(tmp_path, monkeypatch, capsys):
    calls = _record_prewarm(monkeypatch)
    home_dir = tmp_path / "home"

    assert main(["guard", "install", "codex", "--home", str(home_dir), "--json"]) == 0
    _ = json.loads(capsys.readouterr().out)

    assert len(calls) == 1
    guard_home, recorded_home = calls[0]
    assert recorded_home == home_dir
    assert guard_home == home_dir


@pytest.mark.usefixtures("native_prompt_runtime")
def test_a_dry_run_install_starts_nothing(tmp_path, monkeypatch, capsys):
    calls = _record_prewarm(monkeypatch)
    home_dir = tmp_path / "home"

    assert main(["guard", "install", "codex", "--home", str(home_dir), "--dry-run", "--json"]) == 0
    _ = json.loads(capsys.readouterr().out)

    assert calls == []


def test_a_test_guard_home_is_never_prewarmed(tmp_path, monkeypatch):
    scheduled: list[Path] = []
    monkeypatch.setattr(
        native_daemon_manage,
        "schedule_guard_daemon_ensure",
        lambda guard_home, *, home_dir=None: scheduled.append(guard_home) or "",
    )

    test_root = tmp_path / "pytest-of-synthetic" / "pytest-12"
    test_root.mkdir(parents=True)

    install_daemon_prewarm.prewarm_after_install(test_root / "guard-home", home_dir=test_root)

    assert scheduled == []


def test_a_real_guard_home_reserves_one_daemon_ensure(monkeypatch):
    scheduled: list[tuple[Path, Path | None]] = []
    monkeypatch.setattr(native_daemon_manage, "_guard_home_is_ephemeral", lambda _guard_home: False)
    monkeypatch.setattr(
        native_daemon_manage,
        "schedule_guard_daemon_ensure",
        lambda guard_home, *, home_dir=None: scheduled.append((guard_home, home_dir)) or "",
    )
    guard_home = Path("/synthetic/home/.hol-guard")

    install_daemon_prewarm.prewarm_after_install(guard_home, home_dir=Path("/synthetic/home"))

    assert scheduled == [(guard_home, Path("/synthetic/home"))]


def test_a_failed_reservation_never_fails_the_install(monkeypatch):
    def refuse(_guard_home: Path, *, home_dir: Path | None = None) -> str:
        del home_dir
        raise RuntimeError("daemon manager unavailable")

    monkeypatch.setattr(native_daemon_manage, "_guard_home_is_ephemeral", lambda _guard_home: False)
    monkeypatch.setattr(native_daemon_manage, "schedule_guard_daemon_ensure", refuse)

    install_daemon_prewarm.prewarm_after_install(Path("/synthetic/home/.hol-guard"))
