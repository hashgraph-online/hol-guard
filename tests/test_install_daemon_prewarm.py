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

    def record(guard_home: Path, *, home_dir: Path | None = None) -> bool:
        calls.append((guard_home, home_dir))
        return False

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


def _daemon_manager(monkeypatch: pytest.MonkeyPatch, *, ensure=None) -> dict[str, list]:
    calls: dict[str, list] = {"ensure": [], "schedule": []}

    def record_ensure(guard_home: Path, *, home_dir: Path | None = None, start_timeout: float | None = None) -> str:
        calls["ensure"].append((guard_home, home_dir, start_timeout))
        if ensure is not None:
            ensure()
        return "http://127.0.0.1:1"

    def record_schedule(guard_home: Path, *, home_dir: Path | None = None) -> str:
        calls["schedule"].append((guard_home, home_dir))
        return ""

    monkeypatch.setattr(native_daemon_manage, "ensure_guard_daemon", record_ensure)
    monkeypatch.setattr(native_daemon_manage, "schedule_guard_daemon_ensure", record_schedule)
    return calls


def test_a_test_guard_home_is_never_prewarmed(tmp_path, monkeypatch):
    calls = _daemon_manager(monkeypatch)
    test_root = tmp_path / "pytest-of-synthetic" / "pytest-12"
    test_root.mkdir(parents=True)

    assert install_daemon_prewarm.prewarm_after_install(test_root / "guard-home", home_dir=test_root) is False

    assert calls == {"ensure": [], "schedule": []}


def test_an_install_waits_for_the_daemon_to_report_ready(monkeypatch):
    calls = _daemon_manager(monkeypatch)
    monkeypatch.setattr(native_daemon_manage, "_guard_home_is_ephemeral", lambda _guard_home: False)
    guard_home = Path("/synthetic/home/.hol-guard")

    ready = install_daemon_prewarm.prewarm_after_install(guard_home, home_dir=Path("/synthetic/home"))

    assert ready is True
    assert calls["ensure"] == [(guard_home, Path("/synthetic/home"), install_daemon_prewarm.INSTALL_READY_WAIT_SECONDS)]
    assert calls["schedule"] == []


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("Guard daemon operation deadline exceeded."),
        native_daemon_manage.GuardDaemonStillStartingError("still starting"),
        RuntimeError("Guard daemon start requires the native runtime."),
    ],
)
def test_a_start_that_misses_the_wait_keeps_starting_in_the_background(monkeypatch, error):
    def refuse() -> None:
        raise error

    calls = _daemon_manager(monkeypatch, ensure=refuse)
    monkeypatch.setattr(native_daemon_manage, "_guard_home_is_ephemeral", lambda _guard_home: False)
    guard_home = Path("/synthetic/home/.hol-guard")

    ready = install_daemon_prewarm.prewarm_after_install(guard_home, home_dir=Path("/synthetic/home"))

    assert ready is False
    assert calls["schedule"] == [(guard_home, Path("/synthetic/home"))]


def test_a_failed_start_and_reservation_never_fail_the_install(monkeypatch):
    def refuse(*_args: object, **_kwargs: object) -> str:
        raise RuntimeError("daemon manager unavailable")

    monkeypatch.setattr(native_daemon_manage, "_guard_home_is_ephemeral", lambda _guard_home: False)
    monkeypatch.setattr(native_daemon_manage, "ensure_guard_daemon", refuse)
    monkeypatch.setattr(native_daemon_manage, "schedule_guard_daemon_ensure", refuse)

    assert install_daemon_prewarm.prewarm_after_install(Path("/synthetic/home/.hol-guard")) is False
