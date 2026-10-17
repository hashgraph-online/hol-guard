"""Stopping the native resident after a harness uninstall leaves none managed."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import uninstall_commands
from codex_plugin_scanner.guard.cli.render import _render_managed_install
from codex_plugin_scanner.guard.native_resident_update_lock import NativeResidentUpdateLockError
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    guard_home.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _stub_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, events: list[str]) -> None:
    @contextmanager
    def hold(_guard_home: Path, **_kwargs: object) -> Iterator[None]:
        events.append("acquire")
        yield
        events.append("release")

    def retire(_guard_home: Path) -> bool:
        events.append("retire")
        return True

    monkeypatch.setattr(uninstall_commands, "hold_native_resident_update_lock", hold)
    monkeypatch.setattr(uninstall_commands, "resident_stop_executable", lambda: tmp_path / "runtime")
    monkeypatch.setattr(uninstall_commands, "retire_native_resident_for_home", retire)
    monkeypatch.setattr(uninstall_commands, "_resident_state_absent", lambda _guard_home: False)


def test_removing_the_last_harness_stops_the_native_resident(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """`hol-guard uninstall codex` left the resident running until its idle timeout."""

    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("codex", False, None, {}, "2026-06-18T00:00:00Z")
    events: list[str] = []
    _stub_resident(monkeypatch, tmp_path, events)

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is True
    assert events == ["acquire", "retire", "release"]


def test_a_harness_still_managed_keeps_the_native_resident(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    store.set_managed_install("codex", False, None, {}, "2026-06-18T00:00:00Z")
    store.set_managed_install("claude-code", True, None, {}, "2026-06-18T00:00:00Z")
    events: list[str] = []
    _stub_resident(monkeypatch, tmp_path, events)

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is None
    assert events == []


def test_no_resident_state_leaves_nothing_to_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    events: list[str] = []
    _stub_resident(monkeypatch, tmp_path, events)
    monkeypatch.setattr(uninstall_commands, "_resident_state_absent", lambda _guard_home: True)

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is None
    assert events == []


def test_a_busy_update_barrier_reports_the_resident_as_still_running(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    events: list[str] = []
    _stub_resident(monkeypatch, tmp_path, events)

    def hold(_guard_home: Path, **_kwargs: object) -> None:
        raise NativeResidentUpdateLockError("update_native_resident_lock_busy")

    monkeypatch.setattr(uninstall_commands, "hold_native_resident_update_lock", hold)

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is False
    assert events == []


def test_a_harness_installed_while_waiting_for_the_barrier_keeps_the_resident(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    events: list[str] = []
    _stub_resident(monkeypatch, tmp_path, events)

    @contextmanager
    def hold(_guard_home: Path, **_kwargs: object) -> Iterator[None]:
        events.append("acquire")
        store.set_managed_install("claude-code", True, None, {}, "2026-06-18T00:00:00Z")
        yield
        events.append("release")

    monkeypatch.setattr(uninstall_commands, "hold_native_resident_update_lock", hold)

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is None
    assert events == ["acquire", "release"]


def test_unreadable_resident_state_keeps_the_uninstall_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    events: list[str] = []
    _stub_resident(monkeypatch, tmp_path, events)

    def unreadable(_guard_home: Path) -> bool:
        raise OSError("denied")

    monkeypatch.setattr(uninstall_commands, "_resident_state_absent", unreadable)

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is None
    assert events == []


def test_terminal_output_names_a_resident_that_did_not_stop() -> None:
    output = StringIO()
    console = Console(file=output, width=120, color_system=None)

    _render_managed_install(
        console,
        {"managed_installs": [{"harness": "codex", "active": False}], "native_resident_retired": False},
    )

    assert "Could not stop the Guard native runtime" in output.getvalue()
