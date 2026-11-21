"""Stopping the native resident after a harness uninstall leaves none managed."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from codex_plugin_scanner.guard.cli import uninstall_commands
from codex_plugin_scanner.guard.cli.render import _render_managed_install
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_resident_update_lock import (
    RESIDENT_UPDATE_LOCK_NAME,
    NativeResidentUpdateLockError,
    _is_lock_contention,
    _unlock,
    open_private_lock_file,
)
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
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

    def retire(
        _guard_home: Path,
        *,
        hold_install_lock: bool = False,
        attempt_barrier: Callable[[], AbstractContextManager[object]] | None = None,
    ) -> bool:
        with attempt_barrier() if attempt_barrier is not None else nullcontext():
            events.append("retire under install lock" if hold_install_lock else "retire")
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
    assert events == ["acquire", "retire under install lock", "release"]


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


def test_the_store_is_never_read_under_the_barrier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A store read under the barrier was refused, so the resident was never stopped.

    The store is read through the resident, which refuses requests while this
    process holds the exclusive side; the refusal read as "a harness is still
    managed" and the stop was silently skipped. The Rust stop's installation
    lock covers an install that starts while the barrier is waited for.
    """

    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    events: list[str] = []
    _stub_resident(monkeypatch, tmp_path, events)
    held = False

    @contextmanager
    def hold(_guard_home: Path, **_kwargs: object) -> Iterator[None]:
        nonlocal held
        events.append("acquire")
        held = True
        yield
        held = False
        events.append("release")

    def installs(_store: GuardStore) -> tuple[list[dict[str, object]], str | None]:
        if held:
            raise NativeRunnerAuthorityError("native_resident_update_in_progress")
        return [], None

    monkeypatch.setattr(uninstall_commands, "hold_native_resident_update_lock", hold)
    monkeypatch.setattr(uninstall_commands, "_active_managed_installs", installs)

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is True
    assert events == ["acquire", "retire under install lock", "release"]


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


def _resident_request(guard_home: Path) -> None:
    """Take and drop the barrier's shared side, as every resident client request does."""

    descriptor = open_private_lock_file(guard_home, RESIDENT_UPDATE_LOCK_NAME)
    try:
        try:
            if os.name == "nt":
                from codex_plugin_scanner.guard.native_command_control_windows_lock import try_lock_authority_file

                try_lock_authority_file(descriptor, shared=True)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as error:
            if _is_lock_contention(error):
                raise NativeRunnerAuthorityError("native_resident_update_in_progress") from error
            raise
        _unlock(descriptor)
    finally:
        os.close(descriptor)


def test_removing_the_last_harness_never_asks_the_resident_for_a_lease_under_the_barrier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """`hol-guard uninstall zcode` as the last harness exited 2 with native_resident_update_in_progress.

    Resident requests take the update barrier's shared side, so any request made
    while this process held the exclusive side contended with itself. The install
    transaction's lease is now held inside the native runtime, so retiring the
    resident under the installation lock makes no resident request of its own.
    """

    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    events: list[str] = []

    def retire(_guard_home: Path, *, hold_install_lock: bool = False, **_kwargs: object) -> bool:
        events.append("retire under install lock" if hold_install_lock else "retire")
        return True

    monkeypatch.setattr(uninstall_commands, "_active_managed_installs", lambda _store: ([], None))
    monkeypatch.setattr(uninstall_commands, "resident_stop_executable", lambda: tmp_path / "runtime")
    monkeypatch.setattr(uninstall_commands, "retire_native_resident_for_home", retire)
    monkeypatch.setattr(uninstall_commands, "_resident_state_absent", lambda _guard_home: False)

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is True
    assert events == ["retire under install lock"]
    _resident_request(context.guard_home)


def test_a_native_refusal_while_stopping_reports_the_resident_as_still_running(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    events: list[str] = []
    _stub_resident(monkeypatch, tmp_path, events)

    def retire(_guard_home: Path, **_kwargs: object) -> bool:
        raise NativeRunnerAuthorityError("native_resident_update_in_progress")

    monkeypatch.setattr(uninstall_commands, "retire_native_resident_for_home", retire)
    monkeypatch.setattr(uninstall_commands, "_active_managed_installs", lambda _store: ([], None))

    assert uninstall_commands.retire_native_resident_after_last_harness(context, store) is False
    assert events == []


def test_terminal_output_names_a_resident_that_did_not_stop() -> None:
    output = StringIO()
    console = Console(file=output, width=120, color_system=None)

    _render_managed_install(
        console,
        {"managed_installs": [{"harness": "codex", "active": False}], "native_resident_retired": False},
    )

    assert "Could not stop the Guard native runtime" in output.getvalue()
