"""Desktop bootstrap reads share one store connection."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_connection_scope
from codex_plugin_scanner.guard.cli import commands_dispatch_desktop, desktop_bootstrap


def test_desktop_bootstrap_snapshot_runs_inside_one_connection_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Desktop's update preflight bounds this command; a connect/close per read
    # pushed it past that budget on loaded machines.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    observed: list[bool] = []

    def fake_run(_args: object, *, store: object, **_kwargs: object) -> int:
        observed.append(store_connection_scope.owns_scope(store))  # type: ignore[arg-type]
        return 0

    monkeypatch.setattr(commands_dispatch_desktop, "_run_guard_desktop_command", fake_run)

    assert desktop_bootstrap.run_desktop_bootstrap_cli() == 0
    assert observed == [True]
