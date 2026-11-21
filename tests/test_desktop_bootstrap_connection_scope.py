"""Desktop bootstrap projection reads share one store connection."""

from __future__ import annotations

import io
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_connection_scope
from codex_plugin_scanner.guard.cli import commands_dispatch_desktop, desktop_bootstrap


def _isolate_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))


def test_desktop_bootstrap_projection_runs_inside_one_connection_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Desktop's update preflight bounds this command; a connect/close per read
    # pushed it past that budget on loaded machines.
    _isolate_home(monkeypatch, tmp_path)
    observed: dict[str, bool] = {}
    store_holder: dict[str, object] = {}

    def fake_session_url(**_kwargs: object) -> str:
        observed["daemon"] = store_connection_scope.owns_scope(store_holder["store"])  # type: ignore[arg-type]
        return "http://127.0.0.1:1/session"

    def fake_assemble(*, store: object, **_kwargs: object) -> dict[str, object]:
        observed["projection"] = store_connection_scope.owns_scope(store)  # type: ignore[arg-type]
        return {"ok": True}

    monkeypatch.delenv("HOL_GUARD_DESKTOP_PREFLIGHT", raising=False)
    monkeypatch.setattr(commands_dispatch_desktop, "build_desktop_dashboard_session_url", fake_session_url)
    monkeypatch.setattr(commands_dispatch_desktop, "assemble_desktop_bootstrap_document", fake_assemble)
    real_run = commands_dispatch_desktop._run_guard_desktop_command

    def capture_store(args: object, *, store: object, **kwargs: object) -> int:
        store_holder["store"] = store
        return real_run(args, store=store, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(commands_dispatch_desktop, "_run_guard_desktop_command", capture_store)

    assert desktop_bootstrap.run_desktop_bootstrap_cli(output_stream=io.StringIO()) == 0
    # The scope holds the shared storage gate, so daemon start/adopt stays outside it.
    assert observed == {"daemon": False, "projection": True}


def test_desktop_bootstrap_scope_entry_failure_exits_two(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _isolate_home(monkeypatch, tmp_path)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_PREFLIGHT", "1")

    @contextmanager
    def failing_scope(_store: object):
        raise TimeoutError("Timed out waiting for Guard storage access")
        yield

    monkeypatch.setattr(store_connection_scope, "connection_scope", failing_scope)

    assert desktop_bootstrap.run_desktop_bootstrap_cli(output_stream=io.StringIO()) == 2
    assert "Error: Timed out waiting for Guard storage access" in capsys.readouterr().err
