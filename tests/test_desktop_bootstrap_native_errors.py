"""Desktop's parser-free bootstrap keeps native installation errors actionable."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from codex_plugin_scanner import cli_native_errors
from codex_plugin_scanner.guard import config, store
from codex_plugin_scanner.guard.cli import desktop_bootstrap, update_native_wheel


def _fail_config_load(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: Exception) -> None:
    """Isolate bootstrap state and fail before policy or daemon work."""
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    monkeypatch.setattr(config, "resolve_guard_home", lambda _override: tmp_path / "guard")
    monkeypatch.setattr(store, "GuardStore", lambda *_args, **_kwargs: object())

    def fail(*_args: object, **_kwargs: object) -> None:
        """Raise the requested configuration failure."""
        raise error

    monkeypatch.setattr(config, "load_guard_config", fail)


@pytest.mark.parametrize("supported", [True, False])
def test_missing_runtime_bootstrap_reports_installation_hint_and_keeps_exit_two(
    supported: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Bootstrap gives actionable native errors without changing its exit contract."""
    _fail_config_load(monkeypatch, tmp_path, ValueError("native_guard_config_unavailable"))
    monkeypatch.setattr(update_native_wheel, "bundled_native_runtime_missing", lambda: True)
    monkeypatch.setattr(update_native_wheel, "native_platform_supported", lambda: supported)
    monkeypatch.setattr(cli_native_errors.sysconfig, "get_platform", lambda: "linux-aarch64")
    output = io.StringIO()

    assert desktop_bootstrap.run_desktop_bootstrap_cli(output_stream=output) == 2
    captured = capsys.readouterr()
    assert output.getvalue() == captured.out == ""
    assert captured.err.startswith("Error: native_guard_config_unavailable\n")
    assert "usage:" not in captured.err
    if supported:
        assert "Run `hol-guard update` to repair this installation" in captured.err
        assert "matching native wheel for this Guard version" in captured.err
    else:
        assert "No published HOL Guard native wheel matches this Python platform (linux-aarch64)" in captured.err


def test_existing_unhealthy_runtime_bootstrap_does_not_report_missing_support(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A present runtime failure must not be misdiagnosed as missing support."""
    _fail_config_load(monkeypatch, tmp_path, ValueError("native_guard_config_unavailable"))
    monkeypatch.setattr(update_native_wheel, "bundled_native_runtime_missing", lambda: False)

    assert desktop_bootstrap.run_desktop_bootstrap_cli(output_stream=io.StringIO()) == 2
    assert capsys.readouterr().err == "Error: native_guard_config_unavailable\n"


@pytest.mark.parametrize("error", [ValueError("invalid config"), OSError("unreadable config"), TimeoutError("busy")])
def test_other_bootstrap_errors_keep_existing_reporting(
    error: Exception, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Other configuration errors preserve their existing message and status."""
    _fail_config_load(monkeypatch, tmp_path, error)

    assert desktop_bootstrap.run_desktop_bootstrap_cli(output_stream=io.StringIO()) == 2
    assert capsys.readouterr().err == f"Error: {error}\n"
