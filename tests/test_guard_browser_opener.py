"""Tests for quiet local-dashboard browser launch behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import browser_opener
from codex_plugin_scanner.guard.cli import commands_support_hook_payload


@pytest.fixture
def real_launch_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the launch seams below the pytest suppression gate."""

    monkeypatch.setenv("HOL_GUARD_TEST_ALLOW_BROWSER_OPEN", "1")


def _fail_launch_attempt(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("browser should not launch")


def test_pytest_context_suppresses_browser_launch(monkeypatch) -> None:
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/test_guard_browser_opener.py::test (call)")
    monkeypatch.delenv("HOL_GUARD_TEST_DISABLE_BROWSER_OPEN", raising=False)
    monkeypatch.delenv("HOL_GUARD_TEST_ALLOW_BROWSER_OPEN", raising=False)
    monkeypatch.setattr(browser_opener.webbrowser, "open", _fail_launch_attempt)
    monkeypatch.setattr(browser_opener.subprocess, "Popen", _fail_launch_attempt)

    assert browser_opener.open_browser_url("http://127.0.0.1:5474") is False


def test_disable_flag_suppresses_browser_launch_outside_test_call(monkeypatch) -> None:
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("HOL_GUARD_TEST_ALLOW_BROWSER_OPEN", raising=False)
    monkeypatch.setenv("HOL_GUARD_TEST_DISABLE_BROWSER_OPEN", "1")
    monkeypatch.setattr(browser_opener.webbrowser, "open", _fail_launch_attempt)
    monkeypatch.setattr(browser_opener.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setattr(browser_opener.subprocess, "Popen", _fail_launch_attempt)

    assert browser_opener.open_browser_url("http://127.0.0.1:5474") is False


def test_allow_flag_reenables_launch_path_during_pytest(monkeypatch) -> None:
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/test_guard_browser_opener.py::test (call)")
    monkeypatch.setenv("HOL_GUARD_TEST_ALLOW_BROWSER_OPEN", "1")
    captured: dict[str, object] = {}

    def fake_open(url: str) -> bool:
        captured["url"] = url
        return True

    monkeypatch.setattr(browser_opener.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(browser_opener.subprocess, "Popen", _fail_launch_attempt)
    monkeypatch.setattr(browser_opener.webbrowser, "open", fake_open)

    assert browser_opener.open_browser_url("http://127.0.0.1:5474") is True
    assert captured["url"] == "http://127.0.0.1:5474"


def test_linux_headless_session_skips_browser_launch(monkeypatch, real_launch_path) -> None:
    monkeypatch.setattr(browser_opener.platform, "system", lambda: "Linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        browser_opener.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("browser should not launch")),
    )

    assert browser_opener.open_browser_url("http://127.0.0.1:5474") is False


def test_linux_graphical_session_launches_xdg_open_quietly(monkeypatch, real_launch_path) -> None:
    captured: dict[str, object] = {}

    class CompletedProcess:
        def wait(self, *, timeout: float) -> int:
            assert timeout == 0.2
            return 0

    def fake_popen(command: list[str], **kwargs: object) -> CompletedProcess:
        captured["command"] = command
        captured.update(kwargs)
        return CompletedProcess()

    monkeypatch.setattr(browser_opener.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(browser_opener.subprocess, "Popen", fake_popen)

    assert browser_opener.open_browser_url("http://127.0.0.1:5474") is True
    assert captured["command"] == ["xdg-open", "http://127.0.0.1:5474"]
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["stdout"] is subprocess.DEVNULL
    assert captured["stderr"] is subprocess.DEVNULL
    assert captured["start_new_session"] is True


def test_linux_graphical_session_uses_generic_handler_without_chromium_probe(monkeypatch, real_launch_path) -> None:
    class CompletedProcess:
        def wait(self, *, timeout: float) -> int:
            assert timeout == 0.2
            return 0

    monkeypatch.setattr(browser_opener.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        browser_opener.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Chromium probe should not run")),
    )
    monkeypatch.setattr(browser_opener.subprocess, "Popen", lambda *_args, **_kwargs: CompletedProcess())

    assert browser_opener.open_browser_url("http://127.0.0.1:5474") is True


def test_linux_graphical_launcher_failure_is_quiet_and_not_opened(monkeypatch, real_launch_path) -> None:
    captured: dict[str, object] = {}

    class FailedProcess:
        def wait(self, *, timeout: float) -> int:
            assert timeout == 0.2
            return 1

    def fake_popen(_command: list[str], **kwargs: object) -> FailedProcess:
        captured.update(kwargs)
        return FailedProcess()

    monkeypatch.setattr(browser_opener.platform, "system", lambda: "Linux")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setattr(browser_opener.subprocess, "Popen", fake_popen)

    assert browser_opener.open_browser_url("http://127.0.0.1:5474") is False
    assert captured["stdout"] is subprocess.DEVNULL
    assert captured["stderr"] is subprocess.DEVNULL


def test_dashboard_approval_center_uses_quiet_browser_opener(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    class FakeSurfaceRuntime:
        def __init__(self, _store: object) -> None:
            pass

        def ensure_surface(self, **kwargs: object) -> dict[str, object]:
            captured.update(kwargs)
            return {"opened": False, "reason": "open-failed"}

    monkeypatch.setattr(commands_support_hook_payload, "GuardSurfaceRuntime", FakeSurfaceRuntime)
    monkeypatch.setattr(commands_support_hook_payload, "load_guard_daemon_auth_token", lambda _guard_home: None)

    result = commands_support_hook_payload._open_approval_center(
        "http://127.0.0.1:5474",
        store=SimpleNamespace(guard_home=tmp_path),
        config=SimpleNamespace(approval_surface_policy="auto-open-once"),
    )

    assert captured["opener"] is browser_opener.open_browser_url
    assert result["opened"] is False
