"""The stored browser preference applies at the shared surface boundary."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.runtime.surface_server import GuardSurfaceRuntime


def test_native_only_suppresses_automatic_surfaces() -> None:
    runtime = GuardSurfaceRuntime(Mock())
    opener = Mock(return_value=True)
    result = runtime.ensure_surface(
        surface="approval-center",
        approval_center_url="http://127.0.0.1:4781",
        approval_surface_policy="native-only",
        open_key="automatic-review",
        opener=opener,
    )
    assert result["opened"] is False
    assert result["reason"] == "policy-disabled"
    opener.assert_not_called()


def test_hook_approval_opener_honors_global_preference(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_hook_payload as hooks
    from codex_plugin_scanner.guard.config import GuardConfig

    store = Mock(guard_home=tmp_path)
    opener = Mock(return_value=True)
    monkeypatch.setattr(hooks, "load_guard_daemon_auth_token", lambda _home: None)
    monkeypatch.setattr(hooks, "open_browser_url", opener)
    result = hooks._open_approval_center(
        "http://127.0.0.1:4781",
        store=store,
        config=GuardConfig(guard_home=tmp_path, workspace=None, approval_surface_policy="native-only"),
    )
    assert result["opened"] is False
    opener.assert_not_called()


def test_user_requested_open_remains_available() -> None:
    runtime = GuardSurfaceRuntime(Mock())
    opener = Mock(return_value=True)
    result = runtime.ensure_surface(
        surface="approval-center",
        approval_center_url="http://127.0.0.1:4781",
        approval_surface_policy="native-only",
        open_key="manual-open",
        force_open=True,
        opener=opener,
    )
    assert result["opened"] is True
    opener.assert_called_once_with("http://127.0.0.1:4781")
