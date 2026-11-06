"""Focused browser-launch failure coverage for the dashboard launcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from codex_plugin_scanner.guard.dashboard_launcher import open_dashboard


def test_browser_opener_failure_is_reported_with_public_url(tmp_path: Path) -> None:
    mock_store = MagicMock()
    mock_config = MagicMock(approval_surface_policy="auto-open-once")
    mock_surface = MagicMock()

    with (
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
            return_value="http://127.0.0.1:4781/approvals",
        ),
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
            return_value="test-token",
        ),
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime",
            return_value=mock_surface,
        ),
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
            return_value="session-token-xyz",
        ),
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.open_browser_url",
            return_value=False,
        ) as mock_opener,
    ):

        def ensure_surface(**kwargs: object) -> dict[str, object]:
            assert kwargs["opener"] is mock_opener
            opened = mock_opener(str(kwargs["browser_url"]))
            return {"opened": opened, "reason": "opened" if opened else "open-failed"}

        mock_surface.ensure_surface.side_effect = ensure_surface
        result = open_dashboard(guard_home=tmp_path, store=mock_store, config=mock_config)

    assert result.opened is False
    assert result.reason == "open-failed"
    assert result.browser_url == "http://127.0.0.1:4781/approvals"
    mock_opener.assert_called_once()
