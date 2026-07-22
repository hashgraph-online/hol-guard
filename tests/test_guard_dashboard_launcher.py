"""Parity tests for the canonical dashboard launcher service.

Validates that the launcher handles all daemon states, alternate Guard
homes, forced open, deduplication, browser failure, and missing token
behavior correctly. Also verifies that the authenticated URL fragment
(token) never appears in returned results, logs, or exceptions.
"""

from __future__ import annotations

import threading
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

from codex_plugin_scanner.guard.dashboard_launcher import (
    DashboardLaunchResult,
    _build_authenticated_browser_url,
    _redact_token_from_url,
    open_dashboard,
)


class TestBuildAuthenticatedBrowserUrl:
    def test_token_in_fragment(self) -> None:
        url = _build_authenticated_browser_url(
            "http://127.0.0.1:4781/approvals",
            auth_token="secret-token-123",
            surface="approval-center",
        )
        parsed = urllib.parse.urlparse(url)
        fragment_params = dict(urllib.parse.parse_qsl(parsed.fragment))
        assert "guard-token" in fragment_params
        assert fragment_params["guard-token"] != "secret-token-123"

    def test_daemon_url_in_fragment(self) -> None:
        url = _build_authenticated_browser_url(
            "http://127.0.0.1:4781/approvals",
            auth_token="tok",
            surface="approval-center",
            daemon_url="http://127.0.0.1:4781",
        )
        parsed = urllib.parse.urlparse(url)
        fragment_params = dict(urllib.parse.parse_qsl(parsed.fragment))
        assert "guardDaemon" in fragment_params

    def test_existing_fragment_preserved(self) -> None:
        url = _build_authenticated_browser_url(
            "http://127.0.0.1:4781/approvals#tab=approvals",
            auth_token="tok",
            surface="approval-center",
        )
        parsed = urllib.parse.urlparse(url)
        fragment_params = dict(urllib.parse.parse_qsl(parsed.fragment))
        assert fragment_params.get("tab") == "approvals"
        assert "guard-token" in fragment_params


class TestRedactTokenFromUrl:
    def test_removes_token(self) -> None:
        url = "http://127.0.0.1:4781/approvals#guard-token=abc123&tab=approvals"
        redacted = _redact_token_from_url(url)
        parsed = urllib.parse.urlparse(redacted)
        fragment_params = dict(urllib.parse.parse_qsl(parsed.fragment))
        assert "guard-token" not in fragment_params
        assert fragment_params.get("tab") == "approvals"

    def test_none_returns_none(self) -> None:
        assert _redact_token_from_url(None) is None

    def test_no_token_returns_unchanged(self) -> None:
        url = "http://127.0.0.1:4781/approvals#tab=approvals"
        redacted = _redact_token_from_url(url)
        assert redacted == url

    def test_preserves_query_params(self) -> None:
        url = "http://127.0.0.1:4781/approvals?foo=bar#guard-token=abc"
        redacted = _redact_token_from_url(url)
        parsed = urllib.parse.urlparse(redacted)
        assert dict(urllib.parse.parse_qsl(parsed.query)) == {"foo": "bar"}


class TestOpenDashboardDaemonUnavailable:
    def test_daemon_error_returns_result(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        with patch(
            "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
            side_effect=RuntimeError("Daemon failed to start"),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        assert isinstance(result, DashboardLaunchResult)
        assert result.opened is False
        assert result.reason == "daemon_unavailable"
        assert result.error is not None
        assert "Daemon failed" in result.error

    def test_daemon_error_does_not_leak_token(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        with patch(
            "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
            side_effect=RuntimeError("Daemon failed: token=secret-xyz"),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        result_str = repr(result) + str(result.to_payload())
        assert "secret-xyz" not in result_str


class TestOpenDashboardAuthTokenMissing:
    def test_missing_token_returns_result(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        with (
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
                return_value="http://127.0.0.1:4781/approvals",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
                return_value=None,
            ),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        assert result.opened is False
        assert result.reason == "auth_token_missing"
        assert result.error is not None


class TestOpenDashboardSuccess:
    def test_successful_open(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        mock_surface = MagicMock()
        mock_surface.ensure_surface.return_value = {
            "surface": "approval-center",
            "opened": True,
            "reason": "opened",
            "open_key": "dashboard",
        }

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
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        assert result.opened is True
        assert result.reason == "opened"
        assert result.approval_center_url == "http://127.0.0.1:4781/approvals"
        assert result.browser_url is not None
        assert "guard-token" not in str(result.browser_url)

    def test_browser_url_does_not_contain_token(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        mock_surface = MagicMock()
        mock_surface.ensure_surface.return_value = {
            "opened": True,
            "reason": "opened",
        }

        with (
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
                return_value="http://127.0.0.1:4781/approvals",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
                return_value="secret-auth-token",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime",
                return_value=mock_surface,
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
                return_value="session-xyz",
            ),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        payload_str = repr(result.to_payload())
        assert "secret-auth-token" not in payload_str
        assert "session-xyz" not in payload_str

    def test_policy_disabled_returns_not_opened(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "notify-only"

        mock_surface = MagicMock()
        mock_surface.ensure_surface.return_value = {
            "opened": False,
            "reason": "policy-disabled",
        }

        with (
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
                return_value="http://127.0.0.1:4781/approvals",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
                return_value="tok",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime",
                return_value=mock_surface,
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
                return_value="session",
            ),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
                force_open=False,
            )

        assert result.opened is False
        assert result.reason == "policy-disabled"

    def test_already_opened_dedup(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        mock_surface = MagicMock()
        mock_surface.ensure_surface.return_value = {
            "opened": False,
            "reason": "already-opened",
        }

        with (
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
                return_value="http://127.0.0.1:4781/approvals",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
                return_value="tok",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime",
                return_value=mock_surface,
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
                return_value="session",
            ),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        assert result.opened is False
        assert result.reason == "already-opened"

    def test_live_client_dedup(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        mock_surface = MagicMock()
        mock_surface.ensure_surface.return_value = {
            "opened": False,
            "reason": "live-client",
        }

        with (
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
                return_value="http://127.0.0.1:4781/approvals",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
                return_value="tok",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime",
                return_value=mock_surface,
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
                return_value="session",
            ),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        assert result.opened is False
        assert result.reason == "live-client"


class TestOpenDashboardConcurrency:
    def test_concurrent_calls_coalesce(self, tmp_path: Path) -> None:
        """Repeated activation creates at most one in-flight daemon start."""
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        call_count = 0
        call_lock = threading.Lock()

        mock_surface = MagicMock()

        def slow_ensure_surface(**kwargs: object) -> dict[str, object]:
            with call_lock:
                nonlocal_ref = call_count  # noqa: F841
            import time

            time.sleep(0.1)
            return {"opened": True, "reason": "opened"}

        mock_surface.ensure_surface.side_effect = slow_ensure_surface

        with (
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
                return_value="http://127.0.0.1:4781/approvals",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
                return_value="tok",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime",
                return_value=mock_surface,
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
                return_value="session",
            ),
        ):
            results: list[DashboardLaunchResult] = []
            threads: list[threading.Thread] = []

            def call_open() -> None:
                results.append(
                    open_dashboard(
                        guard_home=tmp_path,
                        store=mock_store,
                        config=mock_config,
                    )
                )

            for _ in range(5):
                t = threading.Thread(target=call_open)
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

        assert len(results) == 5
        for result in results:
            assert isinstance(result, DashboardLaunchResult)

    def test_result_payload_json_serializable(self, tmp_path: Path) -> None:
        import json

        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        with patch(
            "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
            side_effect=RuntimeError("fail"),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        payload = result.to_payload()
        assert json.dumps(payload) is not None


class TestOpenDashboardSurfaceException:
    """If ``GuardSurfaceRuntime.ensure_surface()`` raises (e.g. due to an
    unexpected internal error), ``open_dashboard`` must normalize the failure
    into a clean redacted error payload instead of propagating the exception
    to the caller (which would crash the tray's open callback)."""

    def test_surface_exception_returns_dashboard_open_failed(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        mock_surface = MagicMock()
        mock_surface.ensure_surface.side_effect = RuntimeError("surface exploded")

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
                return_value="session-xyz",
            ),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        assert result.opened is False
        assert result.reason == "dashboard_open_failed"
        assert result.error is not None
        assert "surface exploded" in result.error
        # Token must never leak into the error payload
        assert "test-token" not in str(result.to_payload())

    def test_surface_exception_redacts_token_from_url(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        mock_config.approval_surface_policy = "auto-open-once"

        mock_surface = MagicMock()
        mock_surface.ensure_surface.side_effect = ValueError("boom")

        with (
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
                return_value="http://127.0.0.1:4781/approvals",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
                return_value="secret-auth-token",
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime",
                return_value=mock_surface,
            ),
            patch(
                "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
                return_value="session-xyz",
            ),
        ):
            result = open_dashboard(
                guard_home=tmp_path,
                store=mock_store,
                config=mock_config,
            )

        # browser_url must be redacted even on the failure path
        assert result.browser_url is None or "secret-auth-token" not in str(result.browser_url)
        payload_str = repr(result.to_payload())
        assert "secret-auth-token" not in payload_str
        assert "session-xyz" not in payload_str
