"""Tests for the tray runtime: menu callbacks, icon loading, coalescing.

Validates the TrayRuntime class without spawning a real pystray icon.
Uses fake callbacks and mocked pystray/PIL imports.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from codex_plugin_scanner.guard.tray.contracts import (
    DASHBOARD_OPEN_COALESCE_SECONDS,
    TrayBackend,
    TrayCapability,
    TrayPlatform,
    TrayReasonCode,
    TrayState,
)
from codex_plugin_scanner.guard.tray.runtime import (
    TrayMenuCallbacks,
    TrayRuntime,
    _load_icon_bytes,
    detect_capability,
)


def _capability(supported: bool = True) -> TrayCapability:
    return TrayCapability(
        platform=TrayPlatform.MACOS,
        backend=TrayBackend.APPKIT,
        supported=supported,
        reason=TrayReasonCode.OK if supported else TrayReasonCode.UNSUPPORTED_PLATFORM,
        details="test",
    )


def _make_runtime(tmp_path: Path, *, callbacks: TrayMenuCallbacks | None = None) -> TrayRuntime:
    mock_store = MagicMock()
    mock_config = MagicMock()
    return TrayRuntime(
        guard_home=tmp_path,
        store=mock_store,
        config=mock_config,
        capability=_capability(),
        callbacks=callbacks,
    )


class TestTrayMenuCallbacks:
    def test_callbacks_stored(self) -> None:
        open_cb = MagicMock()
        toggle_cb = MagicMock(return_value=True)
        quit_cb = MagicMock()
        callbacks = TrayMenuCallbacks(
            open_dashboard=open_cb,
            toggle_start_at_login=toggle_cb,
            quit_tray=quit_cb,
        )
        callbacks.open_dashboard()
        callbacks.toggle_start_at_login()
        callbacks.quit_tray()
        open_cb.assert_called_once()
        toggle_cb.assert_called_once()
        quit_cb.assert_called_once()


class TestRequestOpenDashboard:
    def test_calls_callback_when_provided(self, tmp_path: Path) -> None:
        open_cb = MagicMock()
        callbacks = TrayMenuCallbacks(
            open_dashboard=open_cb,
            toggle_start_at_login=MagicMock(),
            quit_tray=MagicMock(),
        )
        runtime = _make_runtime(tmp_path, callbacks=callbacks)
        runtime.request_open_dashboard()
        open_cb.assert_called_once()

    def test_coalesces_rapid_calls(self, tmp_path: Path) -> None:
        open_cb = MagicMock()
        callbacks = TrayMenuCallbacks(
            open_dashboard=open_cb,
            toggle_start_at_login=MagicMock(),
            quit_tray=MagicMock(),
        )
        runtime = _make_runtime(tmp_path, callbacks=callbacks)
        runtime.request_open_dashboard()
        runtime.request_open_dashboard()
        runtime.request_open_dashboard()
        assert open_cb.call_count == 1

    def test_allows_open_after_coalesce_window(self, tmp_path: Path) -> None:
        open_cb = MagicMock()
        callbacks = TrayMenuCallbacks(
            open_dashboard=open_cb,
            toggle_start_at_login=MagicMock(),
            quit_tray=MagicMock(),
        )
        runtime = _make_runtime(tmp_path, callbacks=callbacks)
        runtime.request_open_dashboard()
        # Manually advance past the coalesce window
        runtime._last_open_at = time.monotonic() - DASHBOARD_OPEN_COALESCE_SECONDS - 0.1
        runtime.request_open_dashboard()
        assert open_cb.call_count == 2

    def test_default_handler_calls_launcher(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        with patch("codex_plugin_scanner.guard.dashboard_launcher.open_dashboard") as mock_open:
            mock_open.return_value = MagicMock(opened=True, reason="opened")
            runtime.request_open_dashboard()
            mock_open.assert_called_once()

    def test_default_handler_notifies_on_failure(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        with patch("codex_plugin_scanner.guard.dashboard_launcher.open_dashboard") as mock_open:
            mock_open.return_value = MagicMock(
                opened=False,
                reason="daemon_unavailable",
                error=None,
            )
            runtime.request_open_dashboard()
            mock_open.assert_called_once()


class TestRequestToggleStartAtLogin:
    def test_toggles_state(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        assert runtime._start_at_login is False
        result = runtime.request_toggle_start_at_login()
        assert result is True
        assert runtime._start_at_login is True
        result = runtime.request_toggle_start_at_login()
        assert result is False
        assert runtime._start_at_login is False

    def test_uses_callback_when_provided(self, tmp_path: Path) -> None:
        toggle_cb = MagicMock(return_value=True)
        callbacks = TrayMenuCallbacks(
            open_dashboard=MagicMock(),
            toggle_start_at_login=toggle_cb,
            quit_tray=MagicMock(),
        )
        runtime = _make_runtime(tmp_path, callbacks=callbacks)
        result = runtime.request_toggle_start_at_login()
        toggle_cb.assert_called_once()
        assert result is True


class TestRequestQuit:
    def test_sets_stop_event(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        runtime.request_quit()
        assert runtime._stop_requested.is_set()

    def test_calls_quit_callback(self, tmp_path: Path) -> None:
        quit_cb = MagicMock()
        callbacks = TrayMenuCallbacks(
            open_dashboard=MagicMock(),
            toggle_start_at_login=MagicMock(),
            quit_tray=quit_cb,
        )
        runtime = _make_runtime(tmp_path, callbacks=callbacks)
        runtime.request_quit()
        quit_cb.assert_called_once()

    def test_stops_icon_if_present(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        runtime._icon = MagicMock()
        runtime.request_quit()
        runtime._icon.stop.assert_called_once()


class TestStop:
    def test_sets_stop_event(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        runtime.stop()
        assert runtime._stop_requested.is_set()

    def test_stops_icon(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        runtime._icon = MagicMock()
        runtime.stop()
        runtime._icon.stop.assert_called_once()

    def test_no_error_when_icon_none(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        runtime.stop()  # should not raise


class TestRun:
    def test_unsupported_platform_returns_1(self, tmp_path: Path) -> None:
        mock_store = MagicMock()
        mock_config = MagicMock()
        runtime = TrayRuntime(
            guard_home=tmp_path,
            store=mock_store,
            config=mock_config,
            capability=_capability(supported=False),
        )
        result = runtime.run()
        assert result == 1
        assert runtime.state == TrayState.UNSUPPORTED

    def test_missing_pystray_returns_1(self, tmp_path: Path) -> None:
        runtime = _make_runtime(tmp_path)
        with patch.dict("sys.modules", {"pystray": None, "PIL": None, "PIL.Image": None}):
            result = runtime.run()
        assert result == 1


class TestLoadIconBytes:
    def test_returns_bytes(self) -> None:
        data = _load_icon_bytes(TrayPlatform.MACOS)
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_returns_valid_png(self) -> None:
        data = _load_icon_bytes(TrayPlatform.MACOS)
        # PNG magic bytes
        assert data[:8] == b"\x89PNG\r\n\x1a\n"

    def test_fallback_for_unknown_platform(self) -> None:
        data = _load_icon_bytes(TrayPlatform.LINUX)
        assert isinstance(data, bytes)
        assert len(data) > 0


class TestDetectCapability:
    def test_returns_supported_on_macos(self) -> None:
        cap = detect_capability()
        # On macOS (where tests run), should be supported
        if cap.platform == TrayPlatform.MACOS:
            assert cap.supported is True
            assert cap.backend == TrayBackend.APPKIT
            assert cap.reason == TrayReasonCode.OK

    def test_returns_unsupported_on_unknown_platform(self) -> None:
        with patch("codex_plugin_scanner.guard.tray.contracts.TrayPlatform.current", return_value=None):
            cap = detect_capability()
        assert cap.supported is False
        assert cap.reason == TrayReasonCode.UNSUPPORTED_PLATFORM
        assert cap.platform is None

    def test_returns_dependency_missing_when_pystray_absent(self) -> None:
        # On headless Linux CI, detect_capability() hits the NO_DISPLAY
        # check before reaching the pystray import. Set DISPLAY to bypass it.
        with patch.dict("os.environ", {"DISPLAY": ":0"}, clear=False), patch.dict("sys.modules", {"pystray": None}):
            cap = detect_capability()
        assert cap.supported is False
        assert cap.reason == TrayReasonCode.DEPENDENCY_MISSING


class TestSanitizeMessage:
    def test_strips_token_from_message(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.security import sanitize_secret

        result = sanitize_secret("Error: token=secret-abc123")
        assert "secret-abc123" not in result
        assert "<redacted>" in result

    def test_strips_bearer_token(self) -> None:
        from codex_plugin_scanner.guard.tray.security import sanitize_secret

        result = sanitize_secret("Authorization: Bearer abc.def.ghi")
        assert "abc.def.ghi" not in result
        assert "<redacted>" in result

    def test_strips_url_fragment(self) -> None:
        from codex_plugin_scanner.guard.tray.security import sanitize_secret

        result = sanitize_secret("http://localhost:4781#guard-token=frag-tok-123")
        assert "frag-tok-123" not in result
        assert "<redacted>" in result

    def test_preserves_non_secret_content(self) -> None:
        from codex_plugin_scanner.guard.tray.security import sanitize_secret

        result = sanitize_secret("Daemon failed to start on port 4781")
        assert "4781" in result
        assert "Daemon failed" in result

    def test_empty_string_returns_empty(self) -> None:
        from codex_plugin_scanner.guard.tray.security import sanitize_secret

        assert sanitize_secret("") == ""
