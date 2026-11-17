"""Every dashboard launch outcome names its cause, port, browser result and fallback."""

from __future__ import annotations

import io
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from codex_plugin_scanner.guard.cli.render import _render_dashboard
from codex_plugin_scanner.guard.dashboard_launcher import DashboardLaunchResult, open_dashboard
from codex_plugin_scanner.guard.native_daemon_failure import daemon_failure_code
from codex_plugin_scanner.guard.native_daemon_manage import _daemon_url_from_answer


def _raised(answer: dict[str, object] | None, deadline: float) -> BaseException:
    with pytest.raises((RuntimeError, OSError, ValueError)) as caught:
        _daemon_url_from_answer(answer, deadline)
    return caught.value


@pytest.mark.parametrize(
    ("answer", "code"),
    (
        ({"error": "ports held", "kind": "runtime", "code": "port_conflict"}, "port_conflict"),
        ({"error": "starting", "kind": "timeout", "code": "daemon_still_starting"}, "daemon_still_starting"),
        ({"error": "starting", "kind": "timeout"}, "daemon_still_starting"),
        ({"error": "bad config", "kind": "value"}, "daemon_launch_config_invalid"),
        ({"error": "lost", "kind": "runtime"}, "daemon_unavailable"),
    ),
)
def test_native_failure_codes_reach_the_caller(answer: dict[str, object], code: str) -> None:
    assert daemon_failure_code(_raised(answer, time.monotonic() + 60)) == code


def test_missing_runtime_and_expired_deadline_are_named() -> None:
    assert daemon_failure_code(_raised(None, time.monotonic() + 60)) == "native_runtime_unavailable"
    assert daemon_failure_code(_raised(None, time.monotonic() - 1)) == "daemon_start_timeout"


@pytest.mark.parametrize(
    ("error", "reason"),
    (
        (TimeoutError("Guard daemon operation deadline exceeded."), "daemon_start_timeout"),
        (ValueError("Guard daemon operation deadline is invalid."), "daemon_launch_config_invalid"),
        (OSError("spawn failed"), "daemon_unavailable"),
    ),
)
def test_every_daemon_error_type_returns_a_typed_result(tmp_path: Path, error: Exception, reason: str) -> None:
    with patch("codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon", side_effect=error):
        result = open_dashboard(guard_home=tmp_path, store=MagicMock(), config=MagicMock())
    assert result.opened is False
    assert result.reason == reason
    payload = result.to_payload()
    assert payload["port"] is None
    assert payload["browser"] == "not_attempted"
    assert payload["fallback"]


def test_port_conflict_fallback_names_the_cause(tmp_path: Path) -> None:
    error = RuntimeError("Guard daemon could not start: every port it can use is held by another program.")
    error.guard_failure_code = "port_conflict"  # type: ignore[attr-defined]
    with patch("codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon", side_effect=error):
        result = open_dashboard(guard_home=tmp_path, store=MagicMock(), config=MagicMock())
    assert result.reason == "port_conflict"
    assert "port" in str(result.to_payload()["fallback"])


def test_surface_without_a_reason_is_never_unknown(tmp_path: Path) -> None:
    surface = MagicMock()
    surface.ensure_surface.return_value = {"opened": False}
    with (
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
            return_value="http://127.0.0.1:4790/approvals",
        ),
        patch("codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token", return_value="fixture"),
        patch("codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime", return_value=surface),
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
            return_value="fixture-session",
        ),
    ):
        result = open_dashboard(guard_home=tmp_path, store=MagicMock(), config=MagicMock())
    assert result.reason == "browser_unavailable"
    assert result.to_payload()["port"] == 4790


def test_opened_dashboard_reports_port_and_browser() -> None:
    result = DashboardLaunchResult(
        opened=True,
        approval_center_url="http://127.0.0.1:4781/approvals",
        browser_url="http://127.0.0.1:4781/approvals",
        reason="opened",
    )
    payload = result.to_payload()
    assert payload["port"] == 4781
    assert payload["browser"] == "opened"
    assert payload["signed_url"] == "delivered_to_browser"
    assert payload["fallback"] is None


def test_human_output_names_cause_and_next_step_and_never_says_unknown() -> None:
    result = DashboardLaunchResult(
        opened=False, approval_center_url="", browser_url=None, reason="port_conflict", error="ports held"
    )
    buffer = io.StringIO()
    _render_dashboard(Console(file=buffer, width=200), result.to_payload())
    text = buffer.getvalue()
    assert "port_conflict" in text
    assert "Next step" in text
    assert "unknown" not in text.lower()
