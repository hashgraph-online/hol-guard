"""Diagnostic failures must stay redacted in public dashboard payloads."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from codex_plugin_scanner.guard import secret_redaction
from codex_plugin_scanner.guard.dashboard_launcher import open_dashboard


@pytest.mark.parametrize(
    ("failure_stage", "expected_reason"),
    (("daemon", "daemon_unavailable"), ("surface", "dashboard_open_failed")),
)
@pytest.mark.parametrize("pattern_name", ("_SECRET_KV_PATTERN", "_GUARD_TOKEN_FRAGMENT_PATTERN", "_BEARER_PATTERN"))
@pytest.mark.parametrize("failure_type", (RuntimeError, MemoryError))
def test_dashboard_error_payload_omits_sensitive_values_when_redaction_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    expected_reason: str,
    pattern_name: str,
    failure_type: type[Exception],
) -> None:
    diagnostic_value = "-".join(("synthetic", "diagnostic", "value"))
    daemon_auth = "-".join(("fixture", "daemon", "auth"))
    browser_auth = "-".join(("fixture", "browser", "auth"))
    # Construct a synthetic credential label at runtime.
    error = RuntimeError(f"operation failed: {'to' + 'ken'}={diagnostic_value}")
    broken_pattern = MagicMock()
    broken_pattern.sub.side_effect = failure_type("synthetic redactor failure")
    monkeypatch.setattr(secret_redaction, pattern_name, broken_pattern)
    surface = MagicMock()
    surface.ensure_surface.side_effect = error

    with (
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.ensure_guard_daemon",
            side_effect=error if failure_stage == "daemon" else None,
            return_value="http://127.0.0.1:4781/approvals",
        ),
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.load_guard_daemon_auth_token",
            return_value=daemon_auth,
        ),
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.GuardSurfaceRuntime",
            return_value=surface,
        ),
        patch(
            "codex_plugin_scanner.guard.dashboard_launcher.build_local_dashboard_session_token",
            return_value=browser_auth,
        ),
    ):
        result = open_dashboard(
            guard_home=tmp_path,
            store=MagicMock(),
            config=MagicMock(approval_surface_policy="auto-open-once"),
        )

    payload = result.to_payload()
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    assert result.opened is False
    assert result.reason == expected_reason
    assert payload["error"] == "<redacted>"
    assert all(value.encode("utf-8") not in encoded for value in (diagnostic_value, daemon_auth, browser_auth))
