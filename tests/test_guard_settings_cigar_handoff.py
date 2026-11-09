"""Saved CIGAR settings reach the native service that prompt hooks read."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_context_assistance
from tests.test_guard_settings_api import _json_request, _with_daemon

# A CIGAR settings change. Turning CIGAR fully on also needs an installed
# runtime, which this test does not set up.
CIGAR_CHANGE = {"enabled": False, "features": {"agent_context": True}}


def test_saving_cigar_settings_hands_them_to_the_native_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    calls: list[tuple[str, Path | None]] = []

    def control(kind: str, *, guard_home: Path | None = None, payload: object = None) -> dict[str, object]:
        calls.append((kind, guard_home))
        return {}

    monkeypatch.setattr(native_context_assistance, "control", control)
    # The daemon's own handlers must answer, so no native edge may serve the
    # reset first.
    monkeypatch.setenv("HOL_GUARD_DAEMON_NATIVE_EDGE", "0")
    _store, daemon = _with_daemon(guard_home)
    try:
        saved, _ = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"context_assistance": CIGAR_CHANGE}},
        )
        after_save = list(calls)
        other, _ = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"mode": "observe"}},
        )
        after_other = list(calls)
        reset, _ = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings/reset",
            method="POST",
            payload={"confirm": "reset-local-settings"},
        )
    finally:
        daemon.stop()

    assert (saved, other, reset) == (200, 200, 200)
    assert after_save == [("status", guard_home)]
    assert after_other == after_save
    assert calls == [("status", guard_home), ("status", guard_home)]


def test_a_native_refusal_does_not_fail_the_save(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"

    def control(kind: str, **_: object) -> dict[str, object]:
        raise native_context_assistance.ContextAssistanceError("native_context_assistance_busy")

    monkeypatch.setattr(native_context_assistance, "control", control)
    _store, daemon = _with_daemon(guard_home)
    try:
        status, payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"context_assistance": CIGAR_CHANGE}},
        )
    finally:
        daemon.stop()

    assert status == 200, payload
    assert "settings" in payload
