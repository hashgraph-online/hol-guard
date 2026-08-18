"""Authenticated approval-center locator publication contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager


def test_publish_locator_binds_authenticated_live_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard"
    state = {"pid": 4242, "port": 6174, "started_at": "2026-08-17T21:00:00+00:00"}
    monkeypatch.setattr(manager, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(manager, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(manager, "_guard_daemon_pid_matches_command", lambda *_args, **_kwargs: True)

    locator = manager.publish_approval_center_locator(guard_home, "http://127.0.0.1:6174")

    assert locator.pid == 4242
    assert locator.started_at == state["started_at"]
    assert manager.read_approval_center_locator(guard_home) == locator


def test_publish_locator_rejects_mismatched_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard"
    monkeypatch.setattr(
        manager,
        "load_authenticated_daemon_state",
        lambda _home: {"pid": 4242, "port": 6174},
    )
    monkeypatch.setattr(manager, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(manager, "_guard_daemon_pid_matches_command", lambda *_args, **_kwargs: True)

    with pytest.raises(RuntimeError, match="does not match"):
        manager.publish_approval_center_locator(guard_home, "http://127.0.0.1:6175")

    assert not (guard_home / "approval-center-locator.json").exists()


def test_publish_locator_accepts_authenticated_health_identity_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard"
    state = {"pid": 4242, "port": 6174, "started_at": "2026-08-17T21:00:00+00:00"}
    details: dict[str, object] = {
        "pid": 4242,
        "guard_home": str(guard_home),
        "package_version": manager.__version__,
        "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": manager._current_guard_daemon_source_root(),
        "runtime_fingerprint": manager._current_guard_daemon_runtime_fingerprint(),
    }
    monkeypatch.setattr(manager, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(manager, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(manager, "_guard_daemon_pid_matches_command", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(manager, "load_guard_daemon_auth_token", lambda _home: "token")
    health_calls: list[tuple[str, str]] = []

    def health_details(daemon_url: str, token: str) -> dict[str, object]:
        health_calls.append((daemon_url, token))
        return details

    monkeypatch.setattr(manager, "_daemon_healthz_details_payload", health_details)

    locator = manager.publish_approval_center_locator(guard_home, "http://127.0.0.1:6174")

    assert locator.pid == 4242
    assert manager.read_approval_center_locator(guard_home) == locator
    assert health_calls == [("http://127.0.0.1:6174", "token")]
