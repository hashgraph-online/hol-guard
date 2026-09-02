"""Watch continues tools; same-release daemons stay current across install paths."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    availability_harness_response,
    cursor_fallback_permission,
)
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.version import __version__


class _HealthzResponse:
    status = 200

    def __enter__(self) -> _HealthzResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(
            {
                "ok": True,
                "tables": ["guard_connect_states"],
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            }
        ).encode("utf-8")


def test_guard_daemon_state_matches_same_release_peer_fingerprint() -> None:
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": __version__,
        "source_root": "/desktop/core/sidecar",
        "runtime_fingerprint": "desktop-sidecar-fingerprint",
    }

    assert daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_guard_daemon_state_rejects_different_package_version_peer() -> None:
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": "0.0.1",
        "source_root": "/opt/hol-guard/lib/python",
        "runtime_fingerprint": "desktop-sidecar-fingerprint",
    }

    assert not daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_guard_daemon_state_matches_older_desktop_core_sidecar() -> None:
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": "0.0.1",
        "source_root": "Library/Application Support/org.hol.guard.desktop/core/versions/0.0.1/hol-guard",
        "runtime_fingerprint": "desktop-sidecar-fingerprint",
    }

    assert daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_guard_daemon_state_matches_windows_desktop_core_sidecar() -> None:
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": "0.0.1",
        "source_root": r"AppData\Roaming\org.hol.guard.desktop\core\versions\0.0.1\hol-guard",
        "runtime_fingerprint": "desktop-sidecar-fingerprint",
    }

    assert daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_guard_daemon_state_rejects_generic_desktop_core_path() -> None:
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": "0.0.1",
        "source_root": "/desktop/core/sidecar",
        "runtime_fingerprint": "desktop-sidecar-fingerprint",
    }

    assert not daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_guard_daemon_state_rejects_empty_fingerprint_desktop_sidecar() -> None:
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": "0.0.1",
        "source_root": "org.hol.guard.desktop/core/versions/0.0.1/hol-guard",
        "runtime_fingerprint": "   ",
    }

    assert not daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_guard_daemon_state_rejects_incompatible_desktop_sidecar() -> None:
    payload = {
        "compatibility_version": "not-current",
        "package_version": "0.0.1",
        "source_root": "Library/Application Support/org.hol.guard.desktop/core/versions/0.0.1/hol-guard",
        "runtime_fingerprint": "desktop-sidecar-fingerprint",
    }

    assert not daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_guard_daemon_state_rejects_embedded_desktop_marker() -> None:
    payload = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": "0.0.1",
        "source_root": "opt/hol-guard/evil-org.hol.guard.desktop/core/versions/0.0.1/hol-guard",
        "runtime_fingerprint": "desktop-sidecar-fingerprint",
    }

    assert not daemon_manager_module._guard_daemon_state_matches_current_runtime(payload)


def test_healthz_details_require_compatible_same_release_peer() -> None:
    compatible = {
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": __version__,
        "runtime_fingerprint": "desktop-sidecar-fingerprint",
    }
    incompatible = dict(compatible)
    incompatible["compatibility_version"] = "not-current"
    assert daemon_manager_module._daemon_healthz_details_match_current_runtime(compatible)
    assert not daemon_manager_module._daemon_healthz_details_match_current_runtime(incompatible)


def test_load_guard_daemon_url_rejects_older_package_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon_manager_module.write_guard_daemon_state(
        guard_home,
        5530,
        "token-123",
        pid=12345,
    )
    monkeypatch.setattr(daemon_manager_module, "__version__", "9.9.9")
    monkeypatch.setattr(
        daemon_manager_module,
        "_current_guard_daemon_runtime_fingerprint",
        lambda: "pipx-runtime-fingerprint",
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)

    assert daemon_manager_module.load_guard_daemon_url(guard_home) is None


def test_load_guard_daemon_url_accepts_older_desktop_core_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(
        daemon_manager_module,
        "_current_guard_daemon_source_root",
        lambda: "Library/Application Support/org.hol.guard.desktop/core/versions/3.0.45/hol-guard",
    )
    monkeypatch.setattr(daemon_manager_module, "__version__", "3.0.45")
    daemon_manager_module.write_guard_daemon_state(
        guard_home,
        5530,
        "token-123",
        pid=12345,
    )
    monkeypatch.setattr(daemon_manager_module, "__version__", "3.0.46")
    monkeypatch.setattr(
        daemon_manager_module,
        "_current_guard_daemon_runtime_fingerprint",
        lambda: "pipx-runtime-fingerprint",
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(
        daemon_manager_module.urllib.request,
        "urlopen",
        lambda request, timeout=1: _HealthzResponse(),
    )

    assert daemon_manager_module.load_guard_daemon_url(guard_home) == "http://127.0.0.1:5530"


def test_load_guard_daemon_url_accepts_same_release_peer_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon_manager_module.write_guard_daemon_state(
        guard_home,
        5530,
        "token-123",
        pid=12345,
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_current_guard_daemon_runtime_fingerprint",
        lambda: "pipx-runtime-fingerprint",
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(
        daemon_manager_module.urllib.request,
        "urlopen",
        lambda request, timeout=1: _HealthzResponse(),
    )

    assert daemon_manager_module.load_guard_daemon_url(guard_home) == "http://127.0.0.1:5530"


def test_availability_watch_config_allows_git_and_network(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'mode = "observe"\nprotection_posture = "watch"\n',
        encoding="utf-8",
    )
    git_cmd = availability_harness_response(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "git status"}},
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        guard_home=guard_home,
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert git_cmd["decision"] == "allow"
    gh_cmd = availability_harness_response(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "gh pr view 1"}},
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        guard_home=guard_home,
    )
    assert gh_cmd["decision"] == "allow"


def test_cursor_fallback_watch_allows_shell() -> None:
    allow, code = cursor_fallback_permission(
        {"hook_event_name": "beforeShellExecution", "command": "rm -rf /"},
        hook_event_name="beforeShellExecution",
        recording_only=True,
    )
    assert code == 0
    assert allow["permission"] == "allow"


def test_watch_unavailable_pretool_records_command_activity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'mode = "observe"\nprotection_posture = "watch"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_mode",
        lambda: "auto",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    writer = MagicMock()
    worker = HookWorker(store=GuardStore(guard_home), activity_writer=writer)
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "git status"}},
        params={},
        default_harness="grok",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "allow"
    writer.submit_command_activity.assert_called_once()
    recorded = writer.submit_command_activity.call_args.kwargs
    assert recorded["event"] == "PreToolUse"
    assert recorded["succeeded"] is True


def test_watch_http_pretool_unavailable_records_command_activity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text(
        'mode = "observe"\nprotection_posture = "watch"\n',
        encoding="utf-8",
    )
    writer = MagicMock()
    worker = HookWorker(store=GuardStore(guard_home), activity_writer=writer)
    monkeypatch.setattr(worker, "_review_pre_tool_native", lambda *_args, **_kwargs: None)
    result = worker._review_pre_tool_http(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "git status"}},
        harness="grok",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "allow"
    writer.submit_command_activity.assert_called_once()
    recorded = writer.submit_command_activity.call_args.kwargs
    assert recorded["event"] == "PreToolUse"
    assert recorded["succeeded"] is True
