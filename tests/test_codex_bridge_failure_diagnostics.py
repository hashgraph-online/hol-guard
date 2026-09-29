"""Failure evidence must explain blocked launchers without exporting payloads."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge_flow as flow
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _DaemonResponseError
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from tests.codex_daemon_hook_bridge_fixtures import _bridge_config


@pytest.mark.parametrize("event", ["PreToolUse", "PermissionRequest"])
def test_unusable_managed_launcher_reports_both_causes_without_running_children(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    event: str,
) -> None:
    secret = "private-payload-must-never-be-in-diagnostics"
    config = _bridge_config(tmp_path / "guard-home", 1)
    config["manifest_path"] = tmp_path / "guard-home/managed/codex/hooks-fixture.manifest.json"
    config["config_json"] = secret
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": event,
                    "tool_name": "Bash",
                    "tool_input": {"command": secret},
                }
            )
        ),
    )

    def unavailable(**_kwargs):
        raise urllib.error.URLError(secret)

    def invalid_launcher(**_kwargs):
        raise ValueError("managed Codex hook bridge path is invalid")

    def unexpected_child(*_args, **_kwargs):
        pytest.fail("An unauthenticated launcher must never execute a child")

    monkeypatch.setattr(flow, "_daemon_response", unavailable)
    monkeypatch.setattr(flow, "trusted_hook_launch", invalid_launcher)
    monkeypatch.setattr(flow, "_run_daemon_start", unexpected_child)
    monkeypatch.setattr(flow, "_run_local_fallback", unexpected_child)

    assert bridge.main(**config) == 0
    captured = capsys.readouterr()
    decision = json.loads(captured.out)["hookSpecificOutput"]
    if event == "PreToolUse":
        assert decision["permissionDecision"] == "deny"
    else:
        assert decision["decision"]["behavior"] == "deny"
    evidence = json.loads(captured.err)
    assert evidence["schema"] == "hol-guard.codex-bridge-failure.v1"
    assert evidence["causes"] == [
        {"stage": "daemon_request", "reason_code": "daemon_transport_unavailable"},
        {"stage": "launcher_validation", "reason_code": "launcher_bridge_path_mismatch"},
    ]
    assert secret not in captured.err
    assert str(tmp_path) not in captured.err


@pytest.mark.parametrize(
    ("validation_error", "reason"),
    [
        (ValueError("sensitive-key-file-and-token"), "launcher_validation_failed"),
        (ValueError("managed Codex hook launch identity is invalid"), "launcher_launch_identity_invalid"),
        (ValueError("managed Codex hook event identity is invalid"), "launcher_event_identity_invalid"),
        (
            ValueError("managed Codex hook bridge compatibility identity is invalid"),
            "launcher_compatibility_identity_invalid",
        ),
        (ValueError("managed Codex hook bridge config is malformed"), "launcher_config_malformed"),
        (
            ValueError("managed Codex hook runtime directory is not owner-only"),
            "launcher_runtime_directory_permissions_unsafe",
        ),
        (TypeError("sensitive-key-file-and-token"), "launcher_authority_unavailable"),
        (AttributeError("sensitive-key-file-and-token"), "launcher_authority_unavailable"),
    ],
)
def test_validation_failure_preserves_specific_causes_and_redacts_unknown_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    validation_error: Exception,
    reason: str,
) -> None:
    config = _bridge_config(tmp_path / "guard-home", 1)
    config["manifest_path"] = tmp_path / "guard-home/managed/codex/hooks-fixture.manifest.json"
    config["config_json"] = "fixture"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    def unavailable(**_kwargs):
        raise ConnectionRefusedError("sensitive-daemon-endpoint")

    def invalid_launcher(**_kwargs):
        raise validation_error

    monkeypatch.setattr(flow, "_daemon_response", unavailable)
    monkeypatch.setattr(flow, "trusted_hook_launch", invalid_launcher)
    assert bridge.main(**config) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(captured.err)["causes"] == [
        {"stage": "daemon_request", "reason_code": "daemon_connection_refused"},
        {"stage": "launcher_validation", "reason_code": reason},
    ]
    assert "sensitive" not in captured.err


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (_DaemonResponseError(403, "private-detail", authenticated=False), "daemon_response_unauthenticated"),
        (_DaemonResponseError(403, "private-detail", authenticated=True), "daemon_authenticated_http_error"),
        (ValueError("daemon identity challenge authentication failed"), "daemon_challenge_authentication_failed"),
        (TimeoutError("private-endpoint"), "daemon_transport_timeout"),
    ],
)
def test_daemon_failure_categories_preserve_authentication_boundary(error, reason) -> None:
    assert flow._daemon_failure_reason(error) == reason


@pytest.mark.parametrize(
    "reason",
    [
        "codex_hook_file_identity_invalid",
        "codex_hook_manifest_missing",
        "codex_hook_manifest_mac_invalid",
        "codex_hook_manifest_authentication_missing",
    ],
)
def test_existing_integrity_reason_survives_without_exception_detail(reason: str) -> None:
    error = CodexHookIntegrityError(reason, "private-file-detail")
    assert flow._launcher_failure_reason(error) == reason
    error.reason = "private-unrecognized-reason"
    assert flow._launcher_failure_reason(error) == "launcher_authority_unavailable"


def test_recovered_daemon_does_not_emit_incident_noise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0

    def daemon_response(**_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionRefusedError("private-endpoint")
        return {}

    monkeypatch.setattr(flow, "_daemon_response", daemon_response)
    monkeypatch.setattr(flow, "_run_daemon_start", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))
    assert bridge.main(**_bridge_config(tmp_path / "guard-home", 1)) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {}
    assert captured.err == ""


@pytest.mark.parametrize("failure", ["broken_sink", "unserializable_cause"])
def test_diagnostic_failure_preserves_denial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    class BrokenSink:
        def write(self, _text):
            raise BrokenPipeError("sink unavailable")

    def unavailable(**_kwargs):
        raise ConnectionRefusedError("unavailable")

    def invalid_launcher(**_kwargs):
        raise ValueError("managed Codex hook bridge path is invalid")

    config = _bridge_config(tmp_path / "guard-home", 1)
    config["manifest_path"] = tmp_path / "guard-home/managed/codex/hooks-fixture.manifest.json"
    config["config_json"] = "fixture"
    monkeypatch.setattr(flow, "_daemon_response", unavailable)
    monkeypatch.setattr(flow, "trusted_hook_launch", invalid_launcher)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))
    if failure == "broken_sink":
        monkeypatch.setattr("sys.stderr", BrokenSink())
    else:
        monkeypatch.setattr(flow, "_record_failure", lambda causes, *_args: causes.append(object()))
    assert bridge.main(**config) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"
