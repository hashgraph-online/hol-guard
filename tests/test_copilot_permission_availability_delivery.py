"""Copilot permission availability must survive the registered command bridge."""

from __future__ import annotations

import io
import json
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlsplit

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter
from codex_plugin_scanner.guard.daemon.hook_availability_policy import availability_harness_response
from scripts.native_slo_registered_surfaces import _registered, install_registered_surface


@pytest.mark.parametrize("event", ("permissionRequest", "permissionRequestV2"))
def test_actual_permission_availability_producer_keeps_native_deny_handoff(event: str) -> None:
    reason = "HOL Guard could not classify this hook event safely."
    response = availability_harness_response(
        {"hookName": event, "toolName": "Bash", "toolInput": {"command": "pwd"}},
        harness="copilot",
        event_name=event,
        reason_code="native_hook_event_unavailable",
        reason=reason,
    )
    assert response == {
        "behavior": "deny",
        "message": reason,
        "interrupt": False,
        "reason_code": "native_hook_event_unavailable",
    }
    before = json.dumps(response, sort_keys=True)
    stdout, stderr, code = daemon._daemon_response_to_native(response, harness="copilot", event_name=event)
    assert json.loads(stdout) == response
    assert (stderr, code) == ("", 0)
    assert json.dumps(response, sort_keys=True) == before


@pytest.mark.parametrize("event", ("PermissionRequest", "permissionRequestV2", "copilot_permission_request"))
@pytest.mark.parametrize("interrupt", (False, True))
@pytest.mark.parametrize("policy", ("allow", "warn", "block"))
def test_explicit_native_permission_denial_is_never_promoted(event: str, interrupt: bool, policy: str) -> None:
    response: dict[str, object] = {
        "behavior": "deny",
        "message": "Original permission explanation: 雪.",
        "interrupt": interrupt,
        "reason_code": "native_hook_event_unavailable",
        "policy_action": policy,
    }
    stdout, stderr, code = daemon._daemon_response_to_native(response, harness="copilot", event_name=event)
    assert json.loads(stdout) == response
    assert (stderr, code) == ("", 0)


@pytest.mark.parametrize("event", ("PreToolUse", "PostToolUse"))
def test_permission_branch_does_not_change_copilot_command_events(event: str) -> None:
    stdout, stderr, code = daemon._daemon_response_to_native(
        {"policy_action": "block", "behavior": "deny", "message": "permission-only field"},
        harness="copilot",
        event_name=event,
    )
    result = json.loads(stdout)
    assert result["permissionDecision"] == "deny"
    assert "behavior" not in result
    assert (stderr, code) == ("", 0)


def test_permission_branch_does_not_change_other_harness_contract() -> None:
    response = availability_harness_response(
        {},
        harness="claude-code",
        event_name="PermissionRequest",
        reason_code="native_hook_event_unavailable",
        reason="Original availability explanation.",
    )
    stdout, stderr, code = daemon._daemon_response_to_native(
        response, harness="claude-code", event_name="PermissionRequest"
    )
    assert json.loads(stdout) == response
    assert (stderr, code) == ("", 0)


@pytest.mark.parametrize("harness", ("claude-code", "codex", "grok"))
def test_native_copilot_denial_is_not_forwarded_as_another_harness_shape(harness: str) -> None:
    stdout, stderr, code = daemon._daemon_response_to_native(
        {"behavior": "deny", "message": "Native Copilot only.", "interrupt": False, "policy_action": "block"},
        harness=harness,
        event_name="PermissionRequest",
    )
    response = json.loads(stdout)
    assert "behavior" not in response
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert (stderr, code) == ("", 0)


@pytest.mark.parametrize(
    "body",
    (b"[]", b"null", b'"deny"', b"false", b"{", b"\xff"),
    ids=("list", "null", "text", "bool", "invalid-json", "invalid-utf8"),
)
def test_permission_transport_rejects_malformed_and_nonobject_body(tmp_path: Path, body: bytes) -> None:
    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self, limit: int) -> bytes:
            assert limit == 1_000_001
            return body

        def geturl(self) -> str:
            return "http://127.0.0.1:7777/v1/hooks/copilot"

    class Opener:
        def open(self, _request: urllib.request.Request, *, timeout: float) -> Response:
            assert 0 < timeout <= 5
            return Response()

    assert (
        daemon.try_daemon_hook(
            guard_home=tmp_path,
            harness="copilot",
            input_text='{"hookName":"permissionRequestV2"}',
            timeout_seconds=25,
            _endpoint_loader=lambda *_args: "http://127.0.0.1:7777/v1/hooks/copilot",
            _token_loader=lambda *_args: "synthetic-token",
            _opener_builder=lambda: cast(urllib.request.OpenerDirector, cast(object, Opener())),
        )
        is None
    )


@pytest.mark.parametrize("scope", ("global", "project"))
@pytest.mark.parametrize("event", ("permissionRequest", "permissionRequestV2"))
def test_real_registered_permission_entry_preserves_actual_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: str, event: str
) -> None:
    """Real registration/entry; transport alone is modeled, not installed proof."""
    home, workspace, guard_home = (tmp_path / name for name in ("home with spaces 雪", "workspace", "guard-home"))
    for path in (home, workspace, guard_home):
        path.mkdir()
    context = HarnessContext(home, workspace, guard_home)
    install_registered_surface(context, "copilot")
    config_path = (
        CopilotHarnessAdapter._config_path(context) if scope == "global" else CopilotHarnessAdapter._hook_path(context)
    )
    assert config_path is not None
    surface = _registered(context, "copilot", event, scope, config_path)
    config = json.loads(surface.argv[-1])
    payload = {"hookName": event, "toolName": "Bash", "toolInput": {"command": "pwd"}}
    response = availability_harness_response(
        payload,
        harness="copilot",
        event_name=event,
        reason_code="native_hook_event_unavailable",
        reason="Original availability explanation.",
    )
    body = json.dumps(response).encode()
    offered: list[object] = []

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self, limit: int) -> bytes:
            assert limit == 1_000_001
            return body

        def geturl(self) -> str:
            return "http://127.0.0.1:7777/v1/hooks/copilot"

    class Opener:
        def open(self, request: urllib.request.Request, *, timeout: float) -> Response:
            parsed = urlsplit(request.full_url)
            assert (parsed.scheme, parsed.netloc, parsed.path) == ("http", "127.0.0.1:7777", "/v1/hooks/copilot")
            expected_context = {
                "guard-home": [str(guard_home)],
                "home": [str(home)],
            }
            if scope == "project":
                expected_context["workspace"] = [str(workspace)]
            assert parse_qs(parsed.query) == expected_context
            assert isinstance(request.data, bytes) and json.loads(request.data) == payload
            assert 0 < timeout <= 5
            offered.append(payload)
            return Response()

    monkeypatch.setattr(daemon, "_daemon_hook_endpoint", lambda *_args: "http://127.0.0.1:7777/v1/hooks/copilot")
    monkeypatch.setattr(daemon, "_read_daemon_auth_token", lambda *_args: "synthetic-token")
    monkeypatch.setattr(
        daemon, "_build_loopback_opener", lambda: cast(urllib.request.OpenerDirector, cast(object, Opener()))
    )

    def unexpected_fallback(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("permission handoff unexpectedly left daemon route")

    monkeypatch.setattr(bridge, "run_isolated_hook_process", unexpected_fallback)
    stdout, stderr = io.StringIO(), io.StringIO()
    before = config_path.read_bytes()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = bridge.run_bounded_cli_hook(config, input_text=json.dumps(payload))
    assert offered == [payload]
    assert json.loads(stdout.getvalue()) == response
    assert (stderr.getvalue(), code) == ("", 0)
    assert config_path.read_bytes() == before
