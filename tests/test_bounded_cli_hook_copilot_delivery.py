"""Copilot registered bridge delivery, independent of daemon JSON envelopes."""

from __future__ import annotations

import io
import json
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_support_prompts import _emit_copilot_hook_response
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from scripts.native_slo_registered_surfaces import install_registered_surface


@pytest.mark.parametrize("event", ("PreToolUse", "preToolUse", "PostToolUse", "postToolUse"))
@pytest.mark.parametrize("action", ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block"))
def test_copilot_bridge_matches_published_cli_emitter(event: str, action: str) -> None:
    denied = action not in {"allow", "warn"}
    reason = "  Original Guard reason: fixture snow 雪.  "
    response: dict[str, object] = {
        "policy_action": action,
        "reason_code": "synthetic_case",
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse" if event.lower().startswith("post") else "PreToolUse",
            "permissionDecision": "deny" if denied else "allow",
            "permissionDecisionReason": reason,
        },
        "approval_reuse": {"status": "not_applicable"},
        "scanner_evidence": [{"source": "synthetic"}],
    }
    original = json.dumps(response, sort_keys=True)
    stdout, stderr, code = daemon._daemon_response_to_native(response, harness="copilot", event_name=event)
    expected = io.StringIO()
    _emit_copilot_hook_response(
        policy_action=action,
        reason=reason,
        approval_reuse={"status": "not_applicable"},
        scanner_evidence=({"source": "synthetic"},),
        output_stream=expected,
    )
    assert json.loads(stdout) == json.loads(expected.getvalue())
    assert json.dumps(response, sort_keys=True) == original
    assert (stderr, code) == ("", 0)


@pytest.mark.parametrize("event", ("PreToolUse", "PostToolUse"))
@pytest.mark.parametrize(
    "response",
    (
        {"policy_action": "block", "permissionDecision": "allow"},
        {"policy_action": "review", "decision": "allow"},
        {"policy_action": "allow", "decision": "deny"},
        {"policy_action": "allow", "hookSpecificOutput": {"permissionDecision": "deny"}},
        {"policy_action": "allow", "hookSpecificOutput": {"permissionDecision": "ask"}},
        {"policy_action": "allow", "permissionDecision": "deny"},
        {"policy_action": "allow", "model_output_action": "block"},
        {"policy_action": "invalid", "permissionDecision": "allow"},
        {"policy_action": [], "permissionDecision": "allow"},
        {"permissionDecision": {}},
        {"hookSpecificOutput": {"additionalContext": "no decision"}},
        {"decision": {}},
        {},
    ),
)
def test_denial_and_ambiguous_authority_are_not_weakened(event: str, response: dict[str, object]) -> None:
    stdout, stderr, code = daemon._daemon_response_to_native(response, harness="copilot", event_name=event)
    payload = json.loads(stdout)
    assert payload["permissionDecision"] == "deny"
    assert payload["permissionDecisionReason"]
    assert set(payload) == {"permissionDecision", "permissionDecisionReason"}
    assert (stderr, code) == ("", 0)


@pytest.mark.parametrize("event", ("PreToolUse", "PostToolUse"))
def test_existing_native_allow_and_availability_reason_remain_intact(event: str) -> None:
    original: dict[str, object] = {
        "permissionDecision": "allow",
        "permissionDecisionReason": "Original availability notice.",
    }
    stdout, stderr, code = daemon._daemon_response_to_native(original, harness="copilot", event_name=event)
    assert json.loads(stdout) == original
    assert (stderr, code) == ("", 0)


def test_watch_post_does_not_promote_observed_block_to_effective_denial() -> None:
    response: dict[str, object] = {
        "policy_action": "warn",
        "observed_policy_action": "block",
        "observe_mode": True,
        "model_output_action": "allow_original",
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
    }
    stdout, stderr, code = daemon._daemon_response_to_native(response, harness="copilot", event_name="PostToolUse")
    assert json.loads(stdout) == {"permissionDecision": "allow"}
    assert (stderr, code) == ("", 0)


def test_post_block_emits_only_observational_native_fields_and_original_reason() -> None:
    stdout, stderr, code = daemon._daemon_response_to_native(
        {
            "policy_action": "block",
            "decision": "block",
            "model_output_action": "block",
            "continue": True,
            "reason": "Original output reason.",
            "reason_code": "output_secret_match",
            "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        },
        harness="copilot",
        event_name="PostToolUse",
    )
    assert json.loads(stdout) == {"permissionDecision": "deny", "permissionDecisionReason": "Original output reason."}
    assert (stderr, code) == ("", 0)


def test_permission_request_uses_existing_separate_contract() -> None:
    original: dict[str, object] = {
        "policy_action": "block",
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny"},
            "permissionDecision": "deny",
        },
    }
    stdout, stderr, code = daemon._daemon_response_to_native(
        original, harness="copilot", event_name="PermissionRequest"
    )
    assert json.loads(stdout) == original
    assert (stderr, code) == ("", 0)


@pytest.mark.parametrize("event", ("preToolUse", "postToolUse"))
@pytest.mark.parametrize("use_daemon", (True, False))
@pytest.mark.parametrize("action", ("allow", "block"))
def test_actual_registered_cli_entrypoint_delivers_native_json_on_both_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: str,
    use_daemon: bool,
    action: str,
) -> None:
    home = tmp_path / "home with spaces '雪"
    workspace = home / "workspace"
    guard_home = home / "guard-home"
    workspace.mkdir(parents=True)
    guard_home.mkdir()
    context = HarnessContext(home, workspace, guard_home)
    surfaces = install_registered_surface(context, "copilot")
    surface = next(item for item in surfaces if item.event == event and item.scope == "project")
    config = json.loads(surface.argv[-1])
    reason = "Original policy reason."
    body = json.dumps(
        {
            "policy_action": action,
            "reason": reason,
            "hookSpecificOutput": {"hookEventName": "PreToolUse" if event == "preToolUse" else "PostToolUse"},
        }
    ).encode()

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
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(request.full_url)
            assert (parsed.scheme, parsed.netloc, parsed.path) == ("http", "127.0.0.1:7777", "/v1/hooks/copilot")
            assert parse_qs(parsed.query) == {
                "guard-home": [str(guard_home)],
                "home": [str(home)],
                "workspace": [str(workspace)],
            }
            assert timeout <= 5
            assert isinstance(request.data, bytes) and json.loads(request.data)["hook_event_name"] == event
            return Response()

    if use_daemon:
        monkeypatch.setattr(daemon, "_daemon_hook_endpoint", lambda *_args: "http://127.0.0.1:7777/v1/hooks/copilot")
        monkeypatch.setattr(daemon, "_read_daemon_auth_token", lambda *_args: "synthetic-token")
        monkeypatch.setattr(
            daemon, "_build_loopback_opener", lambda: cast(urllib.request.OpenerDirector, cast(object, Opener()))
        )

        def unexpected_fallback(*_args: object, **_kwargs: object) -> BoundedHookProcessResult:
            raise AssertionError("registered bridge unexpectedly left daemon route")

        monkeypatch.setattr(bridge, "run_isolated_hook_process", unexpected_fallback)
    else:
        monkeypatch.setattr(daemon, "try_daemon_hook", lambda **_kwargs: None)
        monkeypatch.setattr(
            bridge,
            "run_isolated_hook_process",
            lambda *_args, **_kwargs: BoundedHookProcessResult(
                0,
                body.decode(),
                False,
                False,
            ),
        )
    stdout, stderr = io.StringIO(), io.StringIO()
    # Exercise the real entry function with configuration read from the actual
    # installed registration. Only transport responses are synthetic; this is
    # not reported as a live socket or installed child-process qualification.
    with redirect_stdout(stdout), redirect_stderr(stderr):
        result = bridge.run_bounded_cli_hook(config, input_text=json.dumps({"hook_event_name": event}))
    expected: dict[str, object] = {"permissionDecision": "allow" if action == "allow" else "deny"}
    if action == "block":
        expected["permissionDecisionReason"] = reason
    assert json.loads(stdout.getvalue()) == expected
    assert (result, stderr.getvalue()) == (0, "")


@pytest.mark.parametrize("returncode", (1, 2, -9))
def test_fallback_error_exit_is_not_masked_by_a_native_allow_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
) -> None:
    from tests.bounded_cli_hook_test_support import config

    monkeypatch.setattr(daemon, "try_daemon_hook", lambda **_kwargs: None)
    monkeypatch.setattr(
        bridge,
        "run_isolated_hook_process",
        lambda *_args, **_kwargs: BoundedHookProcessResult(
            returncode,
            '{"permissionDecision":"allow"}',
            False,
            False,
        ),
    )
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        result = bridge.run_bounded_cli_hook(
            config(tmp_path, harness="copilot"),
            input_text='{"hook_event_name":"preToolUse"}',
        )
    assert json.loads(stdout.getvalue()) == {"permissionDecision": "allow"}
    assert result == returncode
