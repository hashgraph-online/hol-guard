from __future__ import annotations

import importlib.util
import io
import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script


def _load_script(tmp_path: Path, *, harness: str, timeout_seconds: float = 8) -> ModuleType:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True, exist_ok=True)
    guard_home.chmod(0o700)
    source = _render_bounded_hook_script(
        guard_home=guard_home,
        harness=harness,
        timeout_seconds=timeout_seconds,
    )
    assert "daemon --serve" not in source
    path = guard_home / f"{harness}.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(f"generated_{harness}_hook", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_daemon_files(module: ModuleType, *, host: str, port: int, token: str = "token") -> None:
    home = Path(module.GUARD_HOME)
    state = home / "daemon-state.json"
    auth = home / "daemon-auth-token"
    state.write_text(json.dumps({"host": host, "port": port}), encoding="utf-8")
    auth.write_text(token, encoding="utf-8")
    state.chmod(0o600)
    auth.chmod(0o600)


def _serve(
    responses: dict[tuple[str, str], dict[str, Any] | tuple[int, dict[str, Any]]],
) -> tuple[str, int, ThreadingHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def _reply(self, method: str) -> None:
            payload = responses.get((method, self.path))
            if payload is None:
                self.send_response(404)
                self.end_headers()
                return
            status = 200
            body = payload
            if isinstance(payload, tuple):
                status, body = payload
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            self._reply("GET")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self._reply("POST")

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    host, port = sock.getsockname()
    sock.close()
    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return host, port, server


@pytest.mark.parametrize("event_name", ["PermissionRequest", "permissionRequestV2"])
def test_generated_client_canonicalizes_copilot_permission_events(
    tmp_path: Path,
    event_name: str,
) -> None:
    module = _load_script(tmp_path, harness="copilot")
    assert module._event_name(json.dumps({"hook_event_name": event_name})) == "PermissionRequest"


def test_generated_client_stamps_outer_environment_before_daemon_forwarding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script(tmp_path, harness="zcode")
    monkeypatch.setenv("PATH", "/frozen/outer/bin")
    monkeypatch.setenv("HOME", "/frozen/outer/home")
    monkeypatch.setenv("GIT_PAGER", "cat")
    monkeypatch.setenv("PAGER", "")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "true")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "frozen-caller-secret-not-serialized")

    forwarded = module._stamp_hook_input(
        json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "guard_execution_environment": {"path": "/model-supplied"},
            }
        )
    )
    payload = json.loads(forwarded)
    context = payload["guard_execution_environment"]
    assert context["path"] == "/frozen/outer/bin"
    assert context["home"] == "/frozen/outer/home"
    assert context["git_pager_disabled"] is True
    assert context["pager_disabled"] is True
    assert context["git_config_no_system"] is True
    assert context["path"] != "/model-supplied"
    assert "GIT_EXTERNAL_DIFF" in context["environment_names"]
    assert context["environment_digest"]
    assert "frozen-caller-secret-not-serialized" not in forwarded


@pytest.mark.parametrize(
    "event_name",
    [
        "UserPromptSubmit",
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "SubagentStop",
        "PostToolUse",
        "PermissionDenied",
    ],
)
def test_generated_client_keeps_empty_grok_observe_response(tmp_path: Path, event_name: str) -> None:
    module = _load_script(tmp_path, harness="grok")
    stdout, stderr, code = module._to_native({}, event_name)
    assert json.loads(stdout) == {}
    assert stderr == ""
    assert code == 0


@pytest.mark.parametrize("event_name", ["SessionStart", "UserPromptSubmit", "PreToolUse"])
def test_generated_client_runs_under_macos_system_python(tmp_path: Path, event_name: str) -> None:
    if sys.platform != "darwin" or not Path("/usr/bin/python3").is_file():
        pytest.skip("macOS system Python compatibility")
    module = _load_script(tmp_path, harness="grok")
    completed = subprocess.run(
        ["/usr/bin/python3", "-I", module.__file__],
        input=json.dumps({"hook_event_name": event_name}),
        text=True,
        capture_output=True,
        timeout=5,
    )
    response = json.loads(completed.stdout)
    assert "Traceback" not in completed.stderr
    if event_name == "PreToolUse":
        assert response["decision"] == "deny"
    elif event_name == "UserPromptSubmit":
        assert response["decision"] == "block"
    else:
        assert response == {}
        assert completed.returncode == 0


@pytest.mark.parametrize("events", [("post_tool_use", "PreToolUse"), ("pre_tool_use", "PostToolUse")])
def test_generated_grok_client_denies_conflicting_pretool_labels(tmp_path: Path, events) -> None:
    module = _load_script(tmp_path, harness="grok")
    system_python = sys.platform == "darwin" and Path("/usr/bin/python3").is_file()
    interpreter = "/usr/bin/python3" if system_python else sys.executable
    completed = subprocess.run(
        [interpreter, "-I", module.__file__],
        input=json.dumps({"hookEventName": events[0], "hook_event_name": events[1]}),
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert json.loads(completed.stdout)["decision"] == "deny"
    assert "conflict" in completed.stdout


@pytest.mark.parametrize("event_name", ["SessionStart", "UserPromptSubmit", "PreToolUse"])
def test_generated_grok_observer_has_short_transport_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_name: str,
) -> None:
    module = _load_script(tmp_path, harness="grok", timeout_seconds=85)
    monkeypatch.setattr(module, "_daemon_auth", lambda: ("127.0.0.1", 9, "fixture"))
    budgets = []

    def unavailable(*args, **kwargs):
        budgets.append(kwargs["timeout"])
        return None

    monkeypatch.setattr(module, "_http_json", unavailable)
    assert module._post_hook(json.dumps({"hook_event_name": event_name})) is None
    expected = {"SessionStart": 1.0, "UserPromptSubmit": 10.0, "PreToolUse": 5.0}
    assert budgets == pytest.approx([expected[event_name]], abs=0.01)


def test_generated_client_copies_grok_approval_metadata(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="grok")
    stdout, _stderr, code = module._to_native(
        {
            "policy_action": "review",
            "reason": "needs review",
            "reason_code": "review_required",
            "approval_url": "http://127.0.0.1:9/approve",
            "approval_request_id": "req-1",
            "primary_approval_request_id": "req-1",
            "primary_approval_url": "http://127.0.0.1:9/approve",
            "guardApprovalRequestId": "req-1",
            "guardApprovalUrl": "http://127.0.0.1:9/approve",
            "approval_requests": [{"request_id": "req-1"}],
        },
        "PreToolUse",
    )
    payload = json.loads(stdout)
    assert code == 2
    assert payload["decision"] == "deny"
    assert payload["approval_request_id"] == "req-1"
    assert payload["primary_approval_request_id"] == "req-1"
    assert payload["approval_requests"] == [{"request_id": "req-1"}]
    assert payload["reason_code"] == "review_required"


def test_generated_client_emits_hermes_native_decision(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="hermes")
    stdout, stderr, code = module._to_native(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "blocked",
            },
            "policy_action": "block",
        },
        "PreToolUse",
    )
    assert json.loads(stdout) == {"decision": "block", "reason": "blocked"}
    assert stderr == ""
    assert code == 2


def test_generated_client_defaults_missing_policy_action_closed(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="kimi")
    _stdout, _stderr, code = module._to_native(
        {
            "decision": "deny",
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
        },
        "PreToolUse",
    )
    assert code == 2


@pytest.mark.parametrize(
    ("harness", "event_name", "decision", "code"),
    [
        ("grok", "PreToolUse", "deny", 0),
        ("hermes", "PreToolUse", "block", 2),
        ("openclaw", "PreToolUse", "deny", 0),
        ("copilot", "PreToolUse", None, 0),
        ("zcode", "PreToolUse", None, 2),
        ("kimi", "PreToolUse", None, 2),
        ("devin", "PreToolUse", None, 2),
        ("grok", "PostToolUse", None, 0),
        ("copilot", "permissionRequestV2", None, 0),
    ],
)
def test_generated_client_unavailable_payload_matches_harness(
    tmp_path: Path,
    harness: str,
    event_name: str,
    decision: str | None,
    code: int,
) -> None:
    module = _load_script(tmp_path, harness=harness)
    payload, exit_code = module._failure_payload(
        module._event_name(json.dumps({"hook_event_name": event_name})), "down"
    )
    assert exit_code == code
    if harness == "grok" and event_name == "PostToolUse":
        assert payload == {}
    if decision is not None:
        assert payload["decision"] == decision
    if harness == "copilot" and event_name == "permissionRequestV2":
        assert payload["behavior"] == "deny"
    if harness in {"zcode", "devin"}:
        assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("harness", ("claude-code", "codex", "copilot", "grok"))
def test_generated_client_prompt_unavailability_matches_host_contract(tmp_path: Path, harness: str) -> None:
    module = _load_script(tmp_path, harness=harness)
    payload, code = module._failure_payload("UserPromptSubmit", "Native prompt review unavailable.")
    assert code == 0
    if harness == "copilot":
        assert payload["behavior"] == "deny"
    else:
        assert payload["decision"] == "block"
        if harness == "codex":
            assert payload["continue"] is False


def test_generated_client_unacknowledged_watch_cannot_allow_pretool(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="grok")
    config = Path(module.GUARD_HOME) / "config.toml"
    config.write_text('protection_posture = "watch"\nmode = "observe"\n', encoding="utf-8")
    config.chmod(0o600)
    payload, code = module._failure_payload("PreToolUse", "down")
    assert code == 0
    assert payload == {"decision": "deny", "reason": "down"}


def test_generated_client_rejects_symlinked_daemon_token(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="grok")
    home = Path(module.GUARD_HOME)
    leaked = tmp_path / "leaked-token"
    leaked.write_text("stolen", encoding="utf-8")
    leaked.chmod(0o600)
    token = home / "daemon-auth-token"
    token.symlink_to(leaked)
    state = home / "daemon-state.json"
    state.write_text(json.dumps({"host": "127.0.0.1", "port": 9}), encoding="utf-8")
    state.chmod(0o600)
    assert module._daemon_auth() is None


def test_generated_client_waits_for_grok_approval_over_http(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="grok", timeout_seconds=8)
    host, port, server = _serve(
        {
            ("POST", "/v1/hooks/grok"): {
                "policy_action": "review",
                "reason": "needs review",
                "primary_approval_request_id": "req-1",
                "approval_requests": [{"request_id": "req-1"}],
            },
            ("GET", "/v1/requests/req-1"): {"resolution_action": "allow"},
        }
    )
    try:
        _write_daemon_files(module, host=host, port=port)
        stdin = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Write"})
        stdout, _stderr, code = module._post_hook(stdin)
    finally:
        server.shutdown()
        server.server_close()
    assert code == 0
    assert json.loads(stdout)["decision"] == "allow"
    assert json.loads(stdout)["policy_action"] == "allow"


def test_generated_client_main_uses_unavailable_matrix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_script(tmp_path, harness="grok")
    stdin = io.BytesIO(b'{"hook_event_name":"SessionStart"}')
    monkeypatch.setattr(module.sys, "stdin", stdin)
    monkeypatch.setattr(stdin, "buffer", stdin, raising=False)
    stdout = io.StringIO()
    monkeypatch.setattr(module.sys, "stdout", stdout)
    assert module.main() == 0
    assert json.loads(stdout.getvalue()) == {}


def test_generated_zcode_review_pretool_exits_zero_with_ask(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="zcode")
    stdout, stderr, code = module._to_native(
        {
            "policy_action": "review",
            "reason": "Approval required.",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "Approval required.",
            },
        },
        "PreToolUse",
    )
    payload = json.loads(stdout)

    assert code == 0
    assert stderr == ""
    assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_generated_zcode_block_pretool_exits_two_with_stderr_reason(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="zcode")
    stdout, stderr, code = module._to_native(
        {
            "policy_action": "block",
            "reason": "Blocked by policy.",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Blocked by policy.",
            },
        },
        "PreToolUse",
    )
    payload = json.loads(stdout)

    assert code == 2
    assert stderr == "Blocked by policy."
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_generated_zcode_authority_block_stderr_appends_remediation(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="zcode")
    _stdout, stderr, code = module._to_native(
        {
            "policy_action": "block",
            "reason": "HOL Guard requires the native command extension policy before this action can execute.",
            "hookSpecificOutput": {"hookEventName": "PreToolUse"},
        },
        "PreToolUse",
    )

    assert code == 2
    assert "hol-guard command controls recover-authority" in stderr


def test_generated_zcode_sandbox_required_denies_with_exit_two(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="zcode")
    stdout, stderr, code = module._to_native(
        {"policy_action": "sandbox-required", "reason": "Sandbox required."}, "PreToolUse"
    )
    payload = json.loads(stdout)

    assert code == 2
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert stderr == "Sandbox required."


def test_generated_zcode_block_without_reason_writes_stderr(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="zcode")
    _stdout, stderr, code = module._to_native({"policy_action": "block"}, "PreToolUse")

    assert code == 2
    assert stderr.startswith("HOL Guard blocked this action")


def test_generated_zcode_prompt_block_keeps_exit_two(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="zcode")
    _stdout, _stderr, code = module._to_native(
        {"policy_action": "review", "reason": "Prompt review."}, "UserPromptSubmit"
    )
    assert code == 2


def test_generated_client_devin_permission_request_review_blocks(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="devin")
    stdout, _stderr, code = module._to_native(
        {"policy_action": "review", "reason": "Needs review."},
        "PermissionRequest",
    )
    payload = json.loads(stdout)
    assert code == 2
    assert payload["decision"] == "block"
    assert payload["reason"]


def test_generated_client_devin_pretooluse_allow_has_no_decision(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="devin")
    stdout, _stderr, code = module._to_native(
        {"policy_action": "allow", "reason": "Allowed."},
        "PreToolUse",
    )
    payload = json.loads(stdout)
    assert code == 0
    assert "decision" not in payload
