from __future__ import annotations

import importlib.util
import io
import json
import os
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
from codex_plugin_scanner.guard.hook_execution_environment import LIBRARY_SEARCH_PATH_NAMES


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
    for name in LIBRARY_SEARCH_PATH_NAMES:
        monkeypatch.delenv(name, raising=False)

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
    assert context["library_search_paths"] == {}


def test_generated_client_stamps_loader_search_path_values_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script(tmp_path, harness="zcode")
    for name in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/usr/local/cuda/lib64:/usr/lib")
    monkeypatch.setenv("DYLD_LIBRARY_PATH", "")
    monkeypatch.setenv("LD_PRELOAD", "/synthetic/preload-not-serialized.so")

    forwarded = module._stamp_hook_input(json.dumps({"hook_event_name": "PreToolUse"}))
    context = json.loads(forwarded)["guard_execution_environment"]
    assert context["library_search_paths"] == {"LD_LIBRARY_PATH": "/usr/local/cuda/lib64:/usr/lib"}
    assert "LD_PRELOAD" in context["environment_names"]
    assert "preload-not-serialized" not in forwarded
    monkeypatch.setenv("LD_LIBRARY_PATH", "/usr/lib/\udcff")
    surrogate = json.loads(module._stamp_hook_input(json.dumps({"hook_event_name": "PreToolUse"})))
    assert surrogate["guard_execution_environment"]["library_search_paths"] == {}
    assert "LD_LIBRARY_PATH" in surrogate["guard_execution_environment"]["environment_names"]


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


def test_generated_muse_review_pretool_denies_on_exit_zero(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="muse")
    stdout, stderr, code = module._to_native(
        {"policy_action": "review", "reason": "Approval required."},
        "PreToolUse",
    )
    payload = json.loads(stdout)

    # Muse reads an ask envelope as no decision and runs the tool.
    assert code == 0
    assert stderr == ""
    assert payload["decision"] == "deny"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_generated_muse_allow_is_silent(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="muse")

    # Muse rejects an envelope that says allow without the reviewed input, so
    # a permitted call is empty stdout on exit 0.
    assert module._to_native({"policy_action": "allow", "reason": ""}, "PreToolUse") == ("", "", 0)
    assert module._to_native({"policy_action": "warn", "reason": "noted"}, "PreToolUse") == ("", "", 0)


def test_generated_muse_permission_request_defers_to_muse_prompt(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="muse")

    # Muse raises its own prompt for a call its PreToolUse hook already sent
    # to Guard; that verdict, not this one, is the decision boundary.
    assert module._to_native({"policy_action": "review", "reason": "x"}, "PermissionRequest") == ("", "", 0)

    stdout, stderr, code = module._to_native({"policy_action": "block", "reason": "denied"}, "PermissionRequest")
    assert (stderr, code) == ("", 0)
    assert json.loads(stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_generated_muse_observation_event_carries_context_not_a_verdict(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="muse")

    stdout, stderr, code = module._to_native({"policy_action": "block", "reason": "ran anyway"}, "PostToolUse")
    payload = json.loads(stdout)

    assert (stderr, code) == ("", 0)
    assert payload == {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "ran anyway"}}
    assert module._to_native({"policy_action": "allow", "reason": ""}, "PostToolUse") == ("", "", 0)


def test_generated_muse_wait_spends_the_budget_the_adapter_sized(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters import muse

    # The adapter hands this client the configured wait plus a grace on each
    # side, so the wait may run for everything but that margin.
    module = _load_script(tmp_path, harness="muse", timeout_seconds=130)
    config = Path(module.GUARD_HOME) / "config.toml"
    config.write_text("approval_wait_timeout_seconds = 120\n", encoding="utf-8")
    config.chmod(0o600)

    assert module._MUSE_WAIT_BUDGET_MARGIN_SECONDS == muse._MUSE_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS * 2
    assert module._approval_wait_seconds() == 120.0


def test_generated_client_waits_for_muse_approval_over_http(tmp_path: Path) -> None:
    module = _load_script(tmp_path, harness="muse", timeout_seconds=8)
    host, port, server = _serve(
        {
            ("POST", "/v1/hooks/muse"): {
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
        stdin = json.dumps(
            {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "cat .env"}}
        )
        stdout, _stderr, code = module._post_hook(stdin)
    finally:
        server.shutdown()
        server.server_close()
    assert code == 0
    payload = json.loads(stdout)
    assert payload["decision"] == "allow"
    assert payload["policy_action"] == "allow"
    # Muse rejects a bare allow; the reviewed input rides along.
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert payload["hookSpecificOutput"]["updatedInput"] == {"command": "cat .env"}


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


_AUTHORITY_BLOCK = {
    "policy_action": "block",
    "reason": "HOL Guard requires the native command extension policy before this action can execute.",
    "hookSpecificOutput": {"hookEventName": "PreToolUse"},
}


def test_generated_zcode_authority_block_stderr_names_the_home_it_reads(tmp_path: Path) -> None:
    # The script knows which home it read the blocking floor from. Pasting a
    # bare command into a shell would recover the default install instead,
    # leaving this one blocked on every tool call.
    module = _load_script(tmp_path, harness="zcode")
    _stdout, stderr, code = module._to_native(dict(_AUTHORITY_BLOCK), "PreToolUse")

    assert code == 2
    # Spelled by the script's own quoting rule, because a Windows home renders
    # for `cmd.exe`, not for a POSIX shell.
    named = module._quote_home(module.GUARD_HOME, os.name == "nt")
    assert named is not None, module.GUARD_HOME
    assert f"hol-guard command --guard-home {named} controls recover-authority" in stderr


def test_generated_zcode_authority_block_keeps_the_short_command_for_the_default_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The short command is the one almost everyone needs, and a path that adds
    # nothing only invites editing.
    module = _load_script(tmp_path, harness="zcode")
    monkeypatch.setattr(module, "GUARD_HOME", str(tmp_path / ".hol-guard"))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    _stdout, stderr, code = module._to_native(dict(_AUTHORITY_BLOCK), "PreToolUse")

    assert code == 2
    assert "hol-guard command controls recover-authority" in stderr
    assert "--guard-home" not in stderr


def test_generated_zcode_authority_block_keeps_the_short_command_without_a_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A platform that will not answer for the user's home leaves nothing to
    # compare, so there is nothing worth adding to the command.
    module = _load_script(tmp_path, harness="zcode")

    def _no_home(cls: type[Path]) -> Path:
        raise RuntimeError("home directory cannot be resolved")

    monkeypatch.setattr(Path, "home", classmethod(_no_home))
    _stdout, stderr, code = module._to_native(dict(_AUTHORITY_BLOCK), "PreToolUse")

    assert code == 2
    assert "hol-guard command controls recover-authority" in stderr
    assert "--guard-home" not in stderr


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


# A newer resident, a truncated field or a corrupted response can hand the
# standalone client an action it cannot place in Guard's lattice. The client
# reads that as "block", the way the native bridge that answers for it does,
# rather than rendering the empty "nothing to say" envelope that let the call
# run.
_UNPLACEABLE_ACTIONS = ("quarantine-required", "ask", "", "BLOCK", "0", None, 7)


@pytest.mark.parametrize(
    "harness",
    ["kimi", "zcode", "grok", "devin", "copilot", "hermes", "cursor", "opencode"],
)
@pytest.mark.parametrize("action", _UNPLACEABLE_ACTIONS)
def test_generated_client_denies_an_action_outside_the_lattice(
    tmp_path: Path,
    harness: str,
    action: object,
) -> None:
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {"policy_action": action, "reason": "Review in HOL Guard."},
        "PreToolUse",
    )
    payload = json.loads(stdout)
    specific = payload.get("hookSpecificOutput")
    decision = specific["permissionDecision"] if isinstance(specific, dict) else payload["decision"]
    assert decision in {"deny", "block"}, (harness, action, stdout)


@pytest.mark.parametrize(
    ("harness", "event_name", "code"),
    [
        ("kimi", "PreToolUse", 2),
        ("zcode", "PreToolUse", 2),
        ("grok", "PreToolUse", 2),
        ("devin", "PreToolUse", 2),
        ("hermes", "PreToolUse", 2),
        ("hermes", "PostToolUse", 2),
        ("kimi", "UserPromptSubmit", 2),
        ("zcode", "UserPromptSubmit", 2),
        # Copilot carries its decision in the envelope, so a deny still exits 0.
        ("copilot", "PreToolUse", 0),
    ],
)
def test_generated_client_exit_code_for_an_unplaceable_action_matches_the_harness(
    tmp_path: Path,
    harness: str,
    event_name: str,
    code: int,
) -> None:
    module = _load_script(tmp_path, harness=harness)
    _stdout, _stderr, exit_code = module._to_native(
        {"policy_action": "quarantine-required", "reason": "Review in HOL Guard."},
        event_name,
    )
    assert exit_code == code


@pytest.mark.parametrize("harness", ["kimi", "zcode", "grok", "devin", "hermes"])
def test_generated_client_still_allows_the_permissive_tiers(tmp_path: Path, harness: str) -> None:
    module = _load_script(tmp_path, harness=harness)
    for action in ("allow", "warn"):
        stdout, _stderr, exit_code = module._to_native(
            {"policy_action": action, "reason": ""},
            "PreToolUse",
        )
        payload = json.loads(stdout)
        specific = payload.get("hookSpecificOutput")
        decision = specific.get("permissionDecision") if isinstance(specific, dict) else payload.get("decision")
        assert exit_code == 0, (harness, action)
        assert decision in {"allow", None}, (harness, action, stdout)


def test_generated_client_canonicalizes_before_naming_the_action_in_a_reason(tmp_path: Path) -> None:
    # The stderr reason names the tier the client acted on, not the raw value
    # it could not place, so an operator reading it sees the decision Guard made.
    module = _load_script(tmp_path, harness="zcode")
    _stdout, stderr, exit_code = module._to_native(
        {
            "policy_action": "quarantine-required",
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
        },
        "PreToolUse",
    )
    assert exit_code == 2
    assert "quarantine-required" not in stderr


@pytest.mark.parametrize("harness", ["copilot", "cursor", "opencode", "kimi", "zcode", "grok", "devin"])
@pytest.mark.parametrize("action", ["quarantine-required", "ask", "BLOCK", "0", None, 7])
def test_generated_client_denies_a_prebuilt_allow_beside_an_unplaceable_action(
    tmp_path: Path,
    harness: str,
    action: object,
) -> None:
    # A response that already carries its harness's permission decision is
    # emitted as it arrived, so canonicalizing the action on its own left the
    # "allow" standing: a harness that reads the envelope rather than the exit
    # code still ran the call. Copilot is the one in this set that does.
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {
            "policy_action": action,
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        },
        "PreToolUse",
    )
    payload = json.loads(stdout)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny", (harness, action, stdout)
    assert payload["policy_action"] == "block", (harness, action, stdout)


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode"])
def test_generated_client_denies_a_prebuilt_top_level_allow_beside_an_unplaceable_action(
    tmp_path: Path,
    harness: str,
) -> None:
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {"policy_action": "quarantine-required", "decision": "allow"},
        "PreToolUse",
    )
    assert json.loads(stdout)["decision"] == "deny", (harness, stdout)


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode", "grok", "devin"])
@pytest.mark.parametrize(
    ("decision", "expected_action"),
    [("deny", "block"), ("block", "block"), ("ask", "review")],
)
def test_generated_client_lowers_a_permissive_action_to_its_restrictive_decision(
    tmp_path: Path,
    harness: str,
    decision: str,
    expected_action: str,
) -> None:
    # A permissive action beside a restrictive decision is not permission.
    # The native bridge lowers the action to the decision; so does the client.
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {
            "policy_action": "allow",
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision},
        },
        "PreToolUse",
    )
    payload = json.loads(stdout)
    assert payload["policy_action"] == expected_action, (harness, decision, stdout)
    assert payload["hookSpecificOutput"]["permissionDecision"] != "allow", stdout


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode", "grok", "devin"])
def test_generated_client_leaves_an_agreeing_prebuilt_allow_alone(tmp_path: Path, harness: str) -> None:
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, exit_code = module._to_native(
        {
            "policy_action": "allow",
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        },
        "PreToolUse",
    )
    payload = json.loads(stdout)
    assert exit_code == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow", stdout
    assert payload["policy_action"] == "allow", stdout


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode", "grok", "devin"])
@pytest.mark.parametrize("action", [" allow ", "\tallow\n", " warn"])
def test_generated_client_reads_a_padded_canonical_action_as_that_action(
    tmp_path: Path,
    harness: str,
    action: str,
) -> None:
    # The native bridge strips the action before testing it against the
    # lattice. A client that did not denied a padded "allow" the bridge
    # allowed, so one response produced two decisions.
    module = _load_script(tmp_path, harness=harness)
    assert module._canonical_policy_action(action) == action.strip()
    stdout, _stderr, exit_code = module._to_native({"policy_action": action, "reason": ""}, "PreToolUse")
    payload = json.loads(stdout)
    specific = payload.get("hookSpecificOutput")
    decision = specific.get("permissionDecision") if isinstance(specific, dict) else payload.get("decision")
    assert exit_code == 0, (harness, action, stdout)
    assert decision in {"allow", None}, (harness, action, stdout)


@pytest.mark.parametrize("harness", ["copilot", "cursor", "opencode", "kimi", "zcode", "grok", "devin"])
@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("quarantine-required", "deny"),
        ("block", "deny"),
        ("sandbox-required", "ask"),
        ("review", "ask"),
        ("require-reapproval", "ask"),
    ],
)
def test_generated_client_writes_a_decision_into_an_empty_envelope(
    tmp_path: Path,
    harness: str,
    action: str,
    expected: str,
) -> None:
    # An envelope with no permission decision beside a restrictive action is
    # what a harness that reads the envelope rather than the exit code runs
    # on. Copilot, cursor and opencode exit 0, so the envelope is the whole
    # answer for them. The native bridge writes the decision in; so does the
    # client, or the same request gets two answers.
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {"policy_action": action, "hookSpecificOutput": {"hookEventName": "PreToolUse"}},
        "PreToolUse",
    )
    payload = json.loads(stdout)
    assert payload["hookSpecificOutput"]["permissionDecision"] == expected, (harness, action, stdout)


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode"])
def test_generated_client_writes_a_decision_into_an_envelope_it_cannot_read(
    tmp_path: Path,
    harness: str,
) -> None:
    # The key is there but carries no envelope, so there is nowhere for the
    # decision to go until the client makes one, as the bridge does.
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {"policy_action": "block", "hookSpecificOutput": "PreToolUse"},
        "PreToolUse",
    )
    payload = json.loads(stdout)
    assert payload["hookSpecificOutput"] == {"hookEventName": "PreToolUse", "permissionDecision": "deny"}, stdout


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode", "grok", "devin"])
@pytest.mark.parametrize("word", ["permit", "allowed", "", 7, None, "DENY-ish"])
def test_generated_client_denies_an_unplaceable_decision_word_on_a_gating_event(
    tmp_path: Path,
    harness: str,
    word: object,
) -> None:
    # A decision word this client cannot place names no permission. Passing
    # it through beside an "allow" action left the call running on a harness
    # that reads the envelope; the bridge writes "deny" over it instead.
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {
            "policy_action": "allow",
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": word},
        },
        "PreToolUse",
    )
    payload = json.loads(stdout)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny", (harness, word, stdout)
    assert payload["policy_action"] == "block", (harness, word, stdout)


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode", "grok", "devin"])
def test_generated_client_denies_an_unplaceable_top_level_decision_on_a_gating_event(
    tmp_path: Path,
    harness: str,
) -> None:
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {"policy_action": "allow", "decision": "permit"},
        "UserPromptSubmit",
    )
    payload = json.loads(stdout)
    # Devin names its own blocking decision after the exit code it is about
    # to take; every other harness keeps the word the bridge writes.
    assert payload["decision"] == ("block" if harness == "devin" else "deny"), (harness, stdout)
    assert payload["policy_action"] == "block", (harness, stdout)


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode", "grok", "devin"])
def test_generated_client_blocks_a_restrictive_prompt_with_no_decision(
    tmp_path: Path,
    harness: str,
) -> None:
    # UserPromptSubmit has no permission envelope to carry the decision, so a
    # restrictive action gets the top-level block the bridge writes.
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {"policy_action": "quarantine-required", "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}},
        "UserPromptSubmit",
    )
    assert json.loads(stdout)["decision"] == "block", (harness, stdout)


@pytest.mark.parametrize("harness", ["copilot", "kimi", "zcode", "grok", "devin"])
def test_generated_client_leaves_a_post_tool_envelope_alone(tmp_path: Path, harness: str) -> None:
    # Only an event that gates the call gets a decision written into it. A
    # PostToolUse envelope decides nothing, and the bridge leaves it as it
    # arrived, so the client cannot invent a field the bridge would not.
    module = _load_script(tmp_path, harness=harness)
    stdout, _stderr, _code = module._to_native(
        {"policy_action": "block", "hookSpecificOutput": {"hookEventName": "PostToolUse"}},
        "PostToolUse",
    )
    assert "permissionDecision" not in json.loads(stdout)["hookSpecificOutput"], (harness, stdout)


_DECISION_LATTICE = Path(__file__).resolve().parents[1] / "rust/crates/guard-contracts/src/decision_lattice.rs"


def test_generated_client_action_lattice_matches_guard_action(tmp_path: Path) -> None:
    # The standalone client runs with no Guard on its path, so it writes the
    # lattice out by hand and the copy can drift from the one the native
    # runtime answers from. This reads GuardAction::from_canonical's own arms
    # so a name added or renamed there fails here instead of in the field.
    import re

    source = _DECISION_LATTICE.read_text(encoding="utf-8")
    body = source.split("pub fn from_canonical", 1)[1].split("\n    }", 1)[0]
    canonical = frozenset(re.findall(r'"([a-z-]+)" => Self::', body))

    assert canonical, body
    module = _load_script(tmp_path, harness="grok")
    assert canonical == module._GUARD_ACTIONS
