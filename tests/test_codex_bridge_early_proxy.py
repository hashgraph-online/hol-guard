"""Codex hook bridge answers from the running daemon before frozen imports."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FROZEN_ENTRYPOINT = ROOT / "scripts" / "mdm" / "hol-guard-entry.py"
DISCOVERY_KEY = "ab" * 32
AUTH_TOKEN = "codex-bridge-test-token"
QUERY = "guard-home=%2Ftmp%2Fguard&home=%2Ftmp%2Fhome"


def _poison_guard_import(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    marker = tmp_path / "guard-imported"
    package = tmp_path / "codex_plugin_scanner"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import os\nfrom pathlib import Path\nPath(os.environ['GUARD_IMPORT_MARKER']).write_text('imported')\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(tmp_path)
    environment["GUARD_IMPORT_MARKER"] = str(marker)
    environment["HOME"] = str(tmp_path)
    return marker, environment


def _sign(discovery_key: str, payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hmac.new(bytes.fromhex(discovery_key), canonical, hashlib.sha256).hexdigest()


def _write_daemon_identity(
    tmp_path: Path,
    *,
    host: str,
    port: int,
    token: str = AUTH_TOKEN,
    tamper_signature: bool = False,
) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()
    guard_home.chmod(0o700)
    state = {
        "guard_home": str(guard_home),
        "host": host,
        "port": port,
        "pid": 4242,
        "state_id": "bridge-test-state",
        "started_at": "2026-09-29T00:00:00+00:00",
        "auth_token_id": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "discovery_protocol_version": 1,
        "discovery_key_id": hashlib.sha256(bytes.fromhex(DISCOVERY_KEY)).hexdigest(),
    }
    state["state_signature"] = _sign(DISCOVERY_KEY, state)
    if tamper_signature:
        signature = state["state_signature"]
        state["state_signature"] = f"{signature[:-1]}{'0' if signature[-1] != '0' else '1'}"
    files = {
        guard_home / "daemon-discovery-key": DISCOVERY_KEY,
        guard_home / "daemon-state.json": json.dumps(state),
        guard_home / "daemon-auth-token": token,
    }
    for path, contents in files.items():
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o600)


def _bridge_config(tmp_path: Path) -> str:
    guard_home = tmp_path / ".hol-guard"
    return json.dumps(
        {
            "state_path": str(guard_home / "daemon-state.json"),
            "manifest_path": str(guard_home / "managed" / "codex" / "hooks-test.manifest.json"),
            "fallback_command": ["hol-guard", "hook", "--harness", "codex"],
            "start_command": ["hol-guard", "--_hol-guard-codex-daemon-recover", "{}"],
            "query": QUERY,
            "hook_timeouts": {
                "PreToolUse": 305,
                "PermissionRequest": 30,
                "UserPromptSubmit": 30,
                "PostToolUse": 305,
            },
        },
        separators=(",", ":"),
    )


class _FakeDaemon:
    """Minimal stand-in for /v1/daemon/identity-challenge + /v1/hooks/codex."""

    def __init__(self, hook_response: dict[str, object], *, hook_status: int = 200) -> None:
        self.hook_response = hook_response
        self.hook_status = hook_status
        self.hook_requests: list[dict[str, object]] = []
        self.challenges: list[dict[str, object]] = []
        self.state: dict[str, object] = {}
        self.server: ThreadingHTTPServer | None = None

    @property
    def port(self) -> int:
        assert self.server is not None
        return self.server.server_address[1]

    def start(self) -> None:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except ValueError:
                    payload = {}
                if self.path == "/v1/daemon/identity-challenge":
                    fake._challenge(self, payload)
                elif self.path.startswith("/v1/hooks/codex"):
                    fake._hook(self, payload)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, template: str, *args: object) -> None:
                del template, args

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _challenge(self, handler: BaseHTTPRequestHandler, payload: dict[str, object]) -> None:
        self.challenges.append(payload)
        state = self.state
        now_ms = int(time.time() * 1000)
        unsigned = {
            "protocol_version": 1,
            "nonce": payload.get("nonce"),
            "state_id": state["state_id"],
            "host": state["host"],
            "port": state["port"],
            "pid": state["pid"],
            "started_at": state["started_at"],
            "guard_home": state["guard_home"],
            "hook_event": payload.get("hook_event"),
            "issued_at_ms": now_ms,
            "expires_at_ms": now_ms + 4000,
        }
        response = dict(unsigned)
        response["proof"] = _sign(DISCOVERY_KEY, unsigned)
        body = json.dumps(response).encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _hook(self, handler: BaseHTTPRequestHandler, payload: dict[str, object]) -> None:
        self.hook_requests.append(
            {
                "body": payload,
                "token": handler.headers.get("X-Guard-Token"),
                "nonce": handler.headers.get("X-Guard-Daemon-Nonce"),
                "proof": handler.headers.get("X-Guard-Daemon-Proof"),
            }
        )
        body = json.dumps(self.hook_response).encode("utf-8") if self.hook_status == 200 else b""
        handler.send_response(self.hook_status)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)


def _run_bridge(
    tmp_path: Path, stdin_payload: dict[str, object], env: dict[str, str], *, encode_config: bool = False
) -> subprocess.CompletedProcess[str]:
    config = _bridge_config(tmp_path)
    if encode_config:
        # Windows installs pass the config as unpadded base64url text.
        config = base64.urlsafe_b64encode(config.encode("utf-8")).decode("ascii").rstrip("=")
    return subprocess.run(
        [
            sys.executable,
            str(FROZEN_ENTRYPOINT),
            "--_hol-guard-codex-bridge",
            config,
        ],
        input=json.dumps(stdin_payload),
        capture_output=True,
        env=env,
        check=False,
        text=True,
    )


@pytest.mark.parametrize("encode_config", [False, True])
def test_codex_bridge_proxy_answers_allow_before_guard_imports(tmp_path: Path, encode_config: bool) -> None:
    fake = _FakeDaemon(
        {
            "continue": True,
            "policy_action": "warn",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "policy warning detail",
            },
        }
    )
    fake.start()
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=fake.port)
        guard_home = tmp_path / ".hol-guard"
        fake.state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
        marker, environment = _poison_guard_import(tmp_path)
        result = _run_bridge(
            tmp_path,
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
                "session_id": "session-1",
            },
            environment,
            encode_config=encode_config,
        )
    finally:
        fake.server.shutdown()  # type: ignore[union-attr]
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert response["continue"] is True
    assert response["hookSpecificOutput"] == {"hookEventName": "PreToolUse"}
    assert "permissionDecision" not in response["hookSpecificOutput"]
    assert response["systemMessage"] == "policy warning detail"
    assert not marker.exists()
    assert len(fake.challenges) == 1
    assert fake.challenges[0]["hook_event"] == "PreToolUse"
    assert len(fake.hook_requests) == 1
    request = fake.hook_requests[0]
    assert request["token"] == AUTH_TOKEN
    assert request["nonce"] == fake.challenges[0]["nonce"]
    assert isinstance(request["proof"], str) and request["proof"]
    body = request["body"]
    assert isinstance(body["guard_remaining_ms"], int)
    wait_process = body["guard_codex_browser_wait_process"]
    assert isinstance(wait_process["pid"], int) and wait_process["pid"] > 0
    assert isinstance(wait_process["startToken"], str)
    assert body["guard_codex_browser_wait_timeout_seconds"] > 0


def test_codex_bridge_proxy_preserves_deny(tmp_path: Path) -> None:
    fake = _FakeDaemon(
        {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "blocked by policy",
            },
        }
    )
    fake.start()
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=fake.port)
        guard_home = tmp_path / ".hol-guard"
        fake.state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
        marker, environment = _poison_guard_import(tmp_path)
        result = _run_bridge(
            tmp_path,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}, "session_id": "s"},
            environment,
        )
    finally:
        fake.server.shutdown()  # type: ignore[union-attr]
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert response["hookSpecificOutput"]["permissionDecisionReason"] == "blocked by policy"
    assert not marker.exists()


def test_codex_bridge_proxy_falls_through_when_daemon_unreachable(tmp_path: Path) -> None:
    _write_daemon_identity(tmp_path, host="127.0.0.1", port=1)
    marker, environment = _poison_guard_import(tmp_path)
    result = _run_bridge(
        tmp_path,
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}, "session_id": "s"},
        environment,
    )
    assert result.returncode != 0
    assert marker.is_file()


def test_codex_bridge_proxy_ignores_unauthenticated_state(tmp_path: Path) -> None:
    fake = _FakeDaemon({"continue": True})
    fake.start()
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=fake.port, tamper_signature=True)
        marker, environment = _poison_guard_import(tmp_path)
        result = _run_bridge(
            tmp_path,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}, "session_id": "s"},
            environment,
        )
    finally:
        fake.server.shutdown()  # type: ignore[union-attr]
    assert result.returncode != 0
    assert marker.is_file()
    assert fake.challenges == []


def test_codex_bridge_proxy_falls_through_on_pending_approval(tmp_path: Path) -> None:
    fake = _FakeDaemon(
        {
            "continue": True,
            "guardApprovalRequestId": "req_abc12345",
            "guardApprovalUrl": "http://127.0.0.1:5474/requests/req_abc12345",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "approval required",
            },
        }
    )
    fake.start()
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=fake.port)
        guard_home = tmp_path / ".hol-guard"
        fake.state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
        marker, environment = _poison_guard_import(tmp_path)
        result = _run_bridge(
            tmp_path,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}, "session_id": "s"},
            environment,
        )
    finally:
        fake.server.shutdown()  # type: ignore[union-attr]
    # Pending approvals trigger the browser wait flow, which lazily imports
    # the Guard package — the poisoned import proves the early path engaged it.
    assert result.returncode == 0
    assert marker.is_file()
    response = json.loads(result.stdout)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_codex_bridge_proxy_fails_closed_on_oversized_input(tmp_path: Path) -> None:
    fake = _FakeDaemon({"continue": True})
    fake.start()
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=fake.port)
        guard_home = tmp_path / ".hol-guard"
        fake.state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
        marker, environment = _poison_guard_import(tmp_path)
        result = subprocess.run(
            [
                sys.executable,
                str(FROZEN_ENTRYPOINT),
                "--_hol-guard-codex-bridge",
                _bridge_config(tmp_path),
            ],
            input=" " * 1_000_002,
            capture_output=True,
            env=environment,
            check=False,
            text=True,
        )
    finally:
        fake.server.shutdown()  # type: ignore[union-attr]
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not marker.exists()
    assert fake.hook_requests == []


def test_codex_bridge_proxy_normalizes_post_tool_use(tmp_path: Path) -> None:
    fake = _FakeDaemon(
        {
            "continue": True,
            "decision": "block",
            "reason": "post-tool policy",
            "policy_action": "warn",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "guard context",
                "unexpectedField": "dropped",
            },
        }
    )
    fake.start()
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=fake.port)
        guard_home = tmp_path / ".hol-guard"
        fake.state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
        marker, environment = _poison_guard_import(tmp_path)
        result = _run_bridge(
            tmp_path,
            {"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "s"},
            environment,
        )
    finally:
        fake.server.shutdown()  # type: ignore[union-attr]
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert response["decision"] == "block"
    assert response["reason"] == "post-tool policy"
    assert "policy_action" not in response
    assert response["hookSpecificOutput"] == {
        "hookEventName": "PostToolUse",
        "additionalContext": "guard context",
    }
    assert not marker.exists()
    assert fake.challenges[0]["hook_event"] == "PostToolUse"


def test_codex_bridge_proxy_falls_through_on_worker_failure(tmp_path: Path) -> None:
    fake = _FakeDaemon({"reason_code": "daemon_hook_process_failed", "detail": "worker crashed"})
    fake.start()
    try:
        _write_daemon_identity(tmp_path, host="127.0.0.1", port=fake.port)
        guard_home = tmp_path / ".hol-guard"
        fake.state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
        marker, environment = _poison_guard_import(tmp_path)
        result = _run_bridge(
            tmp_path,
            {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}, "session_id": "s"},
            environment,
        )
    finally:
        fake.server.shutdown()  # type: ignore[union-attr]
    assert result.returncode != 0
    assert marker.is_file()
