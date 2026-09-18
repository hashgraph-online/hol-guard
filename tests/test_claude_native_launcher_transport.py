"""Actual native/Python process conformance, explicitly not installed SLO proof."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.claude_hook_config import command_handler_argv
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _sign_discovery_payload
from scripts import native_claude_launcher_pilot as installer


@pytest.fixture
def binary():
    raw = os.environ.get("CLAUDE_PILOT_TEST_BINARY")
    if sys.platform != "linux" or not raw:
        pytest.skip("explicit Linux source-conformance binary required; no installed qualification implied")
    path = Path(raw)
    assert path.is_absolute() and path.is_file()
    return path


@pytest.fixture(autouse=True)
def owned_interpreter(monkeypatch):
    fixture = json.loads((Path(__file__).parent / "fixtures/claude-launcher-pilot-auth.json").read_text())
    guard = Path(installer.claude_native_pilot_fallback.__file__).resolve().parents[1]
    for name, expected in fixture["bridge_modules"].items():
        assert hashlib.sha256((guard / name).read_bytes()).hexdigest() == expected
    invocation = os.environ.get("CLAUDE_PILOT_TEST_INTERPRETER")
    if invocation:
        assert Path(invocation).is_absolute() and Path(invocation).stat().st_uid in {0, os.getuid()}
        monkeypatch.setattr(sys, "executable", invocation)


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, guard: Path, event: str, mode: str):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.guard, self.event, self.mode = guard, event, mode
        self.key = bytes(range(32)).hex()
        self.challenges = {}
        self.hook_posts = []
        self.state = {
            "host": "127.0.0.1",
            "port": self.server_port,
            "pid": os.getpid(),
            "state_id": "synthetic-conformance-state",
            "started_at": "2026-09-17T00:00:00Z",
            "guard_home": str(guard),
            "auth_token_id": "synthetic-token-id",
            "discovery_protocol_version": 1,
            "discovery_key_id": hashlib.sha256(bytes.fromhex(self.key)).hexdigest(),
        }
        self.publish()

    def publish(self):
        self.guard.mkdir(mode=0o700, exist_ok=True)
        path = self.guard / "daemon-discovery-key"
        path.write_text(self.key)
        path.chmod(0o600)
        self.publish_state()

    def publish_state(self):
        state = {**self.state, "state_signature": _sign_discovery_payload(self.key, self.state)}
        path = self.guard / "daemon-state.json"
        path.write_text(json.dumps(state))
        path.chmod(0o600)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _write(self, body: bytes, *, declared_extra: int = 0, close: bool = False):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body) + declared_extra))
        self.send_header("Connection", "close" if close else "keep-alive")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        if close:
            self.close_connection = True

    def do_POST(self):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        payload = json.loads(data)
        server = self.server
        if self.path == "/v1/daemon/identity-challenge":
            now = int(time.time() * 1000)
            response = {
                **{key: server.state[key] for key in ("state_id", "host", "port", "pid", "started_at", "guard_home")},
                "protocol_version": 1,
                "nonce": payload["nonce"],
                "hook_event": payload["hook_event"],
                "issued_at_ms": now,
                "expires_at_ms": now + 5000,
            }
            if server.mode == "expired":
                response["expires_at_ms"] = now - 1
            response["proof"] = _sign_discovery_payload(server.key, response)
            if server.mode == "wrong_proof":
                response["proof"] = "0" * 64
            server.challenges[payload["nonce"]] = (id(self.connection), response["proof"])
            if server.mode == "state_changed":
                server.state["state_id"] = "changed-conformance-state"
                server.publish_state()
            if server.mode == "key_changed":
                (server.guard / "daemon-discovery-key").write_text("ff" * 32)
            self._write(json.dumps(response, separators=(",", ":")).encode())
            return
        assert self.path.startswith("/v1/hooks/claude-code?")
        nonce = self.headers["X-Guard-Daemon-Nonce"]
        assert server.challenges.pop(nonce) == (id(self.connection), self.headers["X-Guard-Daemon-Proof"])
        assert payload["hook_event_name"] == server.event
        server.hook_posts.append(data)
        if server.mode == "malformed" or server.mode == "partial_invalid":
            self._write(b"not-json", declared_extra=10 if server.mode.startswith("partial") else 0, close=True)
            return
        action = "deny" if server.mode == "block" else "ask" if server.mode == "review" else "allow"
        body = {"continue": True, "hookSpecificOutput": {"hookEventName": server.event}}
        if server.event == "PreToolUse":
            body["hookSpecificOutput"]["permissionDecision"] = action
        elif action != "allow":
            body.update(decision="block", reason="synthetic output review")
        body["policy_action"] = action
        self._write(
            json.dumps(body, separators=(",", ":")).encode(),
            declared_extra=9 if server.mode == "partial_valid" else 0,
            close=True,
        )


def _fixture(tmp_path, binary, monkeypatch, event, mode):
    tmp_path.chmod(0o700)
    guard, workspace = tmp_path / "guard", tmp_path / "workspace"
    workspace.mkdir()
    server = _Server(guard, event, mode)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    context = HarnessContext(home_dir=tmp_path, guard_home=guard, workspace_dir=workspace)
    runtime = tmp_path / "native-package" / "hol-guard-runtime"
    runtime.parent.mkdir()
    shutil.copyfile(binary, runtime)
    runtime.chmod(0o700)
    capability = json.loads(subprocess.check_output([str(runtime), "capabilities"]))
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "runtime_size": runtime.stat().st_size,
        "runtime_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
        "package_version": capability["runtime_version"],
        "source_sha": capability["build_sha"],
        "rule_digest": capability["rule_digest"],
        "protocol_version": capability["protocol_version"],
    }
    runtime.with_name("runtime-manifest.json").write_text(json.dumps(manifest))
    # Only this source-conformance fixture bypasses the installed-wheel proof.
    # Native record/self/file authentication still runs in the real process.
    monkeypatch.setattr(installer, "_installed_runtime", lambda: runtime)
    return server, thread, context


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
@pytest.mark.parametrize(
    "mode",
    [
        "allow",
        "block",
        "review",
        "wrong_proof",
        "expired",
        "state_changed",
        "key_changed",
        "malformed",
        "partial_valid",
        "partial_invalid",
    ],
)
def test_native_process_matches_frozen_python_bridge(tmp_path, binary, monkeypatch, event, mode):
    server, thread, context = _fixture(tmp_path, binary, monkeypatch, event, mode)
    try:
        installed = ClaudeCodeHarnessAdapter().install(context)
        configuration = Path(installed["config_path"])
        handler = json.loads(configuration.read_text())["hooks"][event][0]["hooks"][0]
        baseline_argv = command_handler_argv(handler)
        body = json.dumps(
            {
                "hook_event_name": event,
                "tool_name": "Read",
                "tool_response": "synthetic response",
                "tool_input": {"text": "é中文"},
            }
        )
        baseline = subprocess.run(
            baseline_argv, input=body, text=True, capture_output=True, timeout=10, cwd=context.workspace_dir
        )
        server.state["state_id"] = "synthetic-conformance-state"
        server.publish()
        server.hook_posts.clear()
        record = installer.install_private_pilot(context, qualification_root=tmp_path)
        registration = json.loads(record.read_text())
        candidate = subprocess.run(
            registration["argv"][event],
            input=body,
            text=True,
            capture_output=True,
            timeout=10,
            cwd=context.workspace_dir,
        )
        assert candidate.returncode == baseline.returncode == 0, candidate.stderr
        assert candidate.stdout == baseline.stdout
        assert candidate.stderr == baseline.stderr == ""
        assert len(server.hook_posts) == (
            0 if mode in {"wrong_proof", "expired", "state_changed", "key_changed"} else 1
        )
        assert installer.install_private_pilot(context, qualification_root=tmp_path) == record
        installer.restore_private_pilot(record)
        installer.activate_private_pilot(record)
        assert installer.install_private_pilot(context, qualification_root=tmp_path) == record
        installer.restore_private_pilot(record)
        retired = subprocess.run(
            registration["argv"][event],
            input=body,
            text=True,
            capture_output=True,
            timeout=10,
            cwd=context.workspace_dir,
        )
        assert retired.returncode == 2 and retired.stdout == ""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("mode", ["allow", "localhost", "malformed"])
def test_qualification_record_cannot_measure_python_handoff(tmp_path, binary, monkeypatch, mode):
    server, thread, context = _fixture(tmp_path, binary, monkeypatch, "PreToolUse", mode)
    try:
        if mode == "localhost":
            server.state["host"] = "localhost"
            server.publish_state()
        record = installer.install_private_pilot(context, qualification_root=tmp_path, require_native_transport=True)
        registration = json.loads(record.read_text())
        assert registration["require_native_transport"] is True
        completed = subprocess.run(
            registration["argv"]["PreToolUse"],
            input='{"hook_event_name":"PreToolUse","tool_name":"Read"}',
            text=True,
            capture_output=True,
            timeout=10,
            cwd=context.workspace_dir,
        )
        if mode == "allow":
            assert completed.returncode == 0 and json.loads(completed.stdout)["policy_action"] == "allow"
            assert len(server.hook_posts) == 1
        else:
            assert completed.returncode == 2 and completed.stdout == ""
            assert len(server.hook_posts) == (1 if mode == "malformed" else 0)
            if mode == "localhost":
                assert not server.challenges
        with pytest.raises(ValueError, match="transport_requirement_changed"):
            installer.install_private_pilot(context, qualification_root=tmp_path)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
def test_crlf_input_limit_cannot_be_normalized_into_an_allow(tmp_path, binary, monkeypatch, event):
    server, thread, context = _fixture(tmp_path, binary, monkeypatch, event, "allow")
    try:
        installed = ClaudeCodeHarnessAdapter().install(context)
        handler = json.loads(Path(installed["config_path"]).read_text())["hooks"][event][0]["hooks"][0]
        baseline = command_handler_argv(handler)
        prefix = json.dumps({"hook_event_name": event, "tool_name": "Read"})
        body = prefix + " " * (999_999 - len(prefix)) + "\r\n"
        assert len(body.encode()) == 1_000_001
        record = installer.install_private_pilot(context, qualification_root=tmp_path)
        candidate = json.loads(record.read_text())["argv"][event]
        outcomes = [
            subprocess.run(argv, input=body, text=True, capture_output=True, cwd=context.workspace_dir, timeout=10)
            for argv in (baseline, candidate)
        ]
        assert all(item.returncode == 0 and item.stderr == "" for item in outcomes)
        assert outcomes[0].stdout == outcomes[1].stdout
        assert not server.hook_posts and not server.challenges
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
