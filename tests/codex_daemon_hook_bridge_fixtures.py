"""Shared authenticated daemon bridge test fixtures."""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import ClassVar

from codex_plugin_scanner.guard import native_daemon_manage as daemon_manager
from tests.guard_daemon_state_signing import (
    DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS,
    authenticated_challenge_payload,
    load_daemon_discovery_key,
)


class _DaemonHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    captured_challenge_guard_token: ClassVar[str | None] = None
    captured_guard_token: ClassVar[str | None] = None
    captured_hook_body: ClassVar[str | None] = None
    response_body: ClassVar[bytes] = b"{}"
    guard_home: ClassVar[Path | None] = None
    auth_token: ClassVar[str] = "fixture-token"
    challenge_mode: ClassVar[str] = "valid"
    challenge_count: ClassVar[int] = 0

    def _write_json(self, payload: dict[str, object], *, status: int = 200, keep_alive: bool = False) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive" if keep_alive else "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        if self.path == "/v1/daemon/identity-challenge":
            type(self).challenge_count += 1
            type(self).captured_challenge_guard_token = self.headers.get("X-Guard-Token")
            if type(self).challenge_mode == "redirect":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            request = json.loads(raw_body)
            guard_home = type(self).guard_home
            assert guard_home is not None
            state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
            discovery_key = load_daemon_discovery_key(guard_home)
            assert discovery_key is not None
            issued_at_ms = int(time.time() * 1000)
            expires_at_ms = issued_at_ms + DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS * 1000
            if type(self).challenge_mode == "expired":
                issued_at_ms -= 10_000
                expires_at_ms -= 10_000
            response = authenticated_challenge_payload(
                discovery_key=discovery_key,
                state=state,
                nonce=request["nonce"],
                hook_event=request["hook_event"],
                issued_at_ms=issued_at_ms,
                expires_at_ms=expires_at_ms,
            )
            if type(self).challenge_mode == "wrong-proof":
                response["proof"] = "0" * 64
            if type(self).challenge_mode == "refresh-trust-status":
                daemon_manager.write_guard_daemon_state(
                    guard_home,
                    int(state["port"]),
                    type(self).auth_token,
                    pid=int(state["pid"]),
                    write_auth_token=False,
                    host=str(state["host"]),
                    state_id=str(state["state_id"]),
                    started_at=str(state["started_at"]),
                    trust_status={"status": f"refreshed-{type(self).challenge_count}"},
                )
            if type(self).challenge_mode == "replace-state":
                daemon_manager.write_guard_daemon_state(
                    guard_home,
                    self.server.server_address[1],
                    type(self).auth_token,
                    pid=os.getpid(),
                    state_id="replacement-state",
                )
                type(self).challenge_mode = "valid"
            self._write_json(response, keep_alive=True)
            return
        type(self).captured_guard_token = self.headers.get("X-Guard-Token")
        type(self).captured_hook_body = raw_body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).response_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


class _ProxyHandler(BaseHTTPRequestHandler):
    captured_paths: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        type(self).captured_paths.append(self.path)
        self.send_response(502)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return


def _bridge_config(guard_home: Path, port: int) -> dict[str, object]:
    return {
        "state_path": str(guard_home / "daemon-state.json"),
        "fallback_command": [sys.executable, "-c", "print('{}')"],
        "start_command": [sys.executable, "-c", "raise SystemExit(1)"],
        "query": f"guard-home={guard_home}",
        "hook_timeouts": {
            "PreToolUse": 4,
            "PermissionRequest": 4,
            "UserPromptSubmit": 4,
            "PostToolUse": 4,
        },
    }


def _write_authenticated_daemon_files(guard_home: Path, port: int) -> None:
    daemon_manager.write_guard_daemon_state(
        guard_home,
        port,
        _DaemonHandler.auth_token,
        pid=os.getpid(),
        state_id="fixture-state",
    )
    _DaemonHandler.guard_home = guard_home
    _DaemonHandler.captured_challenge_guard_token = None
    _DaemonHandler.captured_guard_token = None
    _DaemonHandler.captured_hook_body = None
    _DaemonHandler.response_body = b"{}"
    _DaemonHandler.challenge_mode = "valid"
    _DaemonHandler.challenge_count = 0


def signed_native_bridge_argv(runtime: Path, guard_home: Path, registered: dict[str, object]) -> tuple[str, ...]:
    """The bridge argv a real install registers, with the signed manifest it authenticates.

    The native bridge runs nothing until the registration matches a manifest
    signed with this home's key, so a test that runs the bridge directly
    records one the way the installer does.
    """
    from datetime import datetime, timezone

    from codex_plugin_scanner.guard.codex_hook_file_integrity import (
        describe_executable_file,
        describe_regular_file,
    )
    from codex_plugin_scanner.guard.codex_hook_integrity import atomic_write_bytes
    from tests.codex_hook_integrity_fixtures import load_or_create_hook_secret, sign_hook_manifest
    from tests.codex_hook_paths_support import canonical_manifest_bytes, hook_manifest_path

    def canonical_path(path):
        return str(Path(path).expanduser().resolve(strict=False))

    config_target = guard_home.parent / ".codex" / "config.toml"
    config_target.parent.mkdir(parents=True, exist_ok=True)
    config_target.touch()
    manifest_path = hook_manifest_path(guard_home, config_target)
    config = dict(registered)
    config["manifest_path"] = str(manifest_path)
    config_argument = json.dumps(config, separators=(",", ":"))
    argv = (str(runtime), "codex-hook-bridge", config_argument)
    secret = load_or_create_hook_secret(guard_home)
    interpreter = describe_executable_file(Path(sys.executable), role="interpreter")
    unsigned: dict[str, object] = {
        "schema_version": 2,
        "harness": "codex",
        "installation_id": secret.installation_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "context": {"runtime_guard_home": canonical_path(guard_home)},
        "config": {"scope": "global", "target": canonical_path(config_target)},
        "interpreter": interpreter,
        "packaged_files": [describe_regular_file(runtime, role="bridge", executable_required=True)],
        "events": [{"argv": list(argv)}],
        "fallback": {"argv": list(config["fallback_command"]), "interpreter": interpreter},
        "daemon_start": {"argv": list(config["start_command"]), "interpreter": interpreter},
    }
    atomic_write_bytes(
        manifest_path,
        canonical_manifest_bytes(sign_hook_manifest(unsigned, secret)),
        mode=0o600,
        private=True,
    )
    return argv
