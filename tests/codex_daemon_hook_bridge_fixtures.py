"""Shared authenticated daemon bridge test fixtures."""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import ClassVar

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon.discovery import (
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
            "PreToolUse": 10,
            "PermissionRequest": 10,
            "UserPromptSubmit": 10,
            "PostToolUse": 10,
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
