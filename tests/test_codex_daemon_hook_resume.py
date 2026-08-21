"""Codex hook-bridge browser approval continuation tests."""

from __future__ import annotations

import argparse
import io
import json
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlparse

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_resume as resume
from codex_plugin_scanner.guard.cli import commands_support_hook_payload as hook_payload
from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction
from codex_plugin_scanner.guard.config import GuardConfig
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _DaemonHandler,
    _write_authenticated_daemon_files,
)
from tests.test_guard_phase04_harness_ux import _json_line, _run_hook


class _ResumeDaemonHandler(_DaemonHandler):
    request_id: ClassVar[str] = "abcd1234ef567890"
    resolution: ClassVar[str | None] = None
    approve_after: ClassVar[float] = 0.0
    started_at: ClassVar[float] = 0.0
    get_count: ClassVar[int] = 0

    def _write_json(self, payload: dict[str, object], *, status: int = 200, keep_alive: bool = False) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive" if keep_alive else "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/daemon/identity-challenge":
            super().do_POST()
            return
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        type(self).captured_guard_token = self.headers.get("X-Guard-Token")
        self._write_json(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "HOL Guard needs a browser decision.",
                },
                "guardApprovalRequestId": type(self).request_id,
                "guardApprovalUrl": (
                    f"http://127.0.0.1:{self.server.server_address[1]}/requests/{type(self).request_id}"
                ),
            }
        )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        type(self).get_count += 1
        if parsed.path != f"/v1/requests/{type(self).request_id}":
            self._write_json({"error": "not_found"}, status=404)
            return
        if self.headers.get("X-Guard-Token") != type(self).auth_token:
            self._write_json({"error": "unauthorized"}, status=401)
            return
        elapsed = time.monotonic() - type(self).started_at
        if type(self).resolution is None or elapsed < type(self).approve_after:
            self._write_json({"status": "pending", "request_id": type(self).request_id})
            return
        self._write_json(
            {
                "status": "resolved",
                "request_id": type(self).request_id,
                "resolution_action": type(self).resolution,
            }
        )

    def log_message(self, fmt: str, *args: object) -> None:
        return


def test_pending_pretool_approval_requires_safe_request_id() -> None:
    assert resume.pending_pretool_approval(
        {
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
            "guardApprovalRequestId": "abcd1234ef567890",
            "guardApprovalUrl": "http://127.0.0.1:9/requests/abcd1234ef567890",
        },
        event_name="PreToolUse",
    ) == ("abcd1234ef567890", "http://127.0.0.1:9/requests/abcd1234ef567890")
    assert (
        resume.pending_pretool_approval(
            {
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
                "guardApprovalRequestId": "../secret",
            },
            event_name="PreToolUse",
        )
        is None
    )
    assert (
        resume.pending_pretool_approval(
            {
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
                "guardApprovalRequestId": "abcd1234ef567890",
            },
            event_name="PostToolUse",
        )
        is None
    )


def test_codex_pretool_wait_metadata_covers_daemon_json_path(tmp_path: Path) -> None:
    args = argparse.Namespace(harness="codex", json=True)
    assert interaction._codex_hook_waits_for_browser_approval(
        args,
        event_name="PreToolUse",
        policy_action="require-reapproval",
        payload={"tool_input": {"command": "cat ~/.npmrc"}},
    )
    assert (
        interaction._codex_browser_wait_timeout_seconds(
            event_name="PreToolUse",
            configured_timeout=120,
        )
        == 120
    )
    metadata = interaction._codex_browser_wait_metadata(
        args=args,
        event_name="PreToolUse",
        policy_action="require-reapproval",
        config=GuardConfig(tmp_path / "guard-home", None, approval_wait_timeout_seconds=120),
        payload={"tool_input": {"command": "cat ~/.npmrc"}},
    )
    assert metadata["codex_hook_waits_for_browser_approval"] is True
    assert metadata["codex_browser_wait_timeout_seconds"] == 120


def test_native_pretool_deny_includes_guard_approval_binding() -> None:
    output = io.StringIO()
    hook_payload._emit_native_hook_response(
        harness="codex",
        policy_action="require-reapproval",
        reason="HOL Guard needs a browser decision.",
        event_name="PreToolUse",
        output_stream=output,
        response_payload={
            "primary_approval_request_id": "abcd1234ef567890",
            "primary_approval_url": "http://127.0.0.1:5475/requests/abcd1234ef567890",
        },
    )
    payload = json.loads(output.getvalue())
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert payload["guardApprovalRequestId"] == "abcd1234ef567890"
    assert payload["guardApprovalUrl"] == "http://127.0.0.1:5475/requests/abcd1234ef567890"


def test_codex_json_pretool_package_install_emits_resume_binding(tmp_path: Path) -> None:
    exit_code, output = _run_hook(
        tmp_path,
        harness="codex",
        json_output=True,
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "npm install is-even@1.0.0"},
        },
    )
    payload = _json_line(output)
    request_id = payload.get("guardApprovalRequestId")
    approval_url = payload.get("guardApprovalUrl")
    assert exit_code == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert isinstance(request_id, str) and len(request_id) >= 8
    assert isinstance(approval_url, str) and request_id in approval_url


def test_native_pretool_deny_parses_request_binding_from_reason() -> None:
    output = io.StringIO()
    hook_payload._emit_native_hook_response(
        harness="codex",
        policy_action="require-reapproval",
        reason=(
            "HOL Guard paused `is-even@1.0.0` for review before install. "
            "Open HOL Guard to approve or keep this blocked: "
            "http://127.0.0.1:4959/requests/e6a363623e084e69b3b5ff34c476deb4. "
            "After you choose, retry the same Codex action."
        ),
        event_name="PreToolUse",
        output_stream=output,
    )
    payload = json.loads(output.getvalue())
    assert payload["guardApprovalRequestId"] == "e6a363623e084e69b3b5ff34c476deb4"
    assert payload["guardApprovalUrl"] == "http://127.0.0.1:4959/requests/e6a363623e084e69b3b5ff34c476deb4"


def test_bridge_converts_denied_pretool_to_allow_after_browser_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _ResumeDaemonHandler)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _ResumeDaemonHandler.guard_home = guard_home
    _ResumeDaemonHandler.resolution = "allow"
    _ResumeDaemonHandler.approve_after = 0.15
    _ResumeDaemonHandler.started_at = time.monotonic()
    _ResumeDaemonHandler.get_count = 0
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm install is-even@1.0.0"},
                }
            )
        ),
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda _url: True)

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, port))
    finally:
        daemon.shutdown()
        thread.join(timeout=5)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    assert "permissionDecision" not in payload.get("hookSpecificOutput", {})
    assert _ResumeDaemonHandler.get_count >= 1
    assert "guardApprovalRequestId" not in payload


def test_bridge_keeps_deny_when_browser_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _ResumeDaemonHandler)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _ResumeDaemonHandler.guard_home = guard_home
    _ResumeDaemonHandler.resolution = "block"
    _ResumeDaemonHandler.approve_after = 0.05
    _ResumeDaemonHandler.started_at = time.monotonic()
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm install is-even@1.0.0"},
                }
            )
        ),
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda _url: True)

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, port))
    finally:
        daemon.shutdown()
        thread.join(timeout=5)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "guardApprovalRequestId" not in payload


def test_bridge_keeps_deny_when_browser_wait_times_out(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _ResumeDaemonHandler)
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _ResumeDaemonHandler.guard_home = guard_home
    _ResumeDaemonHandler.resolution = None
    _ResumeDaemonHandler.approve_after = 30.0
    _ResumeDaemonHandler.started_at = time.monotonic()
    config = _bridge_config(guard_home, port)
    config["hook_timeouts"] = {
        "PreToolUse": 3,
        "PermissionRequest": 3,
        "UserPromptSubmit": 3,
        "PostToolUse": 3,
    }
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm install is-even@1.0.0"},
                }
            )
        ),
    )
    monkeypatch.setattr(resume, "open_browser_url", lambda _url: True)
    monkeypatch.setattr(resume, "_POLL_INTERVAL_SECONDS", 0.05)

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.shutdown()
        thread.join(timeout=5)

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
