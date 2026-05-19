"""Guard queue API contract tests."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import sqlite3
import struct
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from codex_plugin_scanner.guard.codex_app_server import _send_app_server_websocket_messages
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _request(
    request_id: str,
    *,
    harness: str = "codex",
    command: str = "cat ~/.npmrc",
    artifact_id: str | None = None,
    publisher: str | None = None,
    prompt_excerpt: str | None = None,
    mcp_server: str | None = None,
    mcp_tool: str | None = None,
    workspace: str = "workspace-a",
) -> GuardApprovalRequest:
    action_envelope = {
        "action_type": "mcp_tool_call" if mcp_tool else "shell_command",
        "tool_name": "mcp" if mcp_tool else "Bash",
        "command": command,
        "prompt_excerpt": prompt_excerpt,
        "target_paths": ["~/.npmrc"] if "npmrc" in command else [],
        "network_hosts": [],
        "mcp_server": mcp_server,
        "mcp_tool": mcp_tool,
    }
    return GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=artifact_id or f"{harness}:project:{request_id}",
        artifact_name=request_id,
        artifact_hash=f"hash-{request_id}",
        publisher=publisher,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("args",),
        source_scope="project",
        config_path=f"/{workspace}/.config/guard.toml",
        workspace=workspace,
        launch_target=command,
        action_envelope_json=action_envelope,
        decision_v2_json={"dashboard_primary_detail": prompt_excerpt} if prompt_excerpt else None,
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/pending/{request_id}",
    )


def _populate(store: GuardStore, requests: list[GuardApprovalRequest]) -> None:
    for index, request in enumerate(requests):
        store.add_approval_request(request, f"2026-05-08T10:0{index}:00+00:00")


def _force_duplicate_row(store: GuardStore, request_id: str, source_request_id: str) -> None:
    connection = sqlite3.connect(store.path)
    try:
        connection.execute(
            """
            insert into approval_requests (
              request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
              recommended_scope, changed_fields_json, source_scope, config_path, workspace,
              launch_target, normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at,
              transport, risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
              launch_summary, risk_headline, action_envelope_json, decision_v2_json, fallback_cli_command,
              review_command, approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
            )
            select ?, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
              recommended_scope, changed_fields_json, source_scope, config_path, workspace,
              launch_target, normalized_identity_key, action_identity, queue_group_id, 1, last_seen_at,
              transport, risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
              launch_summary, risk_headline, action_envelope_json, decision_v2_json, fallback_cli_command,
              ?, ?, status, resolution_action, resolution_scope, reason, created_at, resolved_at
            from approval_requests
            where request_id = ?
            """,
            (
                request_id,
                f"hol-guard approvals approve {request_id}",
                f"http://127.0.0.1/pending/{request_id}",
                source_request_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _get_json(port: int, path: str) -> dict[str, object]:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(
    port: int,
    token: str,
    path: str,
    payload: dict[str, object],
    extra_headers: dict[str, str] | None = None,
) -> dict[str, object]:
    headers = {"Content-Type": "application/json", "X-Guard-Token": token}
    if extra_headers is not None:
        headers.update(extra_headers)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_error(port: int, token: str, path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))
    raise AssertionError("expected HTTPError")


def _start_fake_codex_app_server(socket_path: Path, received: list[dict[str, object]]) -> threading.Thread:
    def server() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            listener.listen(1)
            connection, _ = listener.accept()
            with connection:
                headers = _recv_until(connection, b"\r\n\r\n").decode("iso-8859-1")
                key = ""
                for line in headers.split("\r\n"):
                    if line.lower().startswith("sec-websocket-key:"):
                        key = line.split(":", 1)[1].strip()
                        break
                accept = base64.b64encode(hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()).decode(
                    "ascii"
                )
                connection.sendall(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Connection: Upgrade\r\n"
                        "Upgrade: websocket\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                while True:
                    opcode, payload = _recv_websocket_frame(connection)
                    if opcode != 0x1:
                        continue
                    message = json.loads(payload.decode("utf-8"))
                    received.append(message)
                    if message.get("id") == 1:
                        _send_websocket_text(
                            connection,
                            {
                                "id": 1,
                                "result": {
                                    "userAgent": "test",
                                    "codexHome": "/tmp",
                                    "platformFamily": "unix",
                                    "platformOs": "macos",
                                },
                            },
                        )
                    if message.get("id") == 2:
                        _send_websocket_text(connection, {"id": 2, "result": {"turnId": "turn-next"}})
                        time.sleep(0.05)
                        _send_websocket_text(
                            connection,
                            {
                                "method": "turn/completed",
                                "params": {
                                    "threadId": "thread-1",
                                    "turn": {
                                        "id": "turn-next",
                                        "status": "completed",
                                    },
                                },
                            },
                        )
                        break

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    for _ in range(50):
        if socket_path.exists():
            break
        time.sleep(0.01)
    return thread


def _start_fake_streaming_codex_app_server(socket_path: Path, received: list[dict[str, object]]) -> threading.Thread:
    def server() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            listener.listen(1)
            connection, _ = listener.accept()
            with connection:
                headers = _recv_until(connection, b"\r\n\r\n").decode("iso-8859-1")
                key = ""
                for line in headers.split("\r\n"):
                    if line.lower().startswith("sec-websocket-key:"):
                        key = line.split(":", 1)[1].strip()
                        break
                accept = base64.b64encode(hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()).decode(
                    "ascii"
                )
                connection.sendall(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Connection: Upgrade\r\n"
                        "Upgrade: websocket\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                while True:
                    opcode, payload = _recv_websocket_frame(connection)
                    if opcode != 0x1:
                        continue
                    message = json.loads(payload.decode("utf-8"))
                    received.append(message)
                    if message.get("id") == 1:
                        _send_websocket_text(
                            connection,
                            {
                                "id": 1,
                                "result": {
                                    "userAgent": "test",
                                    "codexHome": "/tmp",
                                    "platformFamily": "unix",
                                    "platformOs": "macos",
                                },
                            },
                        )
                    if message.get("id") == 2:
                        _send_websocket_text(connection, {"id": 2, "result": {"turnId": "turn-next"}})
                        for _ in range(10):
                            try:
                                _send_websocket_text(
                                    connection,
                                    {
                                        "method": "thread/status/changed",
                                        "params": {
                                            "threadId": "thread-1",
                                            "status": {"type": "active", "activeFlags": []},
                                        },
                                    },
                                )
                            except BrokenPipeError:
                                break
                            time.sleep(0.02)
                        break

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    for _ in range(50):
        if socket_path.exists():
            break
        time.sleep(0.01)
    return thread


def _start_fake_pre_ack_streaming_codex_app_server(
    socket_path: Path, received: list[dict[str, object]]
) -> threading.Thread:
    def server() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            listener.listen(1)
            connection, _ = listener.accept()
            with connection:
                headers = _recv_until(connection, b"\r\n\r\n").decode("iso-8859-1")
                key = ""
                for line in headers.split("\r\n"):
                    if line.lower().startswith("sec-websocket-key:"):
                        key = line.split(":", 1)[1].strip()
                        break
                accept = base64.b64encode(hashlib.sha1((key + _WEBSOCKET_GUID).encode("ascii")).digest()).decode(
                    "ascii"
                )
                connection.sendall(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Connection: Upgrade\r\n"
                        "Upgrade: websocket\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n"
                        "\r\n"
                    ).encode("ascii")
                )
                while True:
                    opcode, payload = _recv_websocket_frame(connection)
                    if opcode != 0x1:
                        continue
                    message = json.loads(payload.decode("utf-8"))
                    received.append(message)
                    if message.get("id") == 1:
                        _send_websocket_text(
                            connection,
                            {
                                "id": 1,
                                "result": {
                                    "userAgent": "test",
                                    "codexHome": "/tmp",
                                    "platformFamily": "unix",
                                    "platformOs": "macos",
                                },
                            },
                        )
                        for _ in range(10):
                            try:
                                _send_websocket_text(
                                    connection,
                                    {
                                        "method": "thread/status/changed",
                                        "params": {
                                            "threadId": "thread-1",
                                            "status": {"type": "active", "activeFlags": []},
                                        },
                                    },
                                )
                            except BrokenPipeError:
                                break
                            time.sleep(0.02)
                        break

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    for _ in range(50):
        if socket_path.exists():
            break
        time.sleep(0.01)
    return thread


def _recv_until(connection: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        data += connection.recv(4096)
    return data


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        data += connection.recv(length - len(data))
    return data


def _recv_websocket_frame(connection: socket.socket) -> tuple[int, bytes]:
    first, second = _recv_exact(connection, 2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(connection, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(connection, 8))[0]
    mask = _recv_exact(connection, 4) if second & 0x80 else None
    payload = _recv_exact(connection, length) if length else b""
    if mask is not None:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return first & 0x0F, payload


def _send_websocket_text(connection: socket.socket, payload: dict[str, object]) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    length = len(data)
    if length < 126:
        header = bytes([0x81, length])
    elif length < 65_536:
        header = bytes([0x81, 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x81, 127]) + struct.pack("!Q", length)
    connection.sendall(header + data)


def test_resolving_active_item_with_two_remaining_returns_next_hint(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(
        store,
        [
            _request("req-old", command="cat ~/.npmrc"),
            _request("req-active", command="cat ~/.pypirc"),
            _request("req-newest", command="curl https://metadata.example/health"),
        ],
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-active/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["remaining_pending_count"] == 2
    assert payload["next_selectable_request_id"] == "req-newest"
    assert {item["request_id"] for item in payload["remaining_pending_summaries"]} == {"req-newest", "req-old"}
    assert payload["copy"]["title"] == "Decision saved. Return to Codex."
    assert "could not find the Codex session to resume" in payload["copy"]["body"]
    assert "approval is now saved" in payload["copy"]["body"]
    assert store.get_approval_request("req-active")["resolution_action"] == "allow"


def test_codex_resolution_sends_continue_prompt_to_original_thread(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-active", command="echo guard resume")])
    socket_path = Path(tempfile.gettempdir()) / f"hol-guard-codex-{uuid.uuid4().hex}.sock"
    received_messages: list[dict[str, object]] = []
    codex_server = _start_fake_codex_app_server(socket_path, received_messages)
    session = store.upsert_guard_session(
        session_id="guard-session-1",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-hook",
        client_title="Codex hook",
        client_version="1.0.0",
        workspace=str(tmp_path),
        capabilities=["approval-resolution"],
        now="2026-05-08T10:00:00+00:00",
    )
    store.upsert_guard_operation(
        operation_id="operation-1",
        session_id=str(session["session_id"]),
        harness="codex",
        operation_type="tool_call",
        status="approval_wait_timeout",
        approval_request_ids=["req-active"],
        resume_token="resume-token",
        metadata={
            "codex_thread_id": "thread-1",
            "codex_turn_id": "turn-1",
            "codex_app_server_socket": str(socket_path),
        },
        now="2026-05-08T10:00:00+00:00",
    )
    for index in range(225):
        store.upsert_guard_operation(
            operation_id=f"noise-operation-{index:03d}",
            session_id=str(session["session_id"]),
            harness="codex",
            operation_type="tool_call",
            status="resolved",
            approval_request_ids=[f"noise-request-{index:03d}"],
            resume_token=None,
            metadata={"codex_thread_id": f"noise-thread-{index:03d}"},
            now=f"2026-05-08T10:01:{index % 60:02d}+00:00",
        )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-active/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()
        codex_server.join(timeout=2)
        socket_path.unlink(missing_ok=True)

    turn_start = received_messages[-1]
    assert payload["codex_resume"]["status"] == "sent"
    assert payload["resolution_summary"] == (
        "Decision saved. HOL Guard sent Codex a continue prompt in the original thread."
    )
    assert turn_start["method"] == "turn/start"
    assert turn_start["params"]["threadId"] == "thread-1"
    assert "HOL Guard approved" in turn_start["params"]["input"][0]["text"]
    assert store.list_events(event_name="codex/thread_resume")[0]["payload"]["status"] == "sent"


def test_codex_resume_completion_timeout_bounds_streaming_noncompletion_frames() -> None:
    socket_path = Path(tempfile.gettempdir()) / f"hol-guard-codex-{uuid.uuid4().hex}.sock"
    received_messages: list[dict[str, object]] = []
    codex_server = _start_fake_streaming_codex_app_server(socket_path, received_messages)

    response, completion_status = _send_app_server_websocket_messages(
        socket_path=str(socket_path),
        payloads=[
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "hol-guard",
                        "title": "HOL Guard",
                        "version": "1.0.0",
                    },
                    "capabilities": {"experimentalApi": True},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "turn/start",
                "params": {
                    "threadId": "thread-1",
                    "input": [{"type": "text", "text": "continue"}],
                },
            },
        ],
        response_id=2,
        timeout_seconds=1,
        completion_thread_id="thread-1",
        completion_timeout_seconds=0.03,
    )
    codex_server.join(timeout=2)
    socket_path.unlink(missing_ok=True)

    assert response is not None
    assert response["id"] == 2
    assert completion_status == "completion_timeout"


def test_codex_resume_response_timeout_bounds_streaming_pre_ack_frames() -> None:
    socket_path = Path(tempfile.gettempdir()) / f"hol-guard-codex-{uuid.uuid4().hex}.sock"
    received_messages: list[dict[str, object]] = []
    codex_server = _start_fake_pre_ack_streaming_codex_app_server(socket_path, received_messages)

    try:
        _send_app_server_websocket_messages(
            socket_path=str(socket_path),
            payloads=[
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "clientInfo": {
                            "name": "hol-guard",
                            "title": "HOL Guard",
                            "version": "1.0.0",
                        },
                        "capabilities": {"experimentalApi": True},
                    },
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "turn/start",
                    "params": {
                        "threadId": "thread-1",
                        "input": [{"type": "text", "text": "continue"}],
                    },
                },
            ],
            response_id=2,
            timeout_seconds=0.03,
            completion_thread_id="thread-1",
            completion_timeout_seconds=1,
        )
    except TimeoutError as error:
        assert str(error) == "turn_start_timeout"
    else:
        raise AssertionError("expected turn_start_timeout")
    finally:
        codex_server.join(timeout=2)
        socket_path.unlink(missing_ok=True)


def test_resolving_last_item_returns_empty_queue_hint(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-only")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-only/block",
            {"scope": "artifact", "reason": "blocked"},
        )
    finally:
        daemon.stop()

    assert payload["remaining_pending_count"] == 0
    assert payload["next_selectable_request_id"] is None
    assert payload["remaining_pending_summaries"] == []
    assert payload["copy"]["title"] == "Decision saved. Return to Codex."
    assert "Do not retry that action in Codex." in payload["copy"]["body"]
    assert "safe alternative" in payload["copy"]["body"]
    assert store.get_approval_request("req-only")["resolution_action"] == "block"


def test_resolving_duplicate_group_reports_collapsed_ids(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-active"), _request("req-unrelated", command="cat ~/.pypirc")])
    _force_duplicate_row(store, "req-duplicate", "req-active")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-active/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert payload["resolved_duplicate_ids"] == ["req-duplicate"]
    assert payload["remaining_pending_count"] == 1
    assert payload["next_selectable_request_id"] == "req-unrelated"


def test_broad_scope_resolution_keeps_other_reviews_pending(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-active"), _request("req-covered", command="cat ~/.pypirc")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-active/approve",
            {"scope": "harness", "reason": "trust this harness"},
        )
    finally:
        daemon.stop()

    assert payload["remaining_pending_count"] == 1
    assert payload["next_selectable_request_id"] == "req-covered"
    assert payload.get("resolved_scope_ids") in (None, [])
    assert store.get_approval_request("req-covered")["status"] == "pending"
    decisions = store.list_policy_decisions("codex")
    assert len(decisions) == 1
    assert decisions[0]["scope"] == "harness"


def test_artifact_scope_resolution_keeps_same_artifact_review_pending(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    shared_artifact = "codex:project:shared-tool"
    _populate(
        store,
        [
            _request("req-active", command="cat ~/.npmrc", artifact_id=shared_artifact),
            _request("req-covered", command="cat ~/.pypirc", artifact_id=shared_artifact),
            _request("req-unrelated", command="cat ~/.ssh/id_rsa", artifact_id="codex:project:other-tool"),
        ],
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-active/approve",
            {"scope": "artifact", "reason": "trust this artifact"},
        )
    finally:
        daemon.stop()

    assert payload["remaining_pending_count"] == 2
    assert payload["next_selectable_request_id"] == "req-unrelated"
    assert payload.get("resolved_scope_ids") in (None, [])
    assert store.get_approval_request("req-covered")["status"] == "pending"


def test_resolving_stale_item_returns_recovery_payload(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-stale")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-stale/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
        status, payload = _post_error(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-stale/approve",
            {"scope": "artifact", "reason": "reviewed again"},
        )
    finally:
        daemon.stop()

    assert status == 409
    assert payload["error"] == "already_resolved"
    assert payload["recovery"]["code"] == "request_resolved"


def test_resolving_missing_item_returns_recovery_payload(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        status, payload = _post_error(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/missing/approve",
            {"scope": "artifact", "reason": "reviewed"},
        )
    finally:
        daemon.stop()

    assert status == 404
    assert payload["error"] == "not_found"
    assert payload["recovery"]["code"] == "request_unknown"


def test_request_resolution_without_auth_returns_session_recovery(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-auth")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/requests/req-auth/approve",
            data=json.dumps({"scope": "artifact"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as error:
            status = error.code
            payload = json.loads(error.read().decode("utf-8"))
        else:
            raise AssertionError("expected HTTPError")
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"
    assert payload["recovery"]["code"] == "session_stale"
    assert "Request failed with 401" not in json.dumps(payload)


def test_authenticated_hosted_origin_request_resolution_does_not_401(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-hosted-auth")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/requests/req-hosted-auth/approve",
            data=json.dumps({"scope": "artifact", "reason": "reviewed"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Origin": "https://hol.org",
                "X-Guard-Token": daemon._server.auth_token,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            allow_origin = response.headers.get("Access-Control-Allow-Origin")
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert payload["copy"]["title"] == "Decision saved. Return to Codex."
    assert "could not find the Codex session to resume" in payload["copy"]["body"]
    assert allow_origin == "https://hol.org"
    assert store.get_approval_request("req-hosted-auth")["resolution_action"] == "allow"


def test_request_list_status_filter_includes_resolved_items(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-resolved"), _request("req-pending")])
    store.resolve_approval_request(
        "req-resolved",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="reviewed",
        resolved_at="2026-05-08T10:03:00+00:00",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        resolved_page = _get_json(daemon.port, "/v1/requests?status=resolved")
        all_page = _get_json(daemon.port, "/v1/requests?status=all")
    finally:
        daemon.stop()

    assert [item["request_id"] for item in resolved_page["items"]] == ["req-resolved"]
    assert {item["request_id"] for item in all_page["items"]} == {"req-pending", "req-resolved"}


def test_request_list_limit_cursor_search_and_harness_filters(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(
        store,
        [
            _request("req-codex-command", command="cat ~/.npmrc"),
            _request("req-codex-prompt", command="", prompt_excerpt="Review plugin prompt excerpt"),
            _request("req-codex-mcp", command="", mcp_server="filesystem", mcp_tool="read_secret"),
            _request("req-copilot", harness="copilot", command="cat ~/.npmrc"),
        ],
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        first_page = _get_json(daemon.port, "/v1/requests?limit=2")
        second_page = _get_json(
            daemon.port,
            f"/v1/requests?limit=2&cursor={urllib.parse.quote(str(first_page['next_cursor']))}",
        )
        command_match = _get_json(daemon.port, "/v1/requests?search=npmrc&harness=codex")
        prompt_match = _get_json(daemon.port, "/v1/requests?search=plugin%20prompt")
        mcp_match = _get_json(daemon.port, "/v1/requests?search=read_secret")
        harness_match = _get_json(daemon.port, "/v1/requests?harness=copilot")
        bad_limit_status = None
        try:
            _get_json(daemon.port, "/v1/requests?limit=banana")
        except urllib.error.HTTPError as error:
            bad_limit_status = error.code
    finally:
        daemon.stop()

    assert [item["request_id"] for item in first_page["items"]] == ["req-copilot", "req-codex-mcp"]
    assert [item["request_id"] for item in second_page["items"]] == ["req-codex-prompt", "req-codex-command"]
    assert {item["request_id"] for item in command_match["items"]} == {"req-codex-command"}
    assert {item["request_id"] for item in prompt_match["items"]} == {"req-codex-prompt"}
    assert {item["request_id"] for item in mcp_match["items"]} == {"req-codex-mcp"}
    assert {item["request_id"] for item in harness_match["items"]} == {"req-copilot"}
    assert bad_limit_status == 400


def test_request_list_invalid_cursor_returns_recovery_error(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _populate(store, [_request("req-only")])
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        try:
            _get_json(daemon.port, "/v1/requests?cursor=not-a-valid-cursor")
        except urllib.error.HTTPError as error:
            status = error.code
            payload = json.loads(error.read().decode("utf-8"))
        else:
            raise AssertionError("expected HTTPError")
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "invalid_cursor"
    assert payload["recovery"]["code"] == "refresh_queue"
