"""Record parity vectors for the resident ``codex_thread_continue`` op.

The vectors pin the behavior of the Python Codex app-server continuation
(``resume_codex_thread_for_request`` in ``guard/codex_app_server.py``) as it
existed before the resident took it over. Each scenario runs the old Python
client against a scripted fake app-server on a private Unix socket and records
the returned result plus every JSON-RPC message the client sent on each
connection. The Rust vectors test replays the same scripts against the op.

Run from a checkout of the base commit that still has the Python client:

    uv run --no-sync python \
        rust/crates/guard-runtime/testdata/codex_app_server/record_codex_thread_continue_vectors.py

It rewrites ``codex_thread_continue_vectors.json`` next to this script.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(_REPO / "src"))

from codex_plugin_scanner.guard import codex_app_server  # noqa: E402

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_OUTPUT = Path(__file__).with_name("codex_thread_continue_vectors.json")
_TIMEOUT_SECONDS = 2.0
_SOCKET_TOKEN = "${SOCKET}"
_DIR_TOKEN = "${SOCKET_DIR}"


def _ok(request_id: int = 3, result: object | None = None) -> dict[str, object]:
    return {"text": json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result or {"turn": {"id": "t-1"}}})}


def _error(message: object = "rejected") -> dict[str, object]:
    error: dict[str, object] = {"code": -32000}
    if message is not None:
        error["message"] = message
    return {"text": json.dumps({"jsonrpc": "2.0", "id": 3, "error": error})}


def _conn(*replies: dict[str, object], handshake: str = "ok") -> dict[str, object]:
    return {"handshake": handshake, "replies": list(replies)}


def _meta(**extra: object) -> dict[str, object]:
    metadata: dict[str, object] = {"codex_thread_id": "thread-1", "codex_app_server_socket": _SOCKET_TOKEN}
    metadata.update(extra)
    return {key: value for key, value in metadata.items() if value is not None}


SCENARIOS: list[dict[str, object]] = [
    {"name": "turn_start_sent", "metadata": _meta(), "connections": [_conn(_ok())]},
    {"name": "turn_start_block", "action": "block", "metadata": _meta(), "connections": [_conn(_ok())]},
    {
        "name": "turn_start_with_command_text",
        "metadata": _meta(command_text="  npm publish  "),
        "connections": [_conn(_ok())],
    },
    {
        "name": "block_with_command_text_camel",
        "action": "deny",
        "metadata": _meta(commandText="rm -rf build"),
        "connections": [_conn(_ok())],
    },
    {
        "name": "steer_sent",
        "metadata": _meta(codex_turn_id="turn-9"),
        "connections": [_conn(_ok())],
    },
    {
        "name": "steer_error_falls_back_to_turn_start",
        "metadata": _meta(turnId="turn-9"),
        "connections": [_conn(_error("no active turn")), _conn(_ok())],
    },
    {
        "name": "steer_eof_falls_back_to_turn_start",
        "metadata": _meta(turn_id="turn-9"),
        "connections": [_conn({"eof": True}), _conn(_ok())],
    },
    {
        "name": "steer_bad_upgrade_falls_back",
        "metadata": _meta(turn_id="turn-9"),
        "connections": [_conn(handshake="bad_status"), _conn(_ok())],
    },
    {
        "name": "steer_and_turn_both_fail",
        "metadata": _meta(turn_id="turn-9"),
        "connections": [_conn(_error("no active turn")), _conn(_error("thread busy"))],
    },
    {"name": "turn_start_error_message", "metadata": _meta(), "connections": [_conn(_error("thread busy"))]},
    {"name": "turn_start_error_without_message", "metadata": _meta(), "connections": [_conn(_error(None))]},
    {"name": "turn_start_error_non_string_message", "metadata": _meta(), "connections": [_conn(_error(42))]},
    {
        "name": "turn_start_error_not_object",
        "metadata": _meta(),
        "connections": [_conn({"text": json.dumps({"id": 3, "error": "nope"})})],
    },
    {"name": "no_response_times_out", "metadata": _meta(), "connections": [_conn({"hold": 3.0})]},
    {"name": "close_frame_before_response", "metadata": _meta(), "connections": [_conn({"close_frame": True})]},
    {"name": "eof_before_response", "metadata": _meta(), "connections": [_conn({"eof": True})]},
    {"name": "bad_upgrade_status", "metadata": _meta(), "connections": [_conn(handshake="bad_status")]},
    {"name": "bad_accept_header", "metadata": _meta(), "connections": [_conn(handshake="bad_accept")]},
    {"name": "eof_during_handshake", "metadata": _meta(), "connections": [_conn(handshake="eof")]},
    {
        "name": "ping_answered_then_response",
        "metadata": _meta(),
        "connections": [_conn({"ping": "keepalive"}, _ok())],
    },
    {
        "name": "ignores_noise_before_response",
        "metadata": _meta(),
        "connections": [
            _conn(
                {"raw_text": "not json"},
                {"text": json.dumps({"method": "thread/started", "params": {"threadId": "thread-1"}})},
                {"binary": "AAEC"},
                {"text": json.dumps([1, 2, 3])},
                _ok(1, {"userAgent": "codex"}),
                _ok(2, {"thread": {"id": "thread-1"}}),
                {"text": json.dumps({"id": "3", "result": {}})},
                _ok(),
            )
        ],
    },
    {"name": "float_response_id", "metadata": _meta(), "connections": [_conn({"text": '{"id":3.0,"result":{}}'})]},
    {"name": "invalid_utf8_text_frame", "metadata": _meta(), "connections": [_conn({"text_bytes": "gIE="})]},
    {
        "name": "steer_invalid_utf8_falls_back",
        "metadata": _meta(turn_id="turn-9"),
        "connections": [_conn({"text_bytes": "/w=="}), _conn(_ok())],
    },
    {
        "name": "steer_close_frame_falls_back",
        "metadata": _meta(turn_id="turn-9"),
        "connections": [_conn({"close_frame": True}), _conn(_ok())],
    },
    {
        "name": "masked_server_frame",
        "metadata": _meta(),
        "connections": [_conn({"masked_text": json.dumps({"id": 3, "result": {}})})],
    },
    {"name": "large_frame_rejected", "metadata": _meta(), "connections": [_conn({"oversized": True})]},
    {
        "name": "medium_frame_accepted",
        "metadata": _meta(),
        "connections": [_conn({"text": json.dumps({"id": 3, "result": {"pad": "x" * 70000}})})],
    },
    {
        "name": "thread_id_aliases_and_strip",
        "metadata": {
            "threadId": "\x1f thread-alias 　",
            "codex_thread_id": "   ",
            "appServerSocket": _SOCKET_TOKEN,
            "codexModel": "gpt",
        },
        "connections": [_conn(_ok())],
    },
    {
        "name": "unicode_thread_id_is_alnum",
        "metadata": _meta(codex_thread_id="thé٣-Ⅷ"),
        "connections": [_conn(_ok())],
    },
    {"name": "unsafe_thread_id_symbol", "metadata": _meta(codex_thread_id="thread/1"), "socket": "none"},
    {"name": "unsafe_thread_id_dash", "metadata": _meta(codex_thread_id="-thread"), "socket": "none"},
    {"name": "unsafe_thread_id_too_long", "metadata": _meta(codex_thread_id="a" * 257), "socket": "none"},
    {"name": "unsafe_thread_id_combining", "metadata": _meta(codex_thread_id="aͅb"), "socket": "none"},
    {"name": "max_length_thread_id", "metadata": _meta(codex_thread_id="b" * 256), "connections": [_conn(_ok())]},
    {"name": "missing_thread_id", "metadata": {"codex_app_server_socket": _SOCKET_TOKEN}, "socket": "none"},
    {"name": "non_string_thread_id", "metadata": _meta(codex_thread_id=7), "socket": "none"},
    {
        "name": "session_id_is_thread_alias",
        "metadata": {"sessionId": "session-5", "codex_app_server_socket": _SOCKET_TOKEN},
        "connections": [_conn(_ok())],
    },
    {"name": "unsafe_socket_path", "metadata": _meta(codex_app_server_socket="/etc/codex.sock"), "socket": "none"},
    {
        "name": "unsafe_socket_path_traversal",
        "metadata": _meta(codex_app_server_socket=_DIR_TOKEN + "/../../../etc/codex.sock"),
        "socket": "none",
    },
    {"name": "socket_not_available", "metadata": _meta(), "socket": "missing"},
    {"name": "socket_path_is_regular_file", "metadata": _meta(), "socket": "regular_file"},
    {"name": "socket_parent_group_writable", "metadata": _meta(), "socket": "loose_parent"},
    {"name": "stale_socket_without_listener", "metadata": _meta(), "socket": "stale"},
    {
        "name": "default_socket_from_codex_home",
        "metadata": {"codex_thread_id": "thread-1", "codex_home": _DIR_TOKEN + "/codex-home"},
        "socket": "codex_home",
        "connections": [_conn(_ok())],
    },
]


def _recv_exact(client: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = client.recv(length - len(data))
        if not chunk:
            raise ConnectionError("client closed")
        data += chunk
    return data


def _read_client_frame(client: socket.socket) -> tuple[int, bytes]:
    first, second = _recv_exact(client, 2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(client, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(client, 8))[0]
    mask = _recv_exact(client, 4)
    payload = _recv_exact(client, length)
    return first & 0x0F, bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))


def _server_frame(opcode: int, payload: bytes) -> bytes:
    length = len(payload)
    if length < 126:
        header = bytes([0x80 | opcode, length])
    elif length < 65_536:
        header = bytes([0x80 | opcode, 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x80 | opcode, 127]) + struct.pack("!Q", length)
    return header + payload


def _serve_connection(client: socket.socket, script: dict[str, object], record: dict[str, object]) -> None:
    request = b""
    while b"\r\n\r\n" not in request:
        chunk = client.recv(4096)
        if not chunk:
            return
        request += chunk
    handshake = script["handshake"]
    if handshake == "eof":
        return
    key = ""
    for line in request.decode("ascii").split("\r\n")[1:]:
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    accept = base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")
    if handshake == "bad_status":
        client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        return
    if handshake == "bad_accept":
        accept = base64.b64encode(b"wrong" * 4).decode("ascii")
    client.sendall(
        (
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("ascii")
    )
    if handshake == "bad_accept":
        return
    received: list[object] = record.setdefault("received", [])  # type: ignore[assignment]
    while len(received) < 4:
        opcode, payload = _read_client_frame(client)
        if opcode == 0x1:
            received.append(json.loads(payload.decode("utf-8")))
    for reply in script["replies"]:  # type: ignore[union-attr]
        if not isinstance(reply, dict):
            continue
        if reply.get("eof"):
            return
        if "hold" in reply:
            time.sleep(float(reply["hold"]))  # type: ignore[arg-type]
            return
        if reply.get("close_frame"):
            client.sendall(_server_frame(0x8, b""))
            return
        if "ping" in reply:
            client.sendall(_server_frame(0x9, str(reply["ping"]).encode()))
            opcode, payload = _read_client_frame(client)
            record.setdefault("pongs", []).append({"opcode": opcode, "payload": payload.decode()})  # type: ignore[union-attr]
            continue
        if "text_bytes" in reply:
            client.sendall(_server_frame(0x1, base64.b64decode(str(reply["text_bytes"]))))
            continue
        if "masked_text" in reply:
            mask = b"\x01\x02\x03\x04"
            data = str(reply["masked_text"]).encode("utf-8")
            masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
            client.sendall(bytes([0x81, 0x80 | len(data)]) + mask + masked)
            continue
        if "binary" in reply:
            client.sendall(_server_frame(0x2, base64.b64decode(str(reply["binary"]))))
            continue
        if reply.get("oversized"):
            client.sendall(bytes([0x81, 127]) + struct.pack("!Q", 1_000_001))
            continue
        text = reply.get("raw_text", reply.get("text"))
        client.sendall(_server_frame(0x1, str(text).encode("utf-8")))
    client.settimeout(0.5)
    try:
        while client.recv(4096):
            pass
    except OSError:
        pass


def _serve(listener: socket.socket, connections: list[dict[str, object]], records: list[dict[str, object]]) -> None:
    for script in connections:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        record: dict[str, object] = {}
        records.append(record)
        with client, contextlib.suppress(OSError, ConnectionError, ValueError):
            _serve_connection(client, script, record)


class _Store:
    def __init__(self, metadata: object) -> None:
        self._operation = {"harness": "codex", "metadata": metadata, "approval_request_ids": ["req-1"]}

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
        return self._operation if request_id == "req-1" else None

    def list_guard_operations(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        return [self._operation]


def _substitute(value: object, replacements: dict[str, str]) -> object:
    if isinstance(value, str):
        for token, replacement in replacements.items():
            value = value.replace(token, replacement)
        return value
    if isinstance(value, dict):
        return {key: _substitute(item, replacements) for key, item in value.items()}
    return value


def _run(scenario: dict[str, object]) -> dict[str, object]:
    base = Path(tempfile.mkdtemp(prefix="cx", dir="/tmp"))
    os.chmod(base, 0o700)
    socket_path = base / "s.sock"
    mode = scenario.get("socket", "server")
    if mode == "codex_home":
        control = base / "codex-home" / "app-server-control"
        control.mkdir(parents=True, mode=0o700)
        socket_path = control / "app-server-control.sock"
    replacements = {_SOCKET_TOKEN: str(socket_path), _DIR_TOKEN: str(base)}
    metadata = _substitute(scenario["metadata"], replacements)
    listener: socket.socket | None = None
    records: list[dict[str, object]] = []
    server: threading.Thread | None = None
    if mode in {"server", "codex_home", "stale", "loose_parent"}:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(4)
        if mode == "stale":
            listener.close()
            listener = None
        elif mode == "loose_parent":
            os.chmod(base, 0o770)
        else:
            server = threading.Thread(
                target=_serve, args=(listener, list(scenario.get("connections", [])), records), daemon=True
            )
            server.start()
    elif mode == "regular_file":
        socket_path.write_text("", encoding="utf-8")
    try:
        result = codex_app_server.resume_codex_thread_for_request(
            store=_Store(metadata),
            request_id="req-1",
            action=str(scenario.get("action", "allow")),
            timeout_seconds=_TIMEOUT_SECONDS,
        )
    finally:
        if listener is not None:
            listener.close()
        if server is not None:
            server.join(timeout=5)
    return {
        "name": scenario["name"],
        "action": scenario.get("action", "allow"),
        "socket": mode,
        "metadata": scenario["metadata"],
        "connections": scenario.get("connections", []),
        "expected": {"result": result, "server": records},
    }


def main() -> int:
    vectors = [_run(scenario) for scenario in SCENARIOS]
    document = {
        "schema": "guard-codex-thread-continue-vectors.v1",
        "source": "guard/codex_app_server.py resume_codex_thread_for_request (pre-resident Python)",
        "request_id": "req-1",
        "timeout_seconds": _TIMEOUT_SECONDS,
        "vectors": vectors,
    }
    _OUTPUT.write_text(json.dumps(document, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"recorded {len(vectors)} vectors -> {_OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
