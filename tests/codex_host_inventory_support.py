"""Private Unix host fixture for authenticated inventory tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import codex_host_inventory as inventory


def _exact(client: socket.socket, size: int) -> bytes:
    result = b""
    while len(result) < size:
        part = client.recv(size - len(result))
        if not part:
            raise EOFError
        result += part
    return result


def _request(client: socket.socket) -> dict[str, object]:
    first, second = _exact(client, 2)
    assert first == 0x81 and second & 0x80
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", _exact(client, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", _exact(client, 8))[0]
    mask = _exact(client, 4)
    payload = _exact(client, size)
    return json.loads(bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))


def _send(client: socket.socket, message: dict[str, object]) -> None:
    payload = json.dumps(message).encode()
    header = bytes([0x81, len(payload)]) if len(payload) < 126 else bytes([0x81, 126]) + struct.pack("!H", len(payload))
    client.sendall(header + payload)


@contextmanager
def _host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[dict[str, object]], dict[str, object]],
) -> Iterator[tuple[Path, list[dict[str, object]]]]:
    # Unix socket paths must fit macOS's 104-byte sockaddr_un limit as well.
    with tempfile.TemporaryDirectory(prefix="codex-", dir="/tmp") as directory:
        home = Path(directory) / ".codex"
        control = home / "app-server-control"
        control.mkdir(parents=True, mode=0o700)
        path = control / "app-server-control.sock"
        pid_path = control / "hol-guard-app-server.pid"
        pid_path.write_text(str(os.getpid()))
        pid_path.chmod(0o600)
        requests: list[dict[str, object]] = []
        failures: list[BaseException] = []
        monkeypatch.setattr(inventory, "_is_codex_process", lambda _pid: True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(1)
        listener.settimeout(1)

        def serve() -> None:
            try:
                with listener.accept()[0] as client:
                    client.settimeout(2)
                    headers = b""
                    while not headers.endswith(b"\r\n\r\n"):
                        headers += _exact(client, 1)
                    key = next(
                        line.split(b": ", 1)[1]
                        for line in headers.split(b"\r\n")
                        if line.startswith(b"Sec-WebSocket-Key:")
                    )
                    accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                    client.sendall(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
                    )
                    while True:
                        request = _request(client)
                        requests.append(request)
                        if "id" in request:
                            _send(client, handler(request))
            except (TimeoutError, EOFError, BrokenPipeError, ConnectionResetError):
                pass
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield home, requests
        finally:
            thread.join(timeout=3)
            listener.close()
            path.unlink(missing_ok=True)
            assert not thread.is_alive()
            assert not failures


def _handler(request: dict[str, object]) -> dict[str, object]:
    method = request["method"]
    if method == "initialize":
        result = {"userAgent": "codex/0.159.2"}
    elif method == "app/installed":
        result = {"apps": [{"id": "example", "runtimeName": "example-runtime", "enabled": True, "callable": True}]}
    elif method == "app/read":
        result = {
            "apps": [
                {
                    "id": "example",
                    "name": "Example connector",
                    "tools": [
                        {
                            "name": "send_message",
                            "title": "Send a message",
                            "description": "Change external content",
                            "isReadOnly": True,
                            "inputSchema": {"type": "object"},
                        },
                    ],
                }
            ],
            "missingAppIds": [],
        }
    else:
        raise AssertionError("unexpected host method")
    return {"id": request["id"], "result": result}
