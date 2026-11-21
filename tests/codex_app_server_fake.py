"""Private Codex app-server control socket for continuation tests.

The native resident only continues a thread over an owner-only Unix socket in
an owner-only directory, so tests that need a real continuation serve the
WebSocket JSON-RPC protocol here and record every message the resident sends.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

_WEBSOCKET_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_RESULTS: dict[str, dict[str, object]] = {
    "initialize": {"userAgent": "codex/0.159.2"},
    "thread/resume": {"thread": {"id": "thread-1"}},
    "turn/steer": {"turnId": "turn-1"},
    "turn/start": {"turn": {"id": "turn-2"}},
}


@dataclass
class CodexAppServer:
    """A served control socket and the messages it received."""

    codex_home: Path
    socket_path: Path
    messages: list[dict[str, object]] = field(default_factory=list)

    def continuations(self) -> list[dict[str, object]]:
        """The `turn/steer` and `turn/start` requests, in order."""

        return [message for message in self.messages if message.get("method") in {"turn/steer", "turn/start"}]


def _exact(client: socket.socket, size: int) -> bytes:
    result = b""
    while len(result) < size:
        part = client.recv(size - len(result))
        if not part:
            raise EOFError
        result += part
    return result


def _frame(client: socket.socket) -> dict[str, object] | None:
    first, second = _exact(client, 2)
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", _exact(client, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", _exact(client, 8))[0]
    mask = _exact(client, 4) if second & 0x80 else b"\0\0\0\0"
    payload = bytes(value ^ mask[index % 4] for index, value in enumerate(_exact(client, size)))
    if first & 0x0F == 0x8:
        return None
    return json.loads(payload)


def _send(client: socket.socket, message: dict[str, object]) -> None:
    payload = json.dumps(message).encode()
    size = bytes([len(payload)]) if len(payload) < 126 else bytes([126]) + struct.pack("!H", len(payload))
    header = b"\x81" + size
    client.sendall(header + payload)


def _serve_connection(client: socket.socket, messages: list[dict[str, object]]) -> None:
    client.settimeout(5)
    headers = b""
    while not headers.endswith(b"\r\n\r\n"):
        headers += _exact(client, 1)
    key = next(
        line.split(b": ", 1)[1] for line in headers.split(b"\r\n") if line.lower().startswith(b"sec-websocket-key:")
    )
    accept = base64.b64encode(hashlib.sha1(key + _WEBSOCKET_GUID).digest())
    client.sendall(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
    )
    while (message := _frame(client)) is not None:
        messages.append(message)
        if "id" in message:
            result = _RESULTS.get(str(message.get("method")), {})
            _send(client, {"jsonrpc": "2.0", "id": message["id"], "result": result})


@contextmanager
def codex_app_server() -> Iterator[CodexAppServer]:
    """Serve `<codex_home>/app-server-control/app-server-control.sock`."""

    # Unix socket paths must fit macOS's 104-byte sockaddr_un limit as well.
    with tempfile.TemporaryDirectory(prefix="cas-", dir="/tmp") as directory:
        codex_home = Path(directory)
        control = codex_home / "app-server-control"
        control.mkdir(mode=0o700)
        server = CodexAppServer(codex_home=codex_home, socket_path=control / "app-server-control.sock")
        failures: list[BaseException] = []
        stopping = threading.Event()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(server.socket_path))
        server.socket_path.chmod(0o600)
        listener.listen(4)
        listener.settimeout(0.1)

        def serve() -> None:
            while not stopping.is_set():
                try:
                    client = listener.accept()[0]
                except TimeoutError:
                    continue
                with client:
                    try:
                        _serve_connection(client, server.messages)
                    except (TimeoutError, EOFError, BrokenPipeError, ConnectionResetError):
                        pass
                    except BaseException as error:
                        failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            stopping.set()
            thread.join(timeout=10)
            listener.close()
            assert not thread.is_alive()
            assert not failures
