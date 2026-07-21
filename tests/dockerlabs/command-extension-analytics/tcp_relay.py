"""Fixed-target TCP relay for host access to the isolated Guard lab."""

from __future__ import annotations

import select
import socket
import socketserver
from contextlib import suppress
from typing import cast

from typing_extensions import override

_BUFFER_BYTES = 64 * 1024
_LISTEN_ADDRESS = ("0.0.0.0", 4781)
_TARGET_ADDRESS = ("guard", 4781)


class _RelayHandler(socketserver.BaseRequestHandler):
    @override
    def handle(self) -> None:
        client = cast(socket.socket, self.request)
        with socket.create_connection(_TARGET_ADDRESS, timeout=5) as target:
            sockets = (client, target)
            active = set(sockets)
            while active:
                readable, _, _ = select.select(tuple(active), (), (), 30)
                if not readable:
                    for endpoint in active:
                        with suppress(OSError):
                            endpoint.shutdown(socket.SHUT_WR)
                    return
                for source in readable:
                    try:
                        payload = source.recv(_BUFFER_BYTES)
                    except ConnectionResetError:
                        payload = b""
                    destination = target if source is client else client
                    if not payload:
                        active.remove(source)
                        with suppress(OSError):
                            destination.shutdown(socket.SHUT_WR)
                        continue
                    _ = destination.sendall(payload)


class _RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address: bool = True
    daemon_threads: bool = True


if __name__ == "__main__":
    with _RelayServer(_LISTEN_ADDRESS, _RelayHandler) as server:
        server.serve_forever(poll_interval=0.25)
