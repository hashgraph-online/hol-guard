"""Fixed-target TCP relay for host access to the isolated Guard lab."""

from __future__ import annotations

import os
import select
import socket
import socketserver
from typing import cast

from typing_extensions import override

_BUFFER_BYTES = 64 * 1024
_ROUTES = {
    "guard": (("0.0.0.0", 4782), ("127.0.0.1", 4781)),
    "host_relay": (("0.0.0.0", 4783), ("guard", 4782)),
}
_ROLE = os.getenv("HOL_GUARD_LAB_RELAY_ROLE")
if _ROLE not in _ROUTES:
    raise RuntimeError(f"HOL_GUARD_LAB_RELAY_ROLE must be 'guard' or 'host_relay', got {_ROLE!r}")
_LISTEN_ADDRESS, _TARGET_ADDRESS = _ROUTES[_ROLE]


class _RelayHandler(socketserver.BaseRequestHandler):
    @override
    def handle(self) -> None:
        client = cast(socket.socket, self.request)
        with socket.create_connection(_TARGET_ADDRESS, timeout=5) as target:
            sockets = (client, target)
            while True:
                readable, _, _ = select.select(sockets, (), ())
                for source in readable:
                    try:
                        payload = source.recv(_BUFFER_BYTES)
                    except ConnectionResetError:
                        return
                    if not payload:
                        return
                    destination = target if source is client else client
                    _ = destination.sendall(payload)


class _RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address: bool = True
    daemon_threads: bool = True


if __name__ == "__main__":
    with _RelayServer(_LISTEN_ADDRESS, _RelayHandler) as server:
        server.serve_forever(poll_interval=0.25)
