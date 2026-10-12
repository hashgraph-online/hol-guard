"""Loopback Cloud endpoint that accepts connections and never answers.

The resident's evaluation request times out against it, which exercises the
real ``cloud_timeout`` availability path instead of a mocked Python transport.
One daemon listener serves the whole test process.
"""

from __future__ import annotations

import socket
import threading

_lock = threading.Lock()
_state: dict[str, object] = {}


def _accept_forever(listener: socket.socket) -> None:
    held: list[socket.socket] = []
    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        held.append(connection)


def silent_cloud_sync_url() -> str:
    with _lock:
        url = _state.get("url")
        if isinstance(url, str):
            return url
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        threading.Thread(target=_accept_forever, args=(listener,), daemon=True).start()
        url = f"http://127.0.0.1:{listener.getsockname()[1]}/api/guard/receipts/sync"
        _state["listener"] = listener
        _state["url"] = url
        return url
