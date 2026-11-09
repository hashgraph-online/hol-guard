"""Serves the daemon's request handlers on a loopback port for tests and probes.

The production daemon is the native runtime (``hol-guard-runtime daemon-serve``);
it answers what it owns and replays the rest through the Python handlers. This
harness serves those same handlers in-process, with the replay server's state,
so a test can drive them over HTTP and patch what they call. It runs no
background workers and makes no lifecycle promises.
"""

from __future__ import annotations

import socket
import socketserver
import threading
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.store import GuardStore


def _server_class() -> type:
    from codex_plugin_scanner.guard.daemon.request_replay import _replay_server_class
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

    replay = _replay_server_class()

    class HarnessServer(replay, socketserver.TCPServer):  # type: ignore[misc, valid-type]
        daemon_threads = True
        allow_reuse_address = False

        def __init__(  # pyright: ignore[reportMissingSuperCall]
            self,
            store: GuardStore,
            host: str,
            port: int,
            *,
            home_dir: Path,
            workspace_dir: Path | None,
            idle_timeout_seconds: float | None,
            auth_key: str,
        ) -> None:
            replay.__init__(self, store, port, host, home_dir, auth_key)
            socketserver.BaseServer.__init__(self, (host, port), _GuardDaemonHandler)
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            self.socket = socket.socket(family, socket.SOCK_STREAM)
            try:
                self.server_bind()
                self.server_activate()
            except BaseException:
                self.socket.close()
                raise
            self.workspace_dir = workspace_dir.expanduser().resolve(strict=False) if workspace_dir else None
            self.idle_timeout_seconds = idle_timeout_seconds
            self._replay_daemon_pid = None

        def server_bind(self) -> None:
            socketserver.TCPServer.server_bind(self)
            host, port = self.socket.getsockname()[:2]
            self.server_name = socket.getfqdn(host)
            self.server_port = port

        def process_request(self, request: Any, client_address: Any) -> None:
            thread = threading.Thread(
                target=self._serve_one,
                args=(request, client_address),
                daemon=True,
                name="guard-daemon-harness-request",
            )
            thread.start()

        def _serve_one(self, request: Any, client_address: Any) -> None:
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                self.shutdown_request(request)

        def serve_forever(self, poll_interval: float = 0.5) -> None:
            socketserver.BaseServer.serve_forever(self, poll_interval)

        def shutdown(self) -> None:
            socketserver.BaseServer.shutdown(self)

        def request_serve_stop(self) -> None:
            self.shutdown_started.set()

        def server_close(self) -> None:
            socketserver.TCPServer.server_close(self)
            self.audit_persistence.close()
            replay.server_close(self)

        def daemon_port(self) -> int:
            return int(self.server_address[1])

    return HarnessServer


class GuardDaemonServer:
    """Starts and stops the handlers on ``host:port`` (0 picks a free port)."""

    def __init__(
        self,
        store: GuardStore,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        idle_timeout_seconds: float | None = None,
        home_dir: Path | None = None,
        workspace_dir: Path | None = None,
        **_retired: object,
    ) -> None:
        from codex_plugin_scanner.guard.daemon.manager import ensure_guard_daemon_auth_token

        self.store = store
        self._server = _server_class()(
            store,
            host,
            port,
            home_dir=(home_dir or Path.home()).expanduser().resolve(strict=False),
            workspace_dir=workspace_dir,
            idle_timeout_seconds=idle_timeout_seconds,
            auth_key=ensure_guard_daemon_auth_token(store.guard_home),
        )
        self.port = self._server.daemon_port()
        self._thread: threading.Thread | None = None
        self._stopped = False

    @property
    def auth_token(self) -> str:
        return str(self._server.auth_token)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="guard-daemon-harness")
        self._thread.start()

    def serve(self) -> None:
        self._server.serve_forever()

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        thread = self._thread
        if thread is not None:
            self._server.shutdown()
            thread.join(timeout=5)
            self._thread = None
        self._server.server_close()

    def _finish_service(self) -> bool:
        """Whether the handlers have stopped serving; probes confirm cleanup with it."""

        return self._stopped and self._thread is None

    def _is_quarantined(self) -> bool:
        return False


__all__ = ["GuardDaemonServer"]
