"""Serves the native Guard daemon on a loopback port for tests and probes.

The production daemon is the native runtime (``hol-guard-runtime daemon-serve``);
this harness starts it on a loopback port and answers the Guard library calls
it makes inside the test process, so a test can drive the daemon over HTTP and
patch the library work its routes hand off.
"""

from __future__ import annotations

import hmac
import socket
import threading
import uuid
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.store import GuardStore


class _LibraryCallServer:
    """Answers the native daemon's library calls inside the test process.

    ``ci/native_library_bridge.py`` is the daemon's CLI command; it sends each
    ``desktop library-call`` and ``desktop library-serve`` here, so the Guard
    library work a route hands off runs where the test's patches apply.
    """

    def __init__(self) -> None:
        self.nonce = uuid.uuid4().hex
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = int(self._listener.getsockname()[1])
        self._closed = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def cli_command(self) -> list[str]:
        import json
        import sys

        from codex_plugin_scanner.guard.daemon.native_edge_handshake import guard_cli_command

        bridge = Path(__file__).with_name("native_library_bridge.py").resolve()
        cli = guard_cli_command() or [sys.executable, "-m", "codex_plugin_scanner.cli"]
        return [sys.executable, str(bridge), str(self.port), self.nonce, json.dumps(cli)]

    def close(self) -> None:
        self._closed.set()
        self._listener.close()

    def _accept(self) -> None:
        while not self._closed.is_set():
            try:
                connection, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection: socket.socket) -> None:
        import json

        from codex_plugin_scanner.guard.library_calls import run_library_call

        with connection, connection.makefile("rb") as reader:
            try:
                header = json.loads(reader.readline())
            except ValueError:
                return
            if not isinstance(header, dict) or not hmac.compare_digest(str(header.get("nonce")), self.nonce):
                return
            guard_home = Path(str(header.get("guard_home")))

            def answer(request: bytes) -> bytes:
                result = run_library_call(guard_home, request)
                return json.dumps(result, separators=(",", ":"), default=str).encode("utf-8")

            if header.get("mode") == "library-serve":
                from codex_plugin_scanner.guard.cli.desktop_library_call import serve_lines

                serve_lines(guard_home, reader.readline, connection.sendall)
                return
            request = reader.read()
            if request:
                connection.sendall(answer(request))
            connection.shutdown(socket.SHUT_WR)
        from codex_plugin_scanner.guard.routes.request_host import wait_for_background_work

        wait_for_background_work()


class _NativeServerView:
    """Server attributes tests read or seed, from the native daemon.

    Anything beyond ``store`` and ``auth_token`` comes from the request host
    the daemon's library calls build, so state it keeps on disk, such as the
    connect flows, is shared with the calls the daemon makes.
    """

    def __init__(self, daemon: Any) -> None:
        object.__setattr__(self, "_daemon", daemon)
        object.__setattr__(self, "store", daemon.store)
        object.__setattr__(self, "_host", None)

    @property
    def auth_token(self) -> str:
        return str(self._daemon.auth_token)

    def _request_host(self) -> Any:
        host = self.__dict__["_host"]
        if host is None:
            from codex_plugin_scanner.guard.routes.request_host import _replay_server_class

            home_dir = Path(self._daemon.home_dir) if self._daemon.home_dir is not None else Path.home()
            # Tests may seed state before the daemon starts and publishes its
            # credential; the host only needs it to answer requests.
            try:
                auth = self.auth_token
            except RuntimeError:
                auth = ""
            host = _replay_server_class()(self.store, int(self._daemon.port), "127.0.0.1", home_dir, auth)
            object.__setattr__(self, "_host", host)
        return host

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        return getattr(self._request_host(), name)

    def __setattr__(self, name: str, value: object) -> None:
        setattr(self._request_host(), name, value)


class GuardDaemonServer:
    """The native daemon process on ``host:port`` (0 picks a free port)."""

    def __init__(
        self,
        store: GuardStore,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        home_dir: Path | None = None,
        **_retired: object,
    ) -> None:
        from ci.native_daemon_harness import NativeGuardDaemon

        self.store = store
        self._library = _LibraryCallServer()
        self._daemon = NativeGuardDaemon(store, host, port, home_dir=home_dir, cli_command=self._library.cli_command())
        self.port = port
        self._server = _NativeServerView(self._daemon)

    @property
    def auth_token(self) -> str:
        return str(self._daemon.auth_token)

    def start(self) -> None:
        self._daemon.start()
        self.port = self._daemon.port

    def stop(self) -> None:
        self._daemon.stop()
        self._library.close()

    def _finish_service(self) -> bool:
        return self._daemon._process is None

    def _is_quarantined(self) -> bool:
        return False


__all__ = ["GuardDaemonServer"]
