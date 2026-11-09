"""Serves the daemon's request handlers on a loopback port for tests and probes.

The production daemon is the native runtime (``hol-guard-runtime daemon-serve``);
it answers what it owns and replays the rest through the Python handlers. This
harness serves those same handlers in-process, with the replay server's state,
so a test can drive them over HTTP and patch what they call. It runs no
background workers and makes no lifecycle promises.
"""

from __future__ import annotations

import hmac
import os
import socket
import socketserver
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from codex_plugin_scanner.guard.store import GuardStore

_CHALLENGE_PATH = "/v1/daemon/identity-challenge"


def _server_class() -> type:
    from codex_plugin_scanner.guard.daemon.request_replay import _replay_server_class
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

    replay = _replay_server_class()

    class HarnessHandler(_GuardDaemonHandler):  # type: ignore[misc, valid-type]
        """The daemon's handlers, plus the identity challenge the native edge answers.

        A codex hook bridge proves the daemon it reaches before it sends a
        hook; the native daemon answers that challenge in front of the
        handlers, so the harness answers it the way the Python daemon did.
        """

        def do_POST(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler's name
            if urlparse(self.path).path != _CHALLENGE_PATH:
                super().do_POST()
                return
            payload, body_error = self._load_request_body()
            if body_error is not None or not isinstance(payload, dict):
                self._write_json({"error": "invalid_daemon_identity_challenge"}, status=400)
                return
            self._answer_identity_challenge(payload)

        def _answer_identity_challenge(self, payload: dict[str, object]) -> None:
            from codex_plugin_scanner.guard.daemon.discovery import (
                DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS,
                DAEMON_DISCOVERY_PROTOCOL_VERSION,
                authenticated_challenge_payload,
                load_authenticated_daemon_state,
                load_daemon_discovery_key,
            )

            nonce, hook_event, state_id = (payload.get(name) for name in ("nonce", "hook_event", "state_id"))
            if (
                not isinstance(nonce, str)
                or len(nonce) != 64
                or any(character not in "0123456789abcdef" for character in nonce.lower())
                or not isinstance(hook_event, str)
                or len(hook_event) > 128
                or not isinstance(state_id, str)
                or payload.get("protocol_version") != DAEMON_DISCOVERY_PROTOCOL_VERSION
            ):
                self._write_json({"error": "invalid_daemon_identity_challenge"}, status=400)
                return
            server: Any = self.server
            guard_home = server.store.guard_home
            state = load_authenticated_daemon_state(guard_home)
            discovery_key = load_daemon_discovery_key(guard_home)
            if state is None or discovery_key is None:
                self._write_json({"error": "daemon_identity_unavailable"}, status=503)
                return
            if (
                state.get("state_id") != state_id
                or state.get("guard_home") != str(guard_home.resolve())
                or state.get("host") != server.daemon_host()
                or state.get("port") != server.daemon_port()
                or state.get("pid") != os.getpid()
            ):
                self._write_json({"error": "daemon_identity_state_mismatch"}, status=409)
                return
            issued_at_ms = int(time.time() * 1000)
            expires_at_ms = issued_at_ms + DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS * 1000
            response = authenticated_challenge_payload(
                discovery_key=discovery_key,
                state=state,
                nonce=nonce,
                hook_event=hook_event,
                issued_at_ms=issued_at_ms,
                expires_at_ms=expires_at_ms,
            )
            with server.identity_challenges_lock:
                server.identity_challenges[nonce] = {
                    "proof": response["proof"],
                    "hook_event": hook_event,
                    "expires_at_ms": expires_at_ms,
                    "connection_id": id(self.connection),
                }
            # The hook that redeems the proof follows on this connection.
            self.close_connection = False
            self.connection.settimeout(DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS)
            previous_protocol_version = self.protocol_version
            self.protocol_version = "HTTP/1.1"
            try:
                self._write_json(response, extra_headers={"Cache-Control": "no-store"})
            finally:
                self.protocol_version = previous_protocol_version

        def _consume_codex_daemon_challenge(self, payload: dict[str, object]) -> bool:
            nonce = self.headers.get("X-Guard-Daemon-Nonce")
            proof = self.headers.get("X-Guard-Daemon-Proof")
            if not isinstance(nonce, str) or not isinstance(proof, str):
                return False
            server: Any = self.server
            with server.identity_challenges_lock:
                challenge = server.identity_challenges.pop(nonce, None)
            if (
                challenge is None
                or challenge["expires_at_ms"] < int(time.time() * 1000)
                or challenge["connection_id"] != id(self.connection)
                or not hmac.compare_digest(proof, challenge["proof"])
            ):
                return False
            event = payload.get("hook_event_name", payload.get("event"))
            return isinstance(event, str) and event.strip() == challenge["hook_event"]

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
            socketserver.BaseServer.__init__(self, (host, port), HarnessHandler)
            self.identity_challenges: dict[str, dict[str, Any]] = {}
            self.identity_challenges_lock = threading.Lock()
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
            # The published state names this server's session, and the
            # identity challenge proves it, as the daemon's own did.
            if not self.runtime_session_id:
                self.runtime_session_id = uuid.uuid4().hex
                self.runtime_started_at = datetime.now(timezone.utc).isoformat()

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


def _start_policy_publication(store: GuardStore, home_dir: Path) -> Any:
    """Admit the installed release, then publish the native policy as the daemon does.

    The native daemon's startup enrolls the extension-control authority and
    its worker host keeps the native policy snapshot published; handlers that
    reach the resident read that snapshot.
    """

    from codex_plugin_scanner.guard.daemon.hook_evidence_dispatch import HookEvidenceDispatch
    from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
    from codex_plugin_scanner.guard.extension_control_host import host_for
    from codex_plugin_scanner.guard.native_hook_evidence_writer import NativeHookEvidenceWriter

    host_for(store)
    return HookWorker(
        store=store,
        home_dir=home_dir,
        activity_writer=NativeHookEvidenceWriter(store=store),
        evidence_dispatch=HookEvidenceDispatch(),
        capture_writer=None,
    )


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
        try:
            self._hook_worker = _start_policy_publication(store, self._server.home_dir)
        except BaseException:
            self._server.server_close()
            raise

    @property
    def auth_token(self) -> str:
        return str(self._server.auth_token)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="guard-daemon-harness")
        self._thread.start()
        self._publish_state()

    def _publish_state(self) -> None:
        """Publish where this daemon listens, as the daemon did once it served.

        A hook bridge the resident defers finds the daemon through this state.
        """

        from codex_plugin_scanner.guard.daemon.manager import write_guard_daemon_state

        server = self._server
        write_guard_daemon_state(
            self.store.guard_home,
            self.port,
            server.auth_token,
            write_auth_token=False,
            host=server.daemon_host(),
            state_id=server.runtime_session_id,
            started_at=server.runtime_started_at,
            trust_status=self.store.get_cached_policy_integrity_state(),
        )

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
        if thread is not None:
            from codex_plugin_scanner.guard.daemon.manager import clear_guard_daemon_state_if_current

            clear_guard_daemon_state_if_current(self.store.guard_home, pid=os.getpid(), port=self.port)
        hook_worker = self._hook_worker
        self._hook_worker = None
        if hook_worker is not None:
            hook_worker.close(deadline_monotonic=time.monotonic() + 5.0)

    def _finish_service(self) -> bool:
        """Whether the handlers have stopped serving; probes confirm cleanup with it."""

        return self._stopped and self._thread is None

    def _is_quarantined(self) -> bool:
        return False


__all__ = ["GuardDaemonServer"]
