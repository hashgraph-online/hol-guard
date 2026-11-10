"""Runtime hooks the native daemon hands to the hook worker.

The native daemon owns the socket, the identity proof and the caller check
for ``POST /v1/hooks/<harness>`` and its readiness route. What it cannot
answer from the resident's direct lane it hands here: this call admits the
hook under its deadline and the scheduler's capacity, reviews it with the
hook worker, and keeps the one reply the route writes.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..store import GuardStore
from .calls import RouteReplyError

_NO_STORE_VALUES = frozenset({"no-store", "no-store, max-age=0"})


def _host_class() -> type:
    from ..daemon.server_runtime_hook import _RuntimeHookRoutes

    class HookHost(_RuntimeHookRoutes):
        """Stands in for the daemon's request handler and keeps the reply."""

        def __init__(self, server: Any, path: str, direct_miss: str | None) -> None:
            self.server = server
            self.path = path
            self.command = "POST"
            self.request = None
            self.headers = {"X-Guard-Direct-Miss": direct_miss} if direct_miss else {}
            self._reply: dict[str, object] | None = None

        def _write_json(
            self,
            payload: dict[str, Any],
            *,
            status: int = 200,
            extra_headers: Mapping[str, str] | None = None,
        ) -> None:
            if self._reply is not None:
                raise RouteReplyError("second_reply")
            cache = dict(extra_headers or {}).get("Cache-Control")
            self._reply = {"status": status, "body": dict(payload), "no_store": cache in _NO_STORE_VALUES}

        def _daemon_server(self) -> Any:
            return self.server

        def _record_bounded_denial_event(self, event_name: str, payload: dict[str, object]) -> None:
            from ..daemon.server_common import _now

            server = self.server
            with server.denial_audit_lock:
                _ = server.audit_persistence.persist(event_name, payload, _now())

        @staticmethod
        def _optional_string(value: object) -> str | None:
            if isinstance(value, str) and value.strip():
                return value.strip()
            return None

        def reply(self) -> dict[str, object]:
            if self._reply is None:
                raise RouteReplyError("no_reply")
            return self._reply

    return HookHost


_HOST_CLASSES: dict[str, type] = {}


def hook_post(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Answers ``POST /v1/hooks/<harness>[/readiness]`` as the daemon's handler does."""

    from ..daemon.auth_token import load_guard_daemon_auth_token
    from ..library_calls import LibraryCallError
    from .request_host import _replay_server_class

    path = args.get("path")
    query = args.get("query")
    payload = args.get("payload")
    port = args.get("port")
    home_dir = args.get("home_dir")
    direct_miss = args.get("direct_miss")
    parts = [part for part in path.split("/") if part] if isinstance(path, str) else []
    readiness = len(parts) == 4 and parts[3] == "readiness"
    if (
        parts[:2] != ["v1", "hooks"]
        or len(parts) not in {3, 4}
        or (len(parts) == 4 and not readiness)
        or not isinstance(query, str)
        or not isinstance(payload, dict)
        or not isinstance(port, int)
        or not (home_dir is None or isinstance(home_dir, str))
        or not (direct_miss is None or isinstance(direct_miss, str))
    ):
        raise LibraryCallError("invalid_arguments")
    host_class = _HOST_CLASSES.get("hook")
    if host_class is None:
        host_class = _HOST_CLASSES.setdefault("hook", _host_class())
    daemon_pid = args.get("daemon_pid")
    server = _replay_server_class()(
        store,
        port,
        "127.0.0.1",
        Path(home_dir) if home_dir else Path.home(),
        load_guard_daemon_auth_token(store.guard_home) or "",
        daemon_pid if isinstance(daemon_pid, int) else None,
        args.get("proof_verified") is True,
    )
    try:
        host = host_class(server, path, direct_miss)
        if readiness:
            host._handle_hook_readiness(payload, query, default_harness=parts[2])
        else:
            host._handle_runtime_hook(payload, query, default_harness=parts[2])
        return host.reply()
    finally:
        server.server_close()


HOOK_HOST_CALLS = {"route.hook_post": hook_post}
