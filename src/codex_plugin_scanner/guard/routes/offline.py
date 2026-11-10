"""The daemon's own route dispatch, run once per request behind ``desktop library-call``.

The native daemon owns the socket, the origin and header-key checks and the
body read. For a route whose handler needs only the Guard store, it calls
``route.dispatch`` with the method, path, query and body. The call runs the
daemon's dispatch on a handler with no socket and returns the one reply the
dispatch wrote: ``{"status": int, "body": {...}, "no_store": bool}``.

A handler that reaches for state only a running daemon holds (its locks, rate
limits, extension-control service or listening address) raises
``LiveDaemonStateError``; the call then answers ``{"relay": true}`` so the
request is relayed instead of answered. The reads in ``_PUBLISHED_READS`` run
on the server state the daemon's request replay builds from the published
daemon state instead: its listening address, its runtime identity and the
connect state it keeps on disk.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from email.message import Message
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..store import GuardStore

_NO_STORE = {"Cache-Control": "no-store"}
# The update status read forbids revalidation too; the native daemon writes
# that header for its path.
_NO_STORE_MAX_AGE_ZERO = {"Cache-Control": "no-store, max-age=0"}
_PUBLISHED_READS = frozenset(
    {
        "/v1/cloud/connect",
        "/v1/local-clis",
        "/v1/runtime",
        "/v1/supply-chain/entitlement",
        "/v1/supply-chain/package-shims",
    }
)
_STATE_LIMIT_BYTES = 64 * 1024
_IGNORED_HEADERS = frozenset({"X-Content-Type-Options"})


class LiveDaemonStateError(Exception):
    """The handler needs state that only a running daemon holds."""


class OfflineReplyError(Exception):
    """The dispatch wrote no reply, two replies, or a reply the daemon cannot send."""


class _RawReplyError(Exception):
    """The dispatch matched no route and began a bare reply."""


class _OfflineServer:
    def __init__(self, store: GuardStore) -> None:
        from ..runtime.surface_server import GuardSurfaceRuntime

        self.store = store
        self.home_dir = Path.home()
        self.runtime = GuardSurfaceRuntime(store)

    def __getattr__(self, name: str) -> Any:
        raise LiveDaemonStateError(name)


def _published_server(store: GuardStore) -> Any:
    """The replay server for the daemon the Guard home's published state names."""

    from ..daemon.manager import _state_path
    from .request_host import _replay_server_class

    try:
        with _state_path(store.guard_home).open("rb") as handle:
            state = json.loads(handle.read(_STATE_LIMIT_BYTES).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveDaemonStateError("daemon_state") from error
    host = state.get("host") if isinstance(state, dict) else None
    port = state.get("port") if isinstance(state, dict) else None
    pid = state.get("pid") if isinstance(state, dict) else None
    if (
        not isinstance(host, str)
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 0 < port < 65536
        or not isinstance(pid, int)
        or isinstance(pid, bool)
    ):
        raise LiveDaemonStateError("daemon_state")
    # The native daemon checked the caller, so the handler needs no auth token.
    return _replay_server_class()(store, port, host, Path.home(), "", pid)


def _handler_class() -> type:
    from .request_handler import _GuardDaemonHandler

    class _OfflineHandler(_GuardDaemonHandler):  # type: ignore[misc, valid-type]
        def __init__(self, server: Any, method: str, path: str) -> None:  # pyright: ignore[reportMissingSuperCall]
            self.server = server  # pyright: ignore[reportAttributeAccessIssue]
            self.headers = Message()
            self.command = method
            self.path = path
            self.client_address = ("127.0.0.1", 0)
            self._native_gate_unavailable = False
            self.reply: dict[str, object] | None = None

        def _header_token_is_valid(self, *, payload: dict[str, object] | None = None) -> bool:
            # The native daemon checked the header key before it called.
            del payload
            return True

        def _cors_headers_for_request(self, *args: object, **kwargs: object) -> dict[str, str] | None:
            # The native daemon writes the CORS headers for its own caller.
            del args, kwargs
            return None

        def _daemon_server(self) -> Any:
            if isinstance(self.server, _OfflineServer):
                raise LiveDaemonStateError("daemon_server")
            return self.server

        def _write_json_bytes(
            self,
            body: bytes,
            *,
            status: int,
            extra_headers: Mapping[str, str] | None = None,
        ) -> None:
            if self.reply is not None:
                raise OfflineReplyError("second_reply")
            headers = {key: value for key, value in (extra_headers or {}).items() if key not in _IGNORED_HEADERS}
            if headers == _NO_STORE_MAX_AGE_ZERO and self.command == "GET":
                headers = _NO_STORE
            if headers not in ({}, _NO_STORE):
                if self.command == "GET":
                    # A read the daemon answers with its own headers is relayed.
                    raise LiveDaemonStateError("reply_headers")
                raise OfflineReplyError("unsupported_headers")
            decoded = json.loads(body)
            if not isinstance(decoded, dict):
                raise OfflineReplyError("non_object_body")
            self.reply = {"status": status, "body": decoded, "no_store": headers == _NO_STORE}

        def send_response(self, *args: object, **kwargs: object) -> None:
            # Only an unmatched route writes a bare status line.
            raise _RawReplyError

    return _OfflineHandler


def dispatch(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Runs the daemon's dispatch for one request and returns its reply."""

    from ..library_calls import LibraryCallError
    from ..native_daemon_route import native_route_facts

    method = args.get("method")
    path = args.get("path")
    query = args.get("query", "")
    payload = args.get("payload", {})
    if (
        method not in {"GET", "POST"}
        or not isinstance(path, str)
        or not isinstance(query, str)
        or not isinstance(payload, dict)
    ):
        raise LibraryCallError("invalid_arguments")
    target = f"{path}?{query}" if query else path
    parsed = urlparse(target)
    parts = [part for part in parsed.path.split("/") if part]
    published = method == "GET" and (
        parsed.path in _PUBLISHED_READS
        or (len(parts) == 4 and parts[0:2] == ["v1", "sessions"] and parts[3] == "resume")
    )
    try:
        server = _published_server(store) if published else _OfflineServer(store)
    except LiveDaemonStateError:
        return {"relay": True}
    handler = _handler_class()(server, method, target)
    try:
        if method == "POST":
            route = native_route_facts("POST", parsed.path, guard_home=store.guard_home)
            handler._dispatch_control_post(parsed, parts, payload, route)
        elif not (
            handler._serve_dashboard_runtime_read(parsed, parts, store)
            or handler._serve_dashboard_records_read(parsed, parts, store)
        ):
            return {"relay": True}
    except (LiveDaemonStateError, _RawReplyError):
        if handler.reply is not None:
            raise
        return {"relay": True}
    finally:
        if published:
            server.server_close()
    if handler.reply is None:
        raise OfflineReplyError("no_reply")
    return handler.reply


DISPATCH_CALLS = {"route.dispatch": dispatch}
