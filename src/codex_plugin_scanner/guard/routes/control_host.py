"""Daemon control writes whose handlers share the daemon's server state.

Supply-chain package protection, Guard Cloud connect,
dashboard updates and first-run initialization run through the daemon's
control handlers, which read and write the cross-request state the server
keeps (the package-protection mutation lock, the action rate limiter, the
Cloud connect flow). The native daemon owns the socket, the caller check and
the body read; this call hands those handlers a host that keeps the one reply
they write, with that state loaded from the Guard home.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..store import GuardStore
from .calls import RouteReplyError

_NO_STORE_VALUES = frozenset({"no-store", "no-store, max-age=0"})


def _host_class() -> type:
    from ..daemon.server_control_cloud_connect import _CloudConnectRoutes
    from ..daemon.server_control_headless import _HeadlessRoutes
    from ..daemon.server_control_health import _ControlHealthRoutes
    from ..daemon.server_control_misc import _ControlMiscRoutes
    from ..daemon.server_control_policy import _ControlPolicyRoutes
    from ..daemon.server_control_routes_post import _ControlPostRoutes
    from ..daemon.server_control_supply_chain import _SupplyChainRoutes
    from ..daemon.server_dashboard_support import _DashboardSupportRoutes

    class ControlHost(
        _DashboardSupportRoutes,
        _ControlPostRoutes,
        _SupplyChainRoutes,
        _CloudConnectRoutes,
        _HeadlessRoutes,
        _ControlMiscRoutes,
        _ControlPolicyRoutes,
        _ControlHealthRoutes,
    ):
        """Stands in for the daemon's request handler and keeps the reply."""

        def __init__(self, server: Any, path: str, facts: Mapping[str, Any]) -> None:
            self.server = server
            self.path = path
            self.command = "POST"
            self.headers: dict[str, str] = {}
            self._facts = facts
            self._reply: dict[str, object] | None = None

        def _record(self, status: int, body: object, headers: Mapping[str, str] | None) -> None:
            if self._reply is not None:
                raise RouteReplyError("second_reply")
            cache = dict(headers or {}).get("Cache-Control")
            if not isinstance(body, dict):
                # A bodiless answer: the daemon writes the JSON error it names.
                body = {"error": "not_found"} if status == 404 else {}
            self._reply = {"status": status, "body": body, "no_store": cache in _NO_STORE_VALUES}

        def _write_json(
            self,
            payload: dict[str, Any],
            *,
            status: int = 200,
            extra_headers: Mapping[str, str] | None = None,
        ) -> None:
            self._record(status, dict(payload), extra_headers)

        def _write_empty(self, *, status: int, extra_headers: Mapping[str, str] | None = None) -> None:
            self._record(status, None, extra_headers)

        def send_response(self, code: int, message: str | None = None) -> None:
            del message
            self._record(code, None, None)

        def send_header(self, keyword: str, value: str) -> None:
            del keyword, value

        def end_headers(self) -> None:
            return None

        def _write_unauthorized(self, *, extra_headers: Mapping[str, str] | None = None) -> None:
            del extra_headers
            self._write_json({"error": "unauthorized"}, status=401)

        def _write_approval_gate_error(self, error: Any, *, resolved: bool | None = None) -> None:
            payload = error.to_payload()
            if resolved is not None:
                payload["resolved"] = resolved
            self._write_json(payload, status=error.status)

        def _cors_headers_for_request(self, **_: object) -> dict[str, str] | None:
            return None

        def _daemon_server(self) -> Any:
            return self.server

        def _route_home(self) -> Path | None:
            return getattr(getattr(self.server, "store", None), "guard_home", None)

        def _header_token_is_valid(self, *, payload: dict[str, object] | None = None) -> bool:
            # The native daemon checked the caller before it ran this call.
            del payload
            return True

        def _is_hosted_dashboard_origin(self) -> bool:
            return self._facts.get("hosted_origin") is True

        def _request_uses_protection_repair_session(self) -> bool:
            return self._facts.get("protection_repair_session") is True

        def _request_holds_link_bound_session(self) -> bool:
            return self._facts.get("link_bound_session") is True

        def _refresh_dashboard_session_token(self, *, surface: str) -> str | None:
            del surface
            return None

        def _strict_loopback_origin(self, value: object) -> str | None:
            from ..native_daemon_route import NativeDaemonRouteError, native_strict_loopback_origin

            if not isinstance(value, str):
                return None
            stripped = value.strip()
            parsed = urlparse(stripped)
            normalized = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None
            try:
                return native_strict_loopback_origin(stripped, normalized, guard_home=self._route_home())
            except NativeDaemonRouteError:
                return None

        def _native_handler_decision(self, ask: Callable[[], Any]) -> Any:
            from ..native_daemon_handler import NativeDaemonHandlerError

            try:
                decision = ask()
            except NativeDaemonHandlerError:
                self._write_json({"error": "native_handler_policy_unavailable"}, status=503)
                return None
            if decision.rejected:
                self._write_json(decision.body, status=decision.status)
                return None
            return decision

        @staticmethod
        def _optional_string(value: object) -> str | None:
            if isinstance(value, str) and value.strip():
                return value.strip()
            return None

        def reply(self) -> dict[str, object]:
            if self._reply is None:
                raise RouteReplyError("no_reply")
            return self._reply

    return ControlHost


_HOST_CLASSES: dict[str, type] = {}


def control_post(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Runs the control handler the daemon dispatches ``POST path`` to."""

    from ..daemon.auth_token import load_guard_daemon_auth_token
    from ..library_calls import LibraryCallError
    from ..native_daemon_route import native_route_facts
    from .request_host import _replay_server_class

    path = args.get("path")
    payload = args.get("payload")
    port = args.get("port")
    home_dir = args.get("home_dir")
    if (
        not isinstance(path, str)
        or not isinstance(payload, dict)
        or not isinstance(port, int)
        or not (home_dir is None or isinstance(home_dir, str))
    ):
        raise LibraryCallError("invalid_arguments")
    host_class = _HOST_CLASSES.get("control")
    if host_class is None:
        host_class = _HOST_CLASSES.setdefault("control", _host_class())
    server = _replay_server_class()(
        store,
        port,
        "127.0.0.1",
        Path(home_dir) if home_dir else Path.home(),
        load_guard_daemon_auth_token(store.guard_home) or "",
        args.get("daemon_pid") if isinstance(args.get("daemon_pid"), int) else None,
        False,
    )
    try:
        host = host_class(server, path, args)
        route = native_route_facts("POST", path, guard_home=store.guard_home)
        parts = [part for part in path.split("/") if part]
        host._dispatch_control_post(urlparse(path), parts, payload, route)
        return host.reply()
    finally:
        server.server_close()


CONTROL_GET_PATHS = frozenset(
    {
        "/v1/cloud/connect",
        "/v1/local-clis",
        "/v1/runtime",
        "/v1/supply-chain/entitlement",
        "/v1/supply-chain/package-shims",
        "/v1/update/status",
    }
)


def _runtime_read(host: Any, query: str) -> None:
    from ..approvals import build_runtime_snapshot
    from ..config import load_guard_config
    from ..daemon.command_activity_health_repair import auto_repair_command_activity_health_if_degraded
    from ..daemon.server_common import _now
    from ..daemon.server_control_cloud_sync import _managed_controls_publish_for, _maybe_queue_first_cloud_sync
    from ..models import format_local_http_origin

    server = host.server
    store = server.store
    _maybe_queue_first_cloud_sync(store=store, managed_controls_publish=_managed_controls_publish_for(server))
    auto_repair_command_activity_health_if_degraded(store)
    config = load_guard_config(store.guard_home)
    include_receipts = host._query_bool(query, "include_receipts", default=True)
    snapshot = build_runtime_snapshot(
        store=store,
        approval_center_url=format_local_http_origin(server.daemon_host(), server.daemon_port()),
        active_request_id=host._query_string(query, "active_request_id"),
        include_items=host._query_bool(query, "include_items", default=True),
        receipt_limit=25 if include_receipts else 0,
        containment_health=host._containment_health_payload(),
        serving_runtime={
            "session_id": server.runtime_session_id,
            "daemon_host": server.runtime_host,
            "daemon_port": server.daemon_port(),
            "started_at": server.runtime_started_at,
            "last_heartbeat_at": _now(),
        },
    )
    host._write_json(
        {**snapshot, "security_level": config.security_level, "operator_health": host._operator_health_payload()}
    )


def _dispatch_control_get(host: Any, path: str, query: str) -> None:
    from ..cli.update_commands import build_guard_update_status_payload
    from ..daemon.dashboard_update import merge_dashboard_update_progress
    from ..daemon.local_cli_http import handle_local_cli_list

    if path == "/v1/runtime":
        _runtime_read(host, query)
    elif path == "/v1/local-clis":
        handle_local_cli_list(host, query)
    elif path == "/v1/supply-chain/package-shims":
        host._handle_supply_chain_package_firewall_status()
    elif path == "/v1/cloud/connect":
        host._handle_guard_cloud_connect_status()
    elif path == "/v1/supply-chain/entitlement":
        host._write_json(host._supply_chain_entitlement())
    else:
        guard_home = host.server.store.guard_home
        host._write_json(
            merge_dashboard_update_progress(guard_home, build_guard_update_status_payload(guard_home=guard_home)),
            extra_headers={"Cache-Control": "no-store, max-age=0"},
        )


def control_get(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Answers a dashboard ``GET`` whose handler reads the daemon's server state."""

    from ..daemon.auth_token import load_guard_daemon_auth_token
    from ..library_calls import LibraryCallError
    from .request_host import _replay_server_class

    path = args.get("path")
    query = args.get("query", "")
    port = args.get("port")
    home_dir = args.get("home_dir")
    if (
        not isinstance(path, str)
        or path not in CONTROL_GET_PATHS
        or not isinstance(query, str)
        or not isinstance(port, int)
        or not (home_dir is None or isinstance(home_dir, str))
    ):
        raise LibraryCallError("invalid_arguments")
    host_class = _HOST_CLASSES.get("control")
    if host_class is None:
        host_class = _HOST_CLASSES.setdefault("control", _host_class())
    server = _replay_server_class()(
        store,
        port,
        "127.0.0.1",
        Path(home_dir) if home_dir else Path.home(),
        load_guard_daemon_auth_token(store.guard_home) or "",
        args.get("daemon_pid") if isinstance(args.get("daemon_pid"), int) else None,
        False,
    )
    try:
        host = host_class(server, path, args)
        host.command = "GET"
        _dispatch_control_get(host, path, query)
        return host.reply()
    finally:
        server.server_close()


CONTROL_HOST_CALLS = {"route.control_post": control_post, "route.control_get": control_get}
