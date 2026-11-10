"""Guard library steps the native daemon's Guard Cloud connect routes run.

The native daemon owns ``/v1/cloud/connect`` and
``/v1/supply-chain/package-shims/connect``: whether connect applies, the flow
states it shows, the request id, the one-flow-at-a-time rule's replies and
every reply body. Each call here is one library step it cannot take natively
yet: reading the store's connect facts, holding the flow state other routes
read, opening the browser session and finishing it in the background.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Mapping
from typing import Any

from ..browser_opener import open_browser_url
from ..cli.connect_flow import start_guard_browser_session
from ..cli.connect_sync_result import failed_browser_connect_flow_state
from ..daemon.server_control_cloud_sync import _managed_controls_publish_for
from ..daemon.server_control_connect_flow import _complete_browser_oauth_connect
from ..daemon.server_control_connect_state import (
    _begin_guard_cloud_connect_state,
    _begin_package_firewall_connect_state,
    _copy_guard_cloud_connect_state,
    _copy_package_firewall_connect_state,
    _guard_cloud_connect_repair_mode,
    _guard_cloud_connect_required_for_insights,
    _guard_cloud_connect_succeeded,
    _package_firewall_connect_needs_repair,
    _package_firewall_connect_url,
    _set_guard_cloud_connect_state,
    _set_package_firewall_connect_state,
)
from ..package_firewall_entitlement import (
    PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON,
    package_firewall_entitlement_or_denied,
)
from ..runtime.runner import prepare_guard_cloud_connect_authorization
from ..store import GuardStore
from .control_host import control_server

# Browser sessions opened by ``connect.open`` wait here for ``connect.run``.
_SESSIONS: dict[str, Any] = {}
_SESSIONS_LOCK = threading.Lock()


def _kind(args: Mapping[str, Any]) -> str:
    return "package_firewall" if args.get("kind") == "package_firewall" else "cloud"


def _state(args: Mapping[str, Any], name: str) -> dict[str, object] | None:
    value = args.get(name)
    return dict(value) if isinstance(value, dict) else None


def facts(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """What the connect flows are built from: need, repair copy, URL and states."""

    reason = str(args.get("reason") or "")
    if _kind(args) == "package_firewall":
        required = True
        repair = _package_firewall_connect_needs_repair(store, reason)
    else:
        required = _guard_cloud_connect_required_for_insights(store)
        repair = _guard_cloud_connect_repair_mode(store) if required else False
    with control_server(store, args) as server:
        cloud_state = _copy_guard_cloud_connect_state(server)
        package_state = _copy_package_firewall_connect_state(server)
    return {
        "required": required,
        "repair": repair,
        "connect_url": _package_firewall_connect_url(store),
        "cloud_state": cloud_state,
        "package_state": package_state,
    }


def begin(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Records the starting state unless a connect flow is already in flight."""

    starting = _state(args, "state") or {}
    begin_state = (
        _begin_package_firewall_connect_state if _kind(args) == "package_firewall" else _begin_guard_cloud_connect_state
    )
    with control_server(store, args) as server:
        started, current = begin_state(server, starting)
    return {"started": started, "current": current}


def set_state(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Replaces the flow state the status routes read."""

    set_flow = (
        _set_package_firewall_connect_state if _kind(args) == "package_firewall" else _set_guard_cloud_connect_state
    )
    with control_server(store, args) as server:
        set_flow(server, _state(args, "state"))
    return {}


def open_session(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Prepares authorization, starts the browser session and opens it."""

    connect_url = str(args.get("connect_url") or "")
    try:
        prepare_guard_cloud_connect_authorization(store)
        device = store.get_device_metadata()
        session = start_guard_browser_session(
            connect_url=connect_url,
            machine_id=str(device["installation_id"]),
            machine_label=str(device["device_label"]),
        )
        browser_opened = open_browser_url(session.authorize_url)
    except Exception as error:
        return {"error": str(error)}
    session_id = uuid.uuid4().hex
    with _SESSIONS_LOCK:
        _SESSIONS[session_id] = session
    return {"session_id": session_id, "authorize_url": session.authorize_url, "browser_opened": bool(browser_opened)}


def _finish(store: GuardStore, args: Mapping[str, Any], session: Any, running: dict[str, object]) -> None:
    kind = _kind(args)
    set_flow = _set_package_firewall_connect_state if kind == "package_firewall" else _set_guard_cloud_connect_state
    with control_server(store, args) as server:
        try:
            payload = _complete_browser_oauth_connect(
                store=store,
                session=session,
                connect_url=str(args.get("connect_url") or ""),
                browser_opened=args.get("browser_opened") is True,
                managed_controls_publish=_managed_controls_publish_for(server),
            )
            if kind == "package_firewall":
                # The credentials are already stored. A runtime that cannot
                # report the entitlement has not failed the sign-in.
                entitlement = package_firewall_entitlement_or_denied(store)
                reason = str(entitlement.get("reason") or "")
                done = (
                    reason == PACKAGE_FIREWALL_RUNTIME_UNAVAILABLE_REASON
                    or bool(entitlement.get("allowed"))
                    or reason == "paid_guard_cloud_required"
                )
            else:
                done = _guard_cloud_connect_succeeded(store)
            if done:
                set_flow(server, None)
                return
            detail = str(
                payload.get("repair_message") or payload.get("sync_error") or "Guard Cloud connect did not finish."
            )
            set_flow(server, failed_browser_connect_flow_state(running, detail=detail))
        except Exception as error:
            set_flow(server, failed_browser_connect_flow_state(running, detail=str(error)))
        finally:
            session.close()


def run(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Records the running state and finishes the sign-in in the background."""

    with _SESSIONS_LOCK:
        session = _SESSIONS.pop(str(args.get("session_id") or ""), None)
    if session is None:
        return {"running": False}
    running = _state(args, "state") or {}
    set_state(store, {**args, "state": running})
    threading.Thread(
        target=_finish,
        args=(store, dict(args), session, running),
        daemon=True,
        name=f"guard-{_kind(args).replace('_', '-')}-connect",
    ).start()
    return {"running": True}


CONNECT_CALLS = {
    "connect.facts": facts,
    "connect.begin": begin,
    "connect.set_state": set_state,
    "connect.open": open_session,
    "connect.run": run,
}
