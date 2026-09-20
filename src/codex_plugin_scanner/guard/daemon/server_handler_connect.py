"""Package firewall and Guard cloud connection routes."""

from __future__ import annotations

from . import server as _server


def _handle_supply_chain_package_firewall_connect(self: _server._GuardDaemonHandler) -> None:
    entitlement = self._supply_chain_entitlement()
    reason = str(entitlement.get("reason") or "").strip().lower()
    if reason not in {"guard_cloud_connect_required", "guard_cloud_reconnect_required"}:
        self._write_json(
            {
                "error": "guard_cloud_connect_not_required",
                "entitlement": entitlement,
                "message": "Guard Cloud connect is not required for package firewall on this machine.",
            },
            status=409,
        )
        return
    store = self.server.store  # type: ignore[attr-defined]
    connect_url = _server._package_firewall_connect_url(store)
    action_label = _server._package_firewall_connect_action_label(
        reason,
        repair_copy=_server._package_firewall_connect_needs_repair(store, reason),
    )
    request_id = f"guard-connect-{_server.uuid.uuid4().hex}"
    starting_state = {
        **_server._default_package_firewall_connect_flow(store=store, reason=reason),
        "state": "starting",
        "title": "Opening Guard Cloud sign-in",
        "detail": "HOL Guard is opening the secure sign-in flow in your browser.",
        "action_label": action_label,
        "authorize_url": None,
        "browser_opened": None,
        "request_id": request_id,
        "poll_after_ms": _server._SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
    }
    started, current = _server._begin_package_firewall_connect_state(  # type: ignore[arg-type]
        self.server,
        starting_state,
    )
    if not started:
        self._write_json(current, status=202)
        return
    try:
        _server.prepare_guard_cloud_connect_authorization(store)
        device = store.get_device_metadata()
        session = _server.start_guard_browser_session(
            connect_url=connect_url,
            machine_id=str(device["installation_id"]),
            machine_label=str(device["device_label"]),
        )
        browser_opened = _server.open_browser_url(session.authorize_url)
    except Exception as error:
        failure = {
            **_server._default_package_firewall_connect_flow(store=store, reason=reason),
            "state": "failed",
            "detail": str(error),
            "browser_opened": False,
            "poll_after_ms": None,
        }
        _server._set_package_firewall_connect_state(self.server, failure)  # type: ignore[arg-type]
        self._write_json(failure, status=500)
        return

    running_state = {
        **_server._default_package_firewall_connect_flow(store=store, reason=reason),
        "state": "running",
        "title": "Finish Guard Cloud sign-in in your browser",
        "detail": (
            "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this page will "
            "unlock package-firewall controls automatically."
            if browser_opened
            else (
                "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                "not open automatically."
            )
        ),
        "action_label": action_label,
        "authorize_url": session.authorize_url,
        "browser_opened": browser_opened,
        "request_id": request_id,
        "poll_after_ms": _server._SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
    }
    _server._set_package_firewall_connect_state(self.server, running_state)  # type: ignore[arg-type]

    def _complete_connect() -> None:
        try:
            payload = _server._complete_browser_oauth_connect(
                store=store,
                session=session,
                connect_url=connect_url,
                browser_opened=browser_opened,
                managed_controls_publish=_server._managed_controls_publish_for(self.server),
            )
            resolved_entitlement = _server.resolve_package_firewall_entitlement(store)
            resolved_reason = str(resolved_entitlement.get("reason") or "")
            if bool(resolved_entitlement.get("allowed")) or resolved_reason == "paid_guard_cloud_required":
                _server._set_package_firewall_connect_state(self.server, None)  # type: ignore[arg-type]
                return
            repair_message = str(
                payload.get("repair_message") or payload.get("sync_error") or "Guard Cloud connect did not finish."
            )
            _server._set_package_firewall_connect_state(  # type: ignore[arg-type]
                self.server,
                _server.failed_browser_connect_flow_state(running_state, detail=repair_message),
            )
        except Exception as error:
            _server._set_package_firewall_connect_state(  # type: ignore[arg-type]
                self.server,
                _server.failed_browser_connect_flow_state(running_state, detail=str(error)),
            )
        finally:
            session.close()

    _server.threading.Thread(
        target=_complete_connect,
        daemon=True,
        name="guard-package-firewall-connect",
    ).start()
    self._write_json(running_state, status=202)


def _handle_guard_cloud_connect_status(self: _server._GuardDaemonHandler) -> None:
    store = self.server.store  # type: ignore[attr-defined]
    connect_flow = _server._resolve_guard_cloud_connect_flow(server=self.server, store=store)  # type: ignore[arg-type]
    self._write_json(
        {
            "connect_required": connect_flow is not None,
            "connect_flow": connect_flow,
            "dashboard_url": _server._package_firewall_connect_url(store).removesuffix("/connect"),
        }
    )


def _handle_guard_cloud_connect_start(self: _server._GuardDaemonHandler) -> None:
    store = self.server.store  # type: ignore[attr-defined]
    if not _server._guard_cloud_connect_required_for_insights(store):
        self._write_json(
            {
                "error": "guard_cloud_connect_not_required",
                "connect_required": False,
                "connect_flow": None,
                "dashboard_url": _server._package_firewall_connect_url(store).removesuffix("/connect"),
                "message": "Guard Cloud connect is not required to publish insights from this machine.",
            },
            status=409,
        )
        return
    repair_mode = _server._guard_cloud_connect_repair_mode(store)
    connect_url = _server._package_firewall_connect_url(store)
    action_label = "Repair Guard Cloud access" if repair_mode else "Connect Guard Cloud"
    request_id = f"guard-connect-{_server.uuid.uuid4().hex}"
    starting_state = {
        **_server._default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
        "state": "starting",
        "title": "Opening Guard Cloud sign-in",
        "detail": "HOL Guard is opening the secure sign-in flow in your browser.",
        "action_label": action_label,
        "authorize_url": None,
        "browser_opened": None,
        "request_id": request_id,
        "poll_after_ms": _server._SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
    }
    started, current = _server._begin_guard_cloud_connect_state(self.server, starting_state)  # type: ignore[arg-type]
    if not started:
        self._write_json({"connect_required": True, "connect_flow": current}, status=202)
        return
    try:
        _server.prepare_guard_cloud_connect_authorization(store)
        device = store.get_device_metadata()
        session = _server.start_guard_browser_session(
            connect_url=connect_url,
            machine_id=str(device["installation_id"]),
            machine_label=str(device["device_label"]),
        )
        browser_opened = _server.open_browser_url(session.authorize_url)
    except Exception as error:
        failure = {
            **_server._default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
            "state": "failed",
            "detail": str(error),
            "browser_opened": False,
            "poll_after_ms": None,
        }
        _server._set_guard_cloud_connect_state(self.server, failure)  # type: ignore[arg-type]
        self._write_json(
            {"connect_required": True, "connect_flow": failure, "message": str(error)},
            status=500,
        )
        return

    running_state = {
        **_server._default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
        "state": "running",
        "title": "Finish Guard Cloud sign-in in your browser",
        "detail": (
            "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this modal will "
            "unlock public sharing automatically."
            if browser_opened
            else (
                "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                "not open automatically."
            )
        ),
        "action_label": action_label,
        "authorize_url": session.authorize_url,
        "browser_opened": browser_opened,
        "request_id": request_id,
        "poll_after_ms": _server._SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
    }
    _server._set_guard_cloud_connect_state(self.server, running_state)  # type: ignore[arg-type]

    def _complete_connect() -> None:
        try:
            payload = _server._complete_browser_oauth_connect(
                store=store,
                session=session,
                connect_url=connect_url,
                browser_opened=browser_opened,
                managed_controls_publish=_server._managed_controls_publish_for(self.server),
            )
            if _server._guard_cloud_connect_succeeded(store):
                _server._set_guard_cloud_connect_state(self.server, None)  # type: ignore[arg-type]
                return
            repair_message = str(
                payload.get("repair_message") or payload.get("sync_error") or "Guard Cloud connect did not finish."
            )
            _server._set_guard_cloud_connect_state(  # type: ignore[arg-type]
                self.server,
                _server.failed_browser_connect_flow_state(running_state, detail=repair_message),
            )
        except Exception as error:
            _server._set_guard_cloud_connect_state(  # type: ignore[arg-type]
                self.server,
                _server.failed_browser_connect_flow_state(running_state, detail=str(error)),
            )
        finally:
            session.close()

    _server.threading.Thread(
        target=_complete_connect,
        daemon=True,
        name="guard-cloud-connect",
    ).start()
    self._write_json({"connect_required": True, "connect_flow": running_state}, status=202)
