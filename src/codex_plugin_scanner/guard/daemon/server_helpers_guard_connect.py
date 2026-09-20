"""Guard cloud connection and OAuth completion."""

from __future__ import annotations

from . import server as _server


def _copy_guard_cloud_connect_state(server: _server._GuardDaemonHttpServer) -> dict[str, object] | None:
    with server.guard_cloud_connect_state_lock:
        current = server.guard_cloud_connect_state
        return dict(current) if isinstance(current, dict) else None


def _set_guard_cloud_connect_state(server: _server._GuardDaemonHttpServer, state: dict[str, object] | None) -> None:
    with server.guard_cloud_connect_state_lock:
        server.guard_cloud_connect_state = dict(state) if isinstance(state, dict) else None


def _begin_guard_cloud_connect_state(
    server: _server._GuardDaemonHttpServer,
    starting_state: dict[str, object],
) -> tuple[bool, dict[str, object]]:
    with server.guard_cloud_browser_session_lock:
        current = _server._copy_guard_cloud_connect_state(server)
        if _server._guard_cloud_connect_state_is_in_flight(current):
            return False, dict(current)
        current = _server._copy_package_firewall_connect_state(server)
        if _server._guard_cloud_connect_state_is_in_flight(current):
            return False, dict(current)
        _server._set_guard_cloud_connect_state(server, starting_state)
        return True, dict(starting_state)


def _guard_cloud_connect_repair_mode_from_health(oauth_health: dict[str, object]) -> bool:
    return bool(oauth_health.get("configured")) and str(oauth_health.get("state") or "") == "degraded"


def _guard_cloud_connect_repair_mode(store: _server.GuardStore) -> bool:
    return _server._guard_cloud_connect_repair_mode_from_health(store.get_oauth_local_credential_health())


def _guard_cloud_connect_required_for_insights(store: _server.GuardStore) -> bool:
    oauth_health = store.get_oauth_local_credential_health()
    if _server._guard_cloud_connect_repair_mode_from_health(oauth_health):
        return True
    if bool(oauth_health.get("configured")) and str(oauth_health.get("state") or "") == "healthy":
        return store.get_cloud_sync_profile() is None
    return True


def _default_guard_cloud_connect_flow(*, store: _server.GuardStore, repair_mode: bool) -> dict[str, object]:
    connect_url = _server._package_firewall_connect_url(store)
    action_label = "Repair Guard Cloud access" if repair_mode else "Connect Guard Cloud"
    if repair_mode:
        title = "Repair Guard Cloud access to publish insights"
        detail = (
            "Guard Cloud sign-in on this machine needs repair before it can publish a public share link. "
            "Start local connect here and finish approval in your browser."
        )
    else:
        title = "Connect Guard Cloud to publish insights"
        detail = (
            "Local Guard remains available. Connect Guard Cloud here so the daemon can publish "
            "a public share link with preview image support."
        )
    return {
        "state": "idle",
        "title": title,
        "detail": detail,
        "action_label": action_label,
        "connect_url": connect_url,
        "authorize_url": None,
        "browser_opened": None,
        "request_id": None,
        "poll_after_ms": None,
        "purpose": "insights_share",
    }


def _resolve_guard_cloud_connect_flow(
    *, server: _server._GuardDaemonHttpServer, store: _server.GuardStore
) -> dict[str, object] | None:
    if not _server._guard_cloud_connect_required_for_insights(store):
        return None
    repair_mode = _server._guard_cloud_connect_repair_mode(store)
    cloud_current = _server._copy_guard_cloud_connect_state(server)
    package_current = _server._copy_package_firewall_connect_state(server)
    current = package_current if _server._guard_cloud_connect_state_is_in_flight(package_current) else cloud_current
    if current is None:
        return _server._default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode)
    state = str(current.get("state") or "idle")
    flow = {
        **_server._default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
        **current,
    }
    if state in {"starting", "running"}:
        flow["title"] = "Finish Guard Cloud sign-in in your browser"
        browser_opened = flow.get("browser_opened") is True
        flow["detail"] = (
            "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this modal will "
            "unlock public sharing automatically."
            if browser_opened
            else (
                "HOL Guard is opening the secure sign-in flow in your browser."
                if state == "starting"
                else (
                    "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                    "not open automatically."
                )
            )
        )
        flow["poll_after_ms"] = _server._SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS
        return flow
    if state == "failed":
        flow["title"] = "Guard Cloud sign-in needs attention"
        flow["poll_after_ms"] = None
        return flow
    return flow


def _guard_cloud_connect_succeeded(store: _server.GuardStore) -> bool:
    return not _server._guard_cloud_connect_required_for_insights(store)


def _sync_supply_chain_cloud_state_with_optional_auth_context(
    store: _server.GuardStore,
    auth_context: dict[str, object] | None,
    *,
    workspace_dir: _server.Path | None = None,
) -> dict[str, object]:
    try:
        parameters = _server.inspect.signature(_server.sync_supply_chain_cloud_state).parameters
    except (TypeError, ValueError):
        parameters = {}
    kwargs: dict[str, _server.Any] = {}
    if auth_context is not None and "auth_context" in parameters:
        kwargs["auth_context"] = auth_context
    if workspace_dir is not None and "workspace_dir" in parameters:
        kwargs["workspace_dir"] = workspace_dir
    return _server.sync_supply_chain_cloud_state(store, **kwargs)


def _sync_local_guard_cloud_proof_with_optional_auth_context(
    store: _server.GuardStore,
    auth_context: dict[str, object] | None,
    managed_controls_publish: (
        _server.Callable[[_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object] | None
    ) = None,
) -> dict[str, object]:
    try:
        parameters = _server.inspect.signature(_server.sync_local_guard_cloud_proof).parameters
    except (TypeError, ValueError):
        parameters = {}
    if (
        auth_context is not None
        and "auth_context" in parameters
        and managed_controls_publish is not None
        and "managed_controls_publish" in parameters
    ):
        return _server.sync_local_guard_cloud_proof(
            store,
            auth_context=auth_context,
            managed_controls_publish=managed_controls_publish,
        )
    if auth_context is not None and "auth_context" in parameters:
        return _server.sync_local_guard_cloud_proof(store, auth_context=auth_context)
    if managed_controls_publish is not None and "managed_controls_publish" in parameters:
        return _server.sync_local_guard_cloud_proof(
            store,
            managed_controls_publish=managed_controls_publish,
        )
    return _server.sync_local_guard_cloud_proof(store)


def _finalize_daemon_guard_connect_payload(
    *,
    store: _server.GuardStore,
    connect_url: str,
    payload: dict[str, object],
    now: str,
    managed_controls_publish: (
        _server.Callable[[_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object] | None
    ) = None,
) -> dict[str, object]:
    sync_auth_context = payload.pop(_server.CONNECT_SYNC_AUTH_CONTEXT_KEY, None)
    resolved_sync_auth_context = sync_auth_context if isinstance(sync_auth_context, dict) else None
    normalized_connect_url, allowed_origin = _server.resolve_connect_url(connect_url)
    sync_url = f"{allowed_origin}/api/guard/receipts/sync"
    dashboard_url = f"{allowed_origin}/guard"
    payload.setdefault("connect_url", normalized_connect_url)
    payload.setdefault("sync_url", sync_url)
    payload.setdefault("dashboard_url", dashboard_url)
    payload.setdefault("inbox_url", f"{dashboard_url}/inbox")
    payload.setdefault("fleet_url", f"{dashboard_url}/protect")
    if str(payload.get("status") or "") != "connected":
        return payload
    store.clear_cloud_sync_state_for_reconnect(
        now=now,
        managed_controls_publish=managed_controls_publish,
    )
    latest_state = store.record_guard_connect_pairing_completed(
        sync_url=sync_url,
        allowed_origin=allowed_origin,
        now=now,
    )
    payload.update(
        {
            "status": str(latest_state.get("status") or payload.get("status") or "connected"),
            "milestone": str(latest_state.get("milestone") or "first_sync_pending"),
            "completed_at": latest_state.get("completed_at") or now,
            "latest_connect_state": latest_state,
        }
    )
    oauth_health = store.get_oauth_local_credential_health()
    if store.get_cloud_sync_profile() is None and (
        oauth_health.get("state") == "degraded" or not oauth_health.get("configured")
    ):
        repair_message = (
            "Guard Cloud authorization did not persist locally. "
            "Start Guard Cloud connect again to repair local sign-in."
        )
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now=now,
            reason=repair_message,
        )
        payload.update(
            {
                "status": "retry_required",
                "milestone": "first_sync_failed",
                "sync_succeeded": False,
                "sync_error": repair_message,
                "repair_message": repair_message,
                "latest_connect_state": store.get_effective_guard_connect_state(now=now),
            }
        )
        return payload
    if store.get_cloud_sync_profile() is None:
        payload["sync_attempted"] = False
        return payload
    payload["sync_attempted"] = True
    try:
        sync_payload = _server._sync_local_guard_cloud_proof_with_optional_auth_context(
            store,
            resolved_sync_auth_context,
            managed_controls_publish,
        )
    except _server.GuardSyncNotAvailableError as error:
        payload = _server.apply_guard_connect_sync_result(
            store,
            payload,
            now=now,
            error=error,
            recorded_status="connected",
            recorded_milestone="sync_not_available",
            repair_message=str(error),
        )
        reconciled_state = _server.reconcile_connect_state_with_oauth_entitlement(store, now=now)
        if reconciled_state is not None:
            payload["milestone"] = str(reconciled_state.get("milestone") or "first_sync_pending")
            payload["latest_connect_state"] = reconciled_state
        return payload
    except (_server.GuardSyncAuthorizationExpiredError, _server.GuardSyncNotConfiguredError) as error:
        return _server.apply_guard_connect_sync_result(
            store,
            payload,
            now=now,
            error=error,
            recorded_status="retry_required",
            recorded_milestone="first_sync_failed",
            repair_message="Run Guard Cloud connect again to refresh local authorization.",
            payload_status="retry_required",
        )
    except (RuntimeError, TimeoutError) as error:
        return _server.apply_guard_connect_sync_result(
            store,
            payload,
            now=now,
            error=error,
            recorded_status="connected",
            recorded_milestone="first_sync_pending",
            repair_message=(
                "Guard Cloud pairing finished, but the first proof sync is still pending. Local Guard will retry while "
                "the daemon is running."
            ),
            payload_status="connected",
        )
    latest_state = store.record_latest_guard_connect_sync_success(
        sync_payload=sync_payload,
        now=str(sync_payload.get("synced_at") or now),
        request_id=str(latest_state.get("request_id") or ""),
    )
    payload.update(
        {
            "status": "connected",
            "milestone": "first_sync_succeeded",
            "sync_succeeded": True,
            "sync": sync_payload,
            "last_sync_at": sync_payload.get("synced_at"),
            "latest_connect_state": latest_state or store.get_latest_guard_connect_state(now=now),
        }
    )
    try:
        payload["supply_chain"] = _server._sync_supply_chain_cloud_state_with_optional_auth_context(
            store,
            resolved_sync_auth_context,
        )
    except (_server.GuardSyncNotConfiguredError, _server.GuardSyncNotAvailableError, RuntimeError) as error:
        payload["supply_chain_error"] = str(error)
    return payload


def _complete_browser_oauth_connect(
    *,
    store: _server.GuardStore,
    session: _server.Any,
    connect_url: str,
    browser_opened: bool,
    managed_controls_publish: (
        _server.Callable[[_server.ExtensionControlAuthorityView, _server.Callable[[], None]], object] | None
    ),
) -> dict[str, object]:
    _, allowed_origin = _server.resolve_connect_url(connect_url)
    oauth_client = _server.resolve_guard_oauth_client_config(allowed_origin)
    callback = session.wait_for_callback(_server._SUPPLY_CHAIN_CONNECT_WAIT_TIMEOUT_SECONDS)
    if callback is None or callback.code is None:
        raise RuntimeError("Guard OAuth callback missing authorization code.")
    token_result = _server.exchange_guard_authorization_code(
        token_endpoint=oauth_client.token_endpoint,
        client_id=oauth_client.client_id,
        code=callback.code,
        redirect_uri=session.redirect_uri,
        code_verifier=session.pkce_verifier,
        dpop_key_material=session.dpop_key_material,
    )
    if token_result.refresh_token is None:
        raise RuntimeError("Guard OAuth token exchange failed: missing refresh token.")
    timestamp = _server._now()
    _server._persist_oauth_local_credentials(
        store=store,
        issuer=oauth_client.issuer,
        client_id=oauth_client.client_id,
        refresh_token=token_result.refresh_token,
        dpop_key_material=session.dpop_key_material,
        grant_id=token_result.grant_id,
        **token_result.target_binding(),
        supply_chain_entitlement=token_result.supply_chain_entitlement,
        workspace_id=token_result.workspace_id,
        runtime_id="hol-guard",
        runtime_label="HOL Guard CLI",
        access_token=token_result.access_token,
        access_token_expires_at=token_result.access_token_expires_at,
        now=timestamp,
    )
    sync_url = f"{allowed_origin}/api/guard/receipts/sync"
    return _server._finalize_daemon_guard_connect_payload(
        store=store,
        connect_url=connect_url,
        payload={
            "status": "connected",
            "connect_mode": "browser_oauth",
            "browser_opened": browser_opened,
            "authorize_url": session.authorize_url,
            "redirect_uri": session.redirect_uri,
            "grant_id": token_result.grant_id,
            "machine_id": token_result.machine_id,
            "workspace_id": token_result.workspace_id,
            "connect_url": connect_url,
            "sync_url": sync_url,
            "_guard_sync_auth_context": _server._build_sync_auth_context(
                access_token=token_result.access_token,
                dpop_key_material=session.dpop_key_material,
                sync_url=sync_url,
            ),
        },
        now=timestamp,
        managed_controls_publish=managed_controls_publish,
    )
