"""Package firewall connection lifecycle."""

from __future__ import annotations

from . import server as _server


def _package_firewall_connect_url(store: _server.GuardStore) -> str:
    profile = store.get_cloud_sync_profile()
    sync_url = profile.get("sync_url") if isinstance(profile, dict) else None
    if isinstance(sync_url, str) and sync_url.strip():
        parsed = _server.urlparse(sync_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/guard/connect"
    return "https://hol.org/guard/connect"


def _package_firewall_connect_needs_repair(store: _server.GuardStore, reason: str) -> bool:
    if reason == "guard_cloud_reconnect_required":
        return True
    oauth_health = store.get_oauth_local_credential_health()
    return bool(oauth_health.get("configured"))


def _package_firewall_connect_action_label(reason: str, *, repair_copy: bool = False) -> str:
    if reason == "guard_cloud_reconnect_required" or repair_copy:
        return "Repair Guard Cloud access"
    return "Connect HOL Guard Cloud"


def _copy_package_firewall_connect_state(server: _server._GuardDaemonHttpServer) -> dict[str, object] | None:
    with server.package_firewall_connect_state_lock:
        current = server.package_firewall_connect_state
        return dict(current) if isinstance(current, dict) else None


def _set_package_firewall_connect_state(
    server: _server._GuardDaemonHttpServer, state: dict[str, object] | None
) -> None:
    with server.package_firewall_connect_state_lock:
        server.package_firewall_connect_state = dict(state) if isinstance(state, dict) else None


def _guard_cloud_connect_state_is_in_flight(state: dict[str, object] | None) -> _server.TypeGuard[dict[str, object]]:
    return isinstance(state, dict) and str(state.get("state") or "") in {"starting", "running"}


def _begin_package_firewall_connect_state(
    server: _server._GuardDaemonHttpServer,
    starting_state: dict[str, object],
) -> tuple[bool, dict[str, object]]:
    with server.guard_cloud_browser_session_lock:
        current = _server._copy_package_firewall_connect_state(server)
        if _server._guard_cloud_connect_state_is_in_flight(current):
            return False, dict(current)
        current = _server._copy_guard_cloud_connect_state(server)
        if _server._guard_cloud_connect_state_is_in_flight(current):
            return False, dict(current)
        _server._set_package_firewall_connect_state(server, starting_state)
        return True, dict(starting_state)


def _default_package_firewall_connect_flow(
    *,
    store: _server.GuardStore,
    reason: str,
) -> dict[str, object]:
    connect_url = _server._package_firewall_connect_url(store)
    repair_copy = _server._package_firewall_connect_needs_repair(store, reason)
    action_label = _server._package_firewall_connect_action_label(reason, repair_copy=repair_copy)
    if repair_copy:
        title = "Repair Guard Cloud access to restore package firewall"
        detail = (
            "Guard already has package-firewall coverage for this machine, but the local cloud authorization is not "
            "usable right now. Repair it here and Guard will unlock the firewall again."
        )
    else:
        title = "Connect HOL Guard Cloud to enable package firewall"
        detail = (
            "Guard continues running locally. Connect HOL Guard Cloud here so the daemon can verify "
            "package-firewall access before it changes package-manager routing."
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
    }


def _activate_package_firewall_runtime(context: _server.HarnessContext) -> tuple[int, dict[str, object]]:
    status = _server.package_shim_status(context)
    installed_managers = status.get("installed_managers")
    if not isinstance(installed_managers, list) or not installed_managers:
        return (
            409,
            {
                "error": "activation_requires_installed_shims",
                "message": "Protect a package manager before activating this Guard session.",
            },
        )
    activation = _server.activate_package_shims(
        context,
        managers=tuple(str(manager) for manager in installed_managers),
        repair=True,
    )
    repaired_status = activation.get("package_shims")
    if isinstance(repaired_status, dict):
        status = repaired_status
    proof = _server.probe_package_shim_intercepts(
        context,
        managers=(str(installed_managers[0]),),
        allow_inactive_path=True,
        timeout_seconds=10,
    )
    if not bool(proof.get("intercept_proved")):
        return (
            409,
            {
                "error": "shim_verification_failed",
                "message": ("Guard could not verify the installed package shim. Repair protection and try again."),
                "package_shims": _server.package_shim_status(context),
                "proof": proof,
            },
        )
    return (
        200,
        {
            "status": "verified",
            "message": (
                "Guard verified the installed package shim directly. Open a new terminal or source the matching "
                "shell profile to use it. Restart AI apps only when they run package managers, because existing "
                "app processes do not inherit a terminal PATH change."
            ),
            "package_shims": _server.package_shim_status(context),
            "proof": proof,
        },
    )


def _repair_detected_package_shims(context: _server.HarnessContext) -> dict[str, object]:
    current = _server.package_shim_status(context)
    installed_values = current.get("installed_managers")
    detected_values = current.get("detected_managers")
    current_installed = installed_values if isinstance(installed_values, list) else []
    current_detected = detected_values if isinstance(detected_values, list) else []
    managers = tuple(
        dict.fromkeys(
            [
                *[str(value) for value in current_installed],
                *[str(value) for value in current_detected],
            ]
        )
    )
    if not managers:
        raise RuntimeError("no detected package managers")
    result = _server.activate_package_shims(context, managers=managers, repair=False)
    verified = _server.package_shim_status(context)
    verified_installed_values = verified.get("installed_managers")
    verified_detected_values = verified.get("detected_managers")
    verified_installed = verified_installed_values if isinstance(verified_installed_values, list) else []
    verified_detected = verified_detected_values if isinstance(verified_detected_values, list) else []
    installed = {str(value) for value in verified_installed}
    detected = {str(value) for value in verified_detected}
    manager_details = verified.get("manager_details")
    invalid_integrity = (
        [detail for detail in manager_details if isinstance(detail, dict) and detail.get("integrity") != "ok"]
        if isinstance(manager_details, list)
        else ["missing manager details"]
    )
    if not detected.issubset(installed) or verified.get("missing_managers") or invalid_integrity:
        raise RuntimeError("package shim verification failed")
    return result


def _resolve_package_firewall_connect_flow(
    *,
    server: _server._GuardDaemonHttpServer,
    entitlement: dict[str, object],
) -> dict[str, object] | None:
    reason = str(entitlement.get("reason") or "").strip().lower()
    if reason not in {"guard_cloud_connect_required", "guard_cloud_reconnect_required"}:
        return None
    package_current = _server._copy_package_firewall_connect_state(server)
    cloud_current = _server._copy_guard_cloud_connect_state(server)
    if _server._guard_cloud_connect_state_is_in_flight(cloud_current):
        current = cloud_current
    elif package_current is not None:
        current = package_current
    else:
        current = cloud_current
    if current is None:
        return _server._default_package_firewall_connect_flow(store=server.store, reason=reason)
    state = str(current.get("state") or "idle")
    flow = {
        **_server._default_package_firewall_connect_flow(store=server.store, reason=reason),
        **current,
    }
    if state in {"starting", "running"}:
        flow["title"] = "Finish Guard Cloud sign-in in your browser"
        browser_opened = flow.get("browser_opened") is True
        flow["detail"] = (
            "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this page will "
            "unlock package-firewall controls automatically."
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
